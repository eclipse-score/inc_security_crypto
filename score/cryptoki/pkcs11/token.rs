// *******************************************************************************
// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// <https://www.apache.org/licenses/LICENSE-2.0>
//
// SPDX-License-Identifier: Apache-2.0
// *******************************************************************************

//! Per-slot token state management — proper PKCS#11 v3.0 token model.
//!
//! Each registered slot has its own `Token` with:
//! - Three-state machine: Reset → ReadWrite → ReadOnly (on SO PIN lockout)
//! - Label (32-byte padded UTF-8)
//! - Argon2id PIN hashes (SO and User)
//! - PIN failure counters with lockout threshold
//! - PIN policies (min/max length)
//! - Token flags derived from state

use std::collections::HashMap;

use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use once_cell::sync::Lazy;
use parking_lot::RwLock;

use super::constants::*;
use super::error::{Pkcs11Error, Result};
use super::types::*;
use score_log::{debug, info, trace, warn};

// ── PIN hashing ─────────────────────────────────────────────────────────

/// An Argon2id PIN hash stored as a PHC-format string.
#[derive(Debug, Clone)]
pub struct HashedPin {
    pub phc_string: String,
}

impl HashedPin {
    /// Hash a PIN with Argon2id and a fresh random salt.
    pub fn new(pin: &[u8]) -> Self {
        let salt = SaltString::generate(&mut OsRng);

        let weak_hashing = std::env::var("CRYPTOKI_WEAK_PIN_HASHING").is_ok_and(|v| v == "1");
        let params = if weak_hashing {
            argon2::Params::new(1024, 1, 1, Some(32)).expect("invalid test Argon2 params")
        } else if cfg!(debug_assertions) {
            argon2::Params::new(4_096, 1, 1, Some(32)).expect("invalid debug Argon2 params")
        } else {
            argon2::Params::new(65_536, 3, 4, Some(32)).expect("invalid prod Argon2 params")
        };

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let phc_string = argon2
            .hash_password(pin, &salt)
            .expect("Argon2 hashing failed")
            .to_string();
        HashedPin { phc_string }
    }

    /// Verify a PIN against this Argon2id hash (constant-time).
    pub fn verify(&self, pin: &[u8]) -> bool {
        let parsed = argon2::PasswordHash::new(&self.phc_string);
        parsed.is_ok_and(|h| Argon2::default().verify_password(pin, &h).is_ok())
    }

    /// Reconstruct from a PHC-format string (for deserialization).
    pub fn from_phc(phc_string: String) -> Self {
        HashedPin { phc_string }
    }
}

// ── Token state machine ─────────────────────────────────────────────────

/// PKCS#11 token state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// Uninitialized — C_InitToken has never been called.
    Reset,
    /// Normal operation.
    ReadWrite,
    /// SO PIN locked after too many failures — token is read-only.
    ReadOnly,
}

/// Maximum consecutive PIN failures before lockout.
const MAX_PIN_FAILURES: u32 = 10;

// ── Token ───────────────────────────────────────────────────────────────

/// Represents the full state of a PKCS#11 token.
#[derive(Debug, Clone)]
pub struct Token {
    pub slot_id: CK_SLOT_ID,
    pub label: [CK_UTF8CHAR; 32],
    pub state: TokenState,
    pub so_pin: Option<HashedPin>,
    pub user_pin: Option<HashedPin>,
    pub so_pin_failures: u32,
    pub user_pin_failures: u32,
    pub login_required: bool,
    pub min_pin_len: usize,
    pub max_pin_len: usize,
    pub serial_number: [CK_CHAR; 16],
}

impl Token {
    /// Create a new uninitialized token for the given slot.
    pub fn new(slot_id: CK_SLOT_ID) -> Self {
        let mut label = [b' '; 32];
        let src = b"Uninitialized Token";
        label[..src.len()].copy_from_slice(src);

        let mut serial = [b' '; 16];
        let sn = b"00000001";
        serial[..sn.len()].copy_from_slice(sn);

        Token {
            slot_id,
            label,
            state: TokenState::Reset,
            so_pin: None,
            user_pin: None,
            so_pin_failures: 0,
            user_pin_failures: 0,
            login_required: true,
            min_pin_len: 4,
            max_pin_len: 64,
            serial_number: serial,
        }
    }

    /// Create a pre-initialized token with a default label and PINs.
    ///
    /// Used when a slot is first accessed before `C_InitToken` is called,
    /// so that the token is immediately usable for testing and demos.
    pub fn new_default(slot_id: CK_SLOT_ID) -> Self {
        let mut token = Token::new(slot_id);
        let mut label = [b' '; 32];
        let src = b"Cryptoki Token";
        label[..src.len()].copy_from_slice(src);
        token.label = label;
        token.state = TokenState::ReadWrite;
        token.so_pin = Some(HashedPin::new(b"so-pin"));
        token.user_pin = Some(HashedPin::new(b"1234"));
        token
    }

    /// Whether the token has been initialized (state != Reset).
    pub fn initialized(&self) -> bool {
        self.state != TokenState::Reset
    }

    /// Initialize the token with SO PIN and label (C_InitToken).
    pub fn init_token(&mut self, so_pin: &[u8], label: &[CK_UTF8CHAR; 32]) -> Result<()> {
        debug!(context: "TOKEN", "Token initialization slot={} label={}", self.slot_id, String::from_utf8_lossy(label).as_ref());
        if so_pin.len() < self.min_pin_len || so_pin.len() > self.max_pin_len {
            return Err(Pkcs11Error::PinLenRange);
        }
        // If already initialized, verify old SO PIN.
        if self.initialized() {
            if let Some(ref existing) = self.so_pin {
                if !existing.verify(so_pin) {
                    return Err(Pkcs11Error::PinIncorrect);
                }
            }
        }
        self.label = *label;
        self.so_pin = Some(HashedPin::new(so_pin));
        self.user_pin = None;
        self.so_pin_failures = 0;
        self.user_pin_failures = 0;
        self.state = TokenState::ReadWrite;
        Ok(())
    }

    /// Initialize/set the user PIN (C_InitPIN — SO must be logged in).
    pub fn init_pin(&mut self, pin: &[u8]) -> Result<()> {
        if !self.initialized() {
            return Err(Pkcs11Error::GeneralError);
        }
        if pin.len() < self.min_pin_len || pin.len() > self.max_pin_len {
            return Err(Pkcs11Error::PinLenRange);
        }
        self.user_pin = Some(HashedPin::new(pin));
        self.user_pin_failures = 0;
        Ok(())
    }

    /// Change a PIN (C_SetPIN). Old PIN must already be verified by the caller.
    pub fn set_pin(&mut self, user_type: CK_USER_TYPE, new_pin: &[u8]) -> Result<()> {
        if new_pin.len() < self.min_pin_len || new_pin.len() > self.max_pin_len {
            return Err(Pkcs11Error::PinLenRange);
        }
        match user_type {
            CKU_SO => {
                self.so_pin = Some(HashedPin::new(new_pin));
                self.so_pin_failures = 0;
            },
            CKU_USER => {
                self.user_pin = Some(HashedPin::new(new_pin));
                self.user_pin_failures = 0;
            },
            _ => return Err(Pkcs11Error::UserTypeInvalid),
        }
        Ok(())
    }

    /// Verify a PIN for login, with failure counting and lockout.
    pub fn verify_pin(&mut self, user_type: CK_USER_TYPE, pin: &[u8]) -> Result<()> {
        trace!(context: "TOKEN", "PIN verification slot={} user_type={}", self.slot_id, user_type);
        let hash = match user_type {
            CKU_SO => {
                if self.state == TokenState::ReadOnly {
                    return Err(Pkcs11Error::PinLocked);
                }
                let ok = self.so_pin.as_ref().is_some_and(|p| p.verify(pin));
                if !ok {
                    self.so_pin_failures += 1;
                    if self.so_pin_failures >= MAX_PIN_FAILURES {
                        self.state = TokenState::ReadOnly;
                        return Err(Pkcs11Error::PinLocked);
                    }
                    return Err(Pkcs11Error::PinIncorrect);
                }
                self.so_pin_failures = 0;
            },
            CKU_USER => {
                if self.user_pin_failures >= MAX_PIN_FAILURES {
                    return Err(Pkcs11Error::PinLocked);
                }
                let ok = self.user_pin.as_ref().is_some_and(|p| p.verify(pin));
                if !ok {
                    self.user_pin_failures += 1;
                    return Err(Pkcs11Error::PinIncorrect);
                }
                self.user_pin_failures = 0;
            },
            _ => return Err(Pkcs11Error::ArgumentsBad),
        };
        Ok(())
    }

    /// Verify user PIN for context-specific re-auth without touching lockout counters.
    pub fn verify_user_pin_no_lockout(&self, pin: &[u8]) -> Result<()> {
        let ok = self.user_pin.as_ref().is_some_and(|p| p.verify(pin));
        if !ok {
            Err(Pkcs11Error::PinIncorrect)
        } else {
            Ok(())
        }
    }

    /// Build the CK_FLAGS for CK_TOKEN_INFO.
    pub fn token_flags(&self) -> CK_FLAGS {
        let mut flags: CK_FLAGS = CKF_RNG;
        if self.initialized() {
            flags |= CKF_TOKEN_INITIALIZED;
        }
        if self.login_required {
            flags |= CKF_LOGIN_REQUIRED;
        }
        if self.user_pin.is_some() {
            flags |= CKF_USER_PIN_INITIALIZED;
        }
        if self.state == TokenState::ReadOnly {
            flags |= CKF_WRITE_PROTECTED;
        }
        if self.so_pin_failures > 0 && self.so_pin_failures < MAX_PIN_FAILURES {
            flags |= CKF_SO_PIN_COUNT_LOW;
            if self.so_pin_failures == MAX_PIN_FAILURES - 1 {
                flags |= CKF_SO_PIN_FINAL_TRY;
            }
        }
        if self.so_pin_failures >= MAX_PIN_FAILURES {
            flags |= CKF_SO_PIN_LOCKED;
        }
        if self.user_pin_failures > 0 && self.user_pin_failures < MAX_PIN_FAILURES {
            flags |= CKF_USER_PIN_COUNT_LOW;
            if self.user_pin_failures == MAX_PIN_FAILURES - 1 {
                flags |= CKF_USER_PIN_FINAL_TRY;
            }
        }
        if self.user_pin_failures >= MAX_PIN_FAILURES {
            flags |= CKF_USER_PIN_LOCKED;
        }
        flags
    }
}

// ── Per-slot token store ─────────────────────────────────────────────────

static TOKENS: Lazy<RwLock<HashMap<CK_SLOT_ID, Token>>> = Lazy::new(|| RwLock::new(HashMap::new()));

/// Ensure a token exists for the given slot (creates a default if missing).
pub fn ensure_token(slot_id: CK_SLOT_ID) {
    let mut tokens = TOKENS.write();
    // Only insert if missing
    tokens.entry(slot_id).or_insert_with(|| Token::new_default(slot_id));
}

/// Access a slot's token immutably.
pub fn with_token<F, T>(slot_id: CK_SLOT_ID, f: F) -> T
where
    F: FnOnce(&Token) -> T,
{
    let tokens = TOKENS.read();
    if let Some(tok) = tokens.get(&slot_id) {
        f(tok)
    } else {
        drop(tokens);
        ensure_token(slot_id);
        let tokens = TOKENS.read();
        f(tokens.get(&slot_id).unwrap())
    }
}

/// Access a slot's token mutably.
pub fn with_token_mut<F, T>(slot_id: CK_SLOT_ID, f: F) -> T
where
    F: FnOnce(&mut Token) -> T,
{
    let mut tokens = TOKENS.write();
    tokens.entry(slot_id).or_insert_with(|| Token::new_default(slot_id));
    f(tokens.get_mut(&slot_id).unwrap())
}

/// Reset a single slot's token to default state.
pub fn reset_token(slot_id: CK_SLOT_ID) {
    let mut tokens = TOKENS.write();
    tokens.insert(slot_id, Token::new_default(slot_id));
}

/// Clear all tokens (called by C_Finalize).
pub fn clear_tokens() {
    TOKENS.write().clear();
}
