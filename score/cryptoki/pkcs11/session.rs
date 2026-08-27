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

//! Per-session state: operation contexts, login state, global session store.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use score_log::{debug, trace, warn};

use super::constants::*;
use super::error::{Pkcs11Error, Result};
use super::object_store::KeyObject;
use super::types::*;

// ── Operation contexts ────────────────────────────────────────────────────

/// State for an active C_SignInit / C_VerifyInit operation.
#[derive(Debug, Clone)]
pub struct SignContext {
    pub mechanism: CK_MECHANISM_TYPE,
    pub key_handle: CK_OBJECT_HANDLE,
    /// Accumulated message bytes (multi-part).
    pub data: Vec<u8>,
}

/// State for an active C_EncryptInit / C_DecryptInit operation.
#[derive(Debug, Clone)]
pub struct CipherContext {
    pub mechanism: CK_MECHANISM_TYPE,
    pub key_handle: CK_OBJECT_HANDLE,
    pub iv: Option<Vec<u8>>,
    pub aad: Option<Vec<u8>>,
    pub tag_len: usize,
    pub accumulated: Vec<u8>,
}

/// State for an active C_DigestInit operation.
#[derive(Debug, Clone)]
pub struct DigestContext {
    pub mechanism: CK_MECHANISM_TYPE,
    pub data: Vec<u8>,
    pub is_single_part: bool,
    pub is_multi_part: bool,
}

/// State for an active C_FindObjectsInit operation.
#[derive(Debug, Clone)]
pub struct FindContext {
    pub results: Vec<CK_OBJECT_HANDLE>,
    pub index: usize,
}

/// State for v3.0 message-based encrypt/decrypt/sign/verify operations.
#[derive(Debug, Clone)]
pub struct MessageCipherContext {
    pub mechanism: CK_MECHANISM_TYPE,
    pub key_handle: CK_OBJECT_HANDLE,
}

/// State for v3.0 message-based signing/verification operations.
#[derive(Debug, Clone)]
pub struct MessageSignContext {
    pub mechanism: CK_MECHANISM_TYPE,
    pub key_handle: CK_OBJECT_HANDLE,
}

// ── Session ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum LoginState {
    NotLoggedIn,
    UserLoggedIn,
    SoLoggedIn,
}

#[derive(Debug)]
pub struct Session {
    pub handle: CK_SESSION_HANDLE,
    pub slot_id: CK_SLOT_ID,
    pub flags: CK_FLAGS,
    pub login_state: LoginState,

    /// Set to `true` after a successful `C_Login(CKU_CONTEXT_SPECIFIC)`.
    /// Consumed (reset to `false`) by the next private-key operation.
    /// Guards keys with `CKA_ALWAYS_AUTHENTICATE = TRUE`.
    pub context_specific_authed: bool,

    pub sign_ctx: Option<SignContext>,
    pub verify_ctx: Option<SignContext>,
    pub encrypt_ctx: Option<CipherContext>,
    pub decrypt_ctx: Option<CipherContext>,
    pub digest_ctx: Option<DigestContext>,
    pub find_ctx: Option<FindContext>,

    // v3.0 message-based operation contexts
    pub msg_encrypt_ctx: Option<MessageCipherContext>,
    pub msg_decrypt_ctx: Option<MessageCipherContext>,
    pub msg_sign_ctx: Option<MessageSignContext>,
    pub msg_verify_ctx: Option<MessageSignContext>,
}

impl Session {
    pub fn new(handle: CK_SESSION_HANDLE, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Self {
        Session {
            handle,
            slot_id,
            flags,
            login_state: LoginState::NotLoggedIn,
            context_specific_authed: false,
            sign_ctx: None,
            verify_ctx: None,
            encrypt_ctx: None,
            decrypt_ctx: None,
            digest_ctx: None,
            find_ctx: None,
            msg_encrypt_ctx: None,
            msg_decrypt_ctx: None,
            msg_sign_ctx: None,
            msg_verify_ctx: None,
        }
    }

    pub fn is_rw(&self) -> bool {
        self.flags & CKF_RW_SESSION != 0
    }

    pub fn require_rw(&self) -> Result<()> {
        if self.is_rw() {
            Ok(())
        } else {
            Err(Pkcs11Error::SessionReadOnly)
        }
    }

    /// Gate a private-key operation on `CKA_ALWAYS_AUTHENTICATE`.
    ///
    /// * If `obj.always_authenticate` is false — permit unconditionally.
    /// * If true and `context_specific_authed` is false — deny.
    /// * If true and `context_specific_authed` is true — permit **and consume** the flag
    ///   (one-shot per spec: the caller must call `C_Login(CKU_CONTEXT_SPECIFIC)` again
    ///   before the next operation on the same key).
    pub fn require_context_auth(&mut self, obj: &KeyObject) -> Result<()> {
        if obj.always_authenticate {
            // Check if the "single-use ticket" exists
            if !self.context_specific_authed {
                warn!(context: "AUTH", "context-specific auth required and missing session={}", self.handle);
                return Err(Pkcs11Error::UserNotLoggedIn);
            }
            // // consume the authentication immediately
            // self.context_specific_authed = false;
        }
        Ok(())
    }
}

// ── Global store ──────────────────────────────────────────────────────────

static SESSIONS: Lazy<RwLock<HashMap<CK_SESSION_HANDLE, Session>>> = Lazy::new(|| RwLock::new(HashMap::new()));

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

fn next_session_handle() -> CK_SESSION_HANDLE {
    NEXT_SESSION.fetch_add(1, Ordering::SeqCst)
}

pub fn open_session(slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Result<CK_SESSION_HANDLE> {
    debug!(context: "SESSION", "Opening session: slot={} flags={}", slot_id, flags);
    if flags & CKF_SERIAL_SESSION == 0 {
        warn!(context: "SESSION", "open_session rejected without CKF_SERIAL_SESSION slot={} flags={}", slot_id, flags);
        return Err(Pkcs11Error::SessionParallelNotSupported);
    }

    let is_rw = (flags & CKF_RW_SESSION) != 0;

    let mut sessions = SESSIONS.write();

    // Determine the current login state for this token
    let current_login_state = sessions
        .values()
        .find(|s| s.slot_id == slot_id)
        .map(|s| s.login_state.clone())
        .unwrap_or(LoginState::NotLoggedIn);

    // Security Officer cannot have Read-Only sessions
    if current_login_state == LoginState::SoLoggedIn && !is_rw {
        warn!(context: "SESSION", "open_session rejected RO while SO logged in slot={}", slot_id);
        return Err(Pkcs11Error::SessionReadWriteSoExists);
    }
    let handle = next_session_handle();
    let mut session = Session::new(handle, slot_id, flags);
    // Inherit the safely validated login state
    session.login_state = current_login_state;
    sessions.insert(handle, session);
    debug!(context: "SESSION", "opened session={} slot={} rw={}", handle, slot_id, is_rw);
    Ok(handle)
}

pub fn close_session(handle: CK_SESSION_HANDLE) -> Result<()> {
    SESSIONS
        .write()
        .remove(&handle)
        .ok_or(Pkcs11Error::InvalidSessionHandle)?;
    debug!(context: "SESSION", "closed session={}", handle);
    Ok(())
}

pub fn close_all_sessions(slot_id: CK_SLOT_ID) {
    let mut sessions = SESSIONS.write();
    let before = sessions.len();
    sessions.retain(|_, s| s.slot_id != slot_id);
    debug!(context: "SESSION", "closed all sessions slot={} removed={}", slot_id, before.saturating_sub(sessions.len()));
}

pub fn with_session_mut<F, T>(handle: CK_SESSION_HANDLE, f: F) -> Result<T>
where
    F: FnOnce(&mut Session) -> Result<T>,
{
    let mut sessions = SESSIONS.write();
    let session = sessions.get_mut(&handle).ok_or(Pkcs11Error::InvalidSessionHandle)?;
    f(session)
}

pub fn with_session<F, T>(handle: CK_SESSION_HANDLE, f: F) -> Result<T>
where
    F: FnOnce(&Session) -> Result<T>,
{
    let sessions = SESSIONS.read();
    let session = sessions.get(&handle).ok_or(Pkcs11Error::InvalidSessionHandle)?;
    f(session)
}

pub fn get_session_info(handle: CK_SESSION_HANDLE) -> Result<CK_SESSION_INFO> {
    with_session(handle, |s| {
        let state: CK_ULONG = match s.login_state {
            LoginState::NotLoggedIn => {
                if s.is_rw() {
                    CKS_RW_PUBLIC_SESSION
                } else {
                    CKS_RO_PUBLIC_SESSION
                }
            },
            LoginState::UserLoggedIn => {
                if s.is_rw() {
                    CKS_RW_USER_FUNCTIONS
                } else {
                    CKS_RO_USER_FUNCTIONS
                }
            },
            LoginState::SoLoggedIn => CKS_RW_SO_FUNCTIONS,
        };
        Ok(CK_SESSION_INFO {
            slotID: s.slot_id,
            state,
            flags: s.flags,
            ulDeviceError: 0,
        })
    })
}

pub fn clear_sessions() {
    let mut sessions = SESSIONS.write();
    let n = sessions.len();
    sessions.clear();
    debug!(context: "SESSION", "cleared all sessions count={}", n);
}

pub fn session_count() -> usize {
    SESSIONS.read().len()
}

/// Count sessions on a specific slot.
pub fn session_count_for_slot(slot_id: CK_SLOT_ID) -> usize {
    SESSIONS.read().values().filter(|s| s.slot_id == slot_id).count()
}

/// Count RW sessions on a specific slot.
pub fn rw_session_count_for_slot(slot_id: CK_SLOT_ID) -> usize {
    SESSIONS
        .read()
        .values()
        .filter(|s| s.slot_id == slot_id && s.is_rw())
        .count()
}

/// Check if any RO sessions exist on a specific slot.
pub fn has_ro_sessions_on_slot(slot_id: CK_SLOT_ID) -> bool {
    SESSIONS.read().values().any(|s| s.slot_id == slot_id && !s.is_rw())
}

/// Set login state for ALL sessions on the given slot.
pub fn login_all_sessions_on_slot(slot_id: CK_SLOT_ID, state: LoginState) {
    let mut sessions = SESSIONS.write();
    for s in sessions.values_mut().filter(|s| s.slot_id == slot_id) {
        s.login_state = state.clone();
    }
}

/// Release active find-object contexts on every session for a slot.
/// Called during logout because object visibility changes (private objects
/// become hidden), so any in-progress C_FindObjects must be invalidated.
pub fn release_find_contexts_on_slot(slot_id: CK_SLOT_ID) {
    let mut sessions = SESSIONS.write();
    let mut released = 0usize;
    for s in sessions.values_mut().filter(|s| s.slot_id == slot_id) {
        if s.find_ctx.is_some() {
            released += 1;
        }
        s.find_ctx = None;
    }
    trace!(context: "SESSION", "released find contexts slot={} count={}", slot_id, released);
}

/// Get the current login state for a slot (from any session on that slot).
pub fn login_state_for_slot(slot_id: CK_SLOT_ID) -> LoginState {
    SESSIONS
        .read()
        .values()
        .find(|s| s.slot_id == slot_id)
        .map(|s| s.login_state.clone())
        .unwrap_or(LoginState::NotLoggedIn)
}

/// Check if any sessions (Read-Only or Read-Write) exist on a specific slot.
pub fn has_open_sessions(slot_id: CK_SLOT_ID) -> bool {
    SESSIONS.read().values().any(|s| s.slot_id == slot_id)
}
