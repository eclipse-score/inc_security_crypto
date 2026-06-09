// *******************************************************************************
// Copyright (c) 2025 Contributors to the Eclipse Foundation
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

//! Integration tests for:
//!   - CK_TOKEN_INFO / CK_SLOT_INFO field correctness
//!   - C_SeedRandom returns CKR_RANDOM_SEED_NOT_SUPPORTED
//!   - Dual-function operations return CKR_FUNCTION_NOT_SUPPORTED

mod common;

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use std::ptr;
use std::sync::Once;

static INIT: Once = Once::new();
fn init() {
    INIT.call_once(|| unsafe {
        let fl = common::fn_list();
        let rv = p11!(fl, C_Initialize, ptr::null_mut());
        assert!(
            rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "C_Initialize failed: {rv:#010x}"
        );
    });
}

unsafe fn token_info() -> CK_TOKEN_INFO {
    let fl = common::fn_list();
    let mut info: CK_TOKEN_INFO = std::mem::zeroed();
    let rv = p11!(fl, C_GetTokenInfo, 0, &mut info);
    assert_eq!(rv, CKR_OK, "C_GetTokenInfo failed: {rv:#010x}");
    info
}

unsafe fn slot_info() -> CK_SLOT_INFO {
    let fl = common::fn_list();
    let mut info: CK_SLOT_INFO = std::mem::zeroed();
    let rv = p11!(fl, C_GetSlotInfo, 0, &mut info);
    assert_eq!(rv, CKR_OK, "C_GetSlotInfo failed: {rv:#010x}");
    info
}

// ── CK_TOKEN_INFO ────────────────────────────────────────────────────────

/// ulMaxSessionCount must be CK_EFFECTIVELY_INFINITE (= 0).
#[test]
fn token_info_max_session_count_is_effectively_infinite() {
    init();
    unsafe {
        let info = token_info();
        assert_eq!(
            info.ulMaxSessionCount, CK_EFFECTIVELY_INFINITE,
            "ulMaxSessionCount should be CK_EFFECTIVELY_INFINITE (0), got {}",
            info.ulMaxSessionCount
        );
    }
}

/// ulMaxRwSessionCount must be CK_EFFECTIVELY_INFINITE (= 0).
#[test]
fn token_info_max_rw_session_count_is_effectively_infinite() {
    init();
    unsafe {
        let info = token_info();
        assert_eq!(
            info.ulMaxRwSessionCount, CK_EFFECTIVELY_INFINITE,
            "ulMaxRwSessionCount should be CK_EFFECTIVELY_INFINITE (0), got {}",
            info.ulMaxRwSessionCount
        );
    }
}

/// CKF_RNG must be set — the library has C_GenerateRandom.
#[test]
fn token_info_ckf_rng_is_set() {
    init();
    unsafe {
        let info = token_info();
        assert_ne!(
            info.flags & CKF_RNG, 0,
            "CKF_RNG must be set in token flags ({:#010x})",
            info.flags
        );
    }
}

/// CKF_LOGIN_REQUIRED must be set (token requires login before private-object access).
#[test]
fn token_info_ckf_login_required_is_set() {
    init();
    unsafe {
        let info = token_info();
        assert_ne!(
            info.flags & CKF_LOGIN_REQUIRED, 0,
            "CKF_LOGIN_REQUIRED must be set in token flags ({:#010x})",
            info.flags
        );
    }
}

/// CKF_TOKEN_INITIALIZED must be set (token has been initialized via C_InitToken).
#[test]
fn token_info_ckf_token_initialized_is_set() {
    init();
    unsafe {
        let info = token_info();
        assert_ne!(
            info.flags & CKF_TOKEN_INITIALIZED, 0,
            "CKF_TOKEN_INITIALIZED must be set after initialization ({:#010x})",
            info.flags
        );
    }
}

/// CKF_USER_PIN_INITIALIZED must be set when the user PIN has been set up.
#[test]
fn token_info_ckf_user_pin_initialized_is_set() {
    init();
    unsafe {
        let info = token_info();
        assert_ne!(
            info.flags & CKF_USER_PIN_INITIALIZED, 0,
            "CKF_USER_PIN_INITIALIZED must be set ({:#010x})",
            info.flags
        );
    }
}

/// CKF_HW_SLOT must NOT be set in CK_SLOT_INFO — this is a software token.
#[test]
fn slot_info_ckf_hw_slot_is_not_set() {
    init();
    unsafe {
        let info = slot_info();
        // CKF_HW_SLOT = 0x00000004 per PKCS#11 spec
        const CKF_HW_SLOT: CK_FLAGS = 0x00000004;
        assert_eq!(
            info.flags & CKF_HW_SLOT, 0,
            "CKF_HW_SLOT must not be set for a software token ({:#010x})",
            info.flags
        );
    }
}

// ── C_SeedRandom ─────────────────────────────────────────────────────────

/// C_SeedRandom must return CKR_RANDOM_SEED_NOT_SUPPORTED.
#[test]
fn seed_random_returns_not_supported() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mut h: CK_SESSION_HANDLE = 0;
        let rv_open = p11!(
            fl, C_OpenSession, 0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            ptr::null_mut(), None, &mut h
        );
        assert_eq!(rv_open, CKR_OK, "C_OpenSession failed");
        let seed = [0u8; 32];
        let rv = p11!(fl, C_SeedRandom, h, seed.as_ptr(), seed.len() as CK_ULONG);
        assert_eq!(
            rv, CKR_RANDOM_SEED_NOT_SUPPORTED,
            "C_SeedRandom must return CKR_RANDOM_SEED_NOT_SUPPORTED, got {rv:#010x}"
        );
        p11!(fl, C_CloseSession, h);
    }
}

// ── Dual-function operations ────────────────────────────────────────────

/// C_DigestEncryptUpdate must return CKR_FUNCTION_NOT_SUPPORTED.
#[test]
fn digest_encrypt_update_not_supported() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mut out_len: CK_ULONG = 0;
        let rv = p11!(fl, C_DigestEncryptUpdate, 0u64,
                      ptr::null(), 0u64, ptr::null_mut(), &mut out_len);
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED,
                   "C_DigestEncryptUpdate should be CKR_FUNCTION_NOT_SUPPORTED: {rv:#010x}");
    }
}

/// C_DecryptDigestUpdate must return CKR_FUNCTION_NOT_SUPPORTED.
#[test]
fn decrypt_digest_update_not_supported() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mut out_len: CK_ULONG = 0;
        let rv = p11!(fl, C_DecryptDigestUpdate, 0u64,
                      ptr::null(), 0u64, ptr::null_mut(), &mut out_len);
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED,
                   "C_DecryptDigestUpdate should be CKR_FUNCTION_NOT_SUPPORTED: {rv:#010x}");
    }
}

/// C_SignEncryptUpdate must return CKR_FUNCTION_NOT_SUPPORTED.
#[test]
fn sign_encrypt_update_not_supported() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mut out_len: CK_ULONG = 0;
        let rv = p11!(fl, C_SignEncryptUpdate, 0u64,
                      ptr::null(), 0u64, ptr::null_mut(), &mut out_len);
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED,
                   "C_SignEncryptUpdate should be CKR_FUNCTION_NOT_SUPPORTED: {rv:#010x}");
    }
}

/// C_DecryptVerifyUpdate must return CKR_FUNCTION_NOT_SUPPORTED.
#[test]
fn decrypt_verify_update_not_supported() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mut out_len: CK_ULONG = 0;
        let rv = p11!(fl, C_DecryptVerifyUpdate, 0u64,
                      ptr::null(), 0u64, ptr::null_mut(), &mut out_len);
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED,
                   "C_DecryptVerifyUpdate should be CKR_FUNCTION_NOT_SUPPORTED: {rv:#010x}");
    }
}
