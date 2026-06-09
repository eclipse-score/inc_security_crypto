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

//! Integration tests for: CKA_ALWAYS_AUTHENTICATE per-operation gating.
//!
//! Tests exercise:
//! - A key with `CKA_ALWAYS_AUTHENTICATE=TRUE` blocks `C_Sign` without a
//!   preceding `C_Login(CKU_CONTEXT_SPECIFIC)`.
//! - The operation succeeds after `C_Login(CKU_CONTEXT_SPECIFIC)` with the
//!   correct PIN.
//! - The context-specific auth is one-shot: a second `C_Sign` (without a new
//!   context login) is rejected.

mod common;

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use serial_test::serial;
use std::ffi::c_void;
use std::ptr;

use std::sync::Once;
static INIT: Once = Once::new();

const SLOT_PIN: &[u8] = b"1234";

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

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Open an RW session and log in as CKU_USER.
unsafe fn open_user_session() -> CK_SESSION_HANDLE {
    let fl = common::fn_list();
    let h = common::open_session(fl);
    let rv = p11!(fl, C_Login, h, CKU_USER, SLOT_PIN.as_ptr(), SLOT_PIN.len() as CK_ULONG);
    assert!(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN,
            "C_Login(USER) failed: {rv:#010x}");
    h
}

/// Generate an EC P-256 key pair. Returns (priv_handle, pub_handle).
///
/// `always_authenticate` controls whether `CKA_ALWAYS_AUTHENTICATE` is set on
/// the private key template.
unsafe fn generate_ec_keypair(
    session:           CK_SESSION_HANDLE,
    always_authenticate: bool,
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let fl = common::fn_list();
    // P-256 OID DER encoding.
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let token_false: &[u8] = &[CK_FALSE];
    let always_auth_byte: &[u8] = &[if always_authenticate { CK_TRUE } else { CK_FALSE }];

    let mut pub_attrs = [
        CK_ATTRIBUTE { r#type: CKA_EC_PARAMS, pValue: p256_oid.as_ptr() as *mut c_void,  ulValueLen: p256_oid.len() as CK_ULONG },
        CK_ATTRIBUTE { r#type: CKA_TOKEN,     pValue: token_false.as_ptr() as *mut c_void, ulValueLen: 1 },
    ];
    let mut priv_attrs = [
        CK_ATTRIBUTE { r#type: CKA_TOKEN,               pValue: token_false.as_ptr() as *mut c_void,      ulValueLen: 1 },
        CK_ATTRIBUTE { r#type: CKA_ALWAYS_AUTHENTICATE,  pValue: always_auth_byte.as_ptr() as *mut c_void, ulValueLen: 1 },
    ];
    let mech = CK_MECHANISM { mechanism: CKM_EC_KEY_PAIR_GEN, pParameter: ptr::null_mut(), ulParameterLen: 0 };
    let mut pub_h: CK_OBJECT_HANDLE = 0;
    let mut priv_h: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKeyPair,
                  session, &mech,
                  pub_attrs.as_mut_ptr(), pub_attrs.len() as CK_ULONG,
                  priv_attrs.as_mut_ptr(), priv_attrs.len() as CK_ULONG,
                  &mut pub_h, &mut priv_h);
    assert_eq!(rv, CKR_OK, "C_GenerateKeyPair failed: {rv:#010x}");
    (priv_h, pub_h)
}

/// Call C_SignInit + C_Sign with ECDSA on `priv_handle`. Returns the raw CK_RV.
unsafe fn do_sign(session: CK_SESSION_HANDLE, priv_handle: CK_OBJECT_HANDLE) -> CK_RV {
    let fl = common::fn_list();
    let mech = CK_MECHANISM { mechanism: CKM_ECDSA, pParameter: ptr::null_mut(), ulParameterLen: 0 };
    let rv = p11!(fl, C_SignInit, session, &mech, priv_handle);
    if rv != CKR_OK { return rv; }
    // 32-byte prehashed digest (SHA-256 of b"test")
    let digest = [0u8; 32];
    let mut sig_buf = [0u8; 72];
    let mut sig_len: CK_ULONG = sig_buf.len() as CK_ULONG;
    p11!(fl, C_Sign, session, digest.as_ptr(), digest.len() as CK_ULONG,
         sig_buf.as_mut_ptr(), &mut sig_len)
}

/// Call C_Login(CKU_CONTEXT_SPECIFIC) on `session` with the correct PIN.
unsafe fn context_login(session: CK_SESSION_HANDLE) -> CK_RV {
    let fl = common::fn_list();
    p11!(fl, C_Login, session, CKU_CONTEXT_SPECIFIC,
         SLOT_PIN.as_ptr(), SLOT_PIN.len() as CK_ULONG)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// A key WITHOUT CKA_ALWAYS_AUTHENTICATE signs normally — no context login needed.
#[test]
#[serial]
fn normal_key_signs_without_context_login() {
    init();
    unsafe {
        let session = open_user_session();
        let (priv_h, _pub_h) = generate_ec_keypair(session, false);
        let rv = do_sign(session, priv_h);
        assert_eq!(rv, CKR_OK, "sign with normal key must succeed, got {rv:#010x}");
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

/// A key WITH CKA_ALWAYS_AUTHENTICATE=TRUE blocks C_Sign unless a preceding
/// C_Login(CKU_CONTEXT_SPECIFIC) was issued on the same session.
#[test]
#[serial]
fn always_auth_key_fails_sign_without_context_login() {
    init();
    unsafe {
        let session = open_user_session();
        let (priv_h, _pub_h) = generate_ec_keypair(session, true);
        let rv = do_sign(session, priv_h);
        assert_eq!(rv, CKR_USER_NOT_LOGGED_IN,
                   "sign without context login must return CKR_USER_NOT_LOGGED_IN, got {rv:#010x}");
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

/// After C_Login(CKU_CONTEXT_SPECIFIC) with the correct PIN, C_Sign succeeds.
#[test]
#[serial]
fn always_auth_key_succeeds_after_context_login() {
    init();
    unsafe {
        let session = open_user_session();
        let (priv_h, _pub_h) = generate_ec_keypair(session, true);

        let mech = CK_MECHANISM { mechanism: CKM_ECDSA, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let rv = p11!(common::fn_list(), C_SignInit, session, &mech, priv_h);
        assert_eq!(rv, CKR_OK);

        let rv = context_login(session);
        assert_eq!(rv, CKR_OK, "C_Login must succeed because SignInit is active");

        let digest = [0u8; 32];
        let mut sig = [0u8; 72];
        let mut sig_len = sig.len() as CK_ULONG;
        let rv = p11!(common::fn_list(), C_Sign, session, digest.as_ptr(), digest.len() as CK_ULONG, sig.as_mut_ptr(), &mut sig_len);
        assert_eq!(rv, CKR_OK);

        p11!(common::fn_list(), C_CloseSession, session);
    }
}

/// The context-specific auth is one-shot: a second C_Sign (without a new
/// C_Login(CKU_CONTEXT_SPECIFIC)) must be rejected.
#[test]
#[serial]
fn always_auth_consumed_after_one_sign() {
    init();
    unsafe {
        let session = open_user_session();
        let (priv_h, _pub_h) = generate_ec_keypair(session, true);

        let mech = CK_MECHANISM { mechanism: CKM_ECDSA, pParameter: std::ptr::null_mut(), ulParameterLen: 0 };
        p11!(common::fn_list(), C_SignInit, session, &mech, priv_h);

        let rv = context_login(session);
        assert_eq!(rv, CKR_OK, "C_Login(CKU_CONTEXT_SPECIFIC) failed: {rv:#010x}");

        let digest = [0u8; 32];
        let mut sig = [0u8; 72];
        let mut sig_len = sig.len() as CK_ULONG;
        let rv = p11!(common::fn_list(), C_Sign, session, digest.as_ptr(), digest.len() as CK_ULONG, sig.as_mut_ptr(), &mut sig_len);
        assert_eq!(rv, CKR_OK, "first sign must succeed, got {rv:#010x}");

        p11!(common::fn_list(), C_SignInit, session, &mech, priv_h);

        let mut sig_len = sig.len() as CK_ULONG;
        let rv = p11!(common::fn_list(), C_Sign, session, digest.as_ptr(), digest.len() as CK_ULONG, sig.as_mut_ptr(), &mut sig_len);
        assert_eq!(rv, CKR_USER_NOT_LOGGED_IN,
                   "second sign without re-login must fail, got {rv:#010x}");
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

/// Two sessions on the same slot are independent: context login on session A
/// does not arm the flag on session B.
#[test]
#[serial]
fn context_auth_is_per_session() {
    init();
    unsafe {
        let fl = common::fn_list();
        let session_a = open_user_session();
        let (priv_h, _pub_h) = generate_ec_keypair(session_a, true);
        let mut session_b: CK_SESSION_HANDLE = 0;
        p11!(fl, C_OpenSession, 0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut session_b);

        let mech = CK_MECHANISM { mechanism: CKM_ECDSA, pParameter: ptr::null_mut(), ulParameterLen: 0 };

        p11!(fl, C_SignInit, session_a, &mech, priv_h);
        p11!(fl, C_SignInit, session_b, &mech, priv_h);
        let rv = context_login(session_a);
        assert_eq!(rv, CKR_OK, "Login must succeed because session_a has an active operation");
        let digest = [0u8; 32];
        let mut sig = [0u8; 72];
        let mut sig_len = sig.len() as CK_ULONG;
        let rv = p11!(fl, C_Sign, session_b, digest.as_ptr(), digest.len() as CK_ULONG, sig.as_mut_ptr(), &mut sig_len);
        assert_eq!(rv, CKR_USER_NOT_LOGGED_IN, "Session B should not be authorized");

        let mut sig_len = sig.len() as CK_ULONG;
        let rv = p11!(fl, C_Sign, session_a, digest.as_ptr(), digest.len() as CK_ULONG, sig.as_mut_ptr(), &mut sig_len);
        assert_eq!(rv, CKR_OK);

        p11!(fl, C_CloseSession, session_a);
        p11!(fl, C_CloseSession, session_b);
    }
}

/// Wrong PIN for CKU_CONTEXT_SPECIFIC login must return CKR_PIN_INCORRECT.
#[test]
#[serial]
fn context_login_wrong_pin_rejected() {
    init();
    unsafe {
        let session = open_user_session();
        let wrong_pin = b"wrong";
        let fl = common::fn_list();
        let rv = p11!(fl, C_Login, session, CKU_CONTEXT_SPECIFIC,
                      wrong_pin.as_ptr(), wrong_pin.len() as CK_ULONG);
        assert_eq!(rv, CKR_PIN_INCORRECT,
                   "wrong PIN for context login must return CKR_PIN_INCORRECT, got {rv:#010x}");
        p11!(fl, C_CloseSession, session);
    }
}
