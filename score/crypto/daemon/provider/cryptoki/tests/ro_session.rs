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

//! Integration tests for: read-only session enforcement.
//!
//! Every state-mutating C_* function must return `CKR_SESSION_READ_ONLY` when
//! called on a session opened without `CKF_RW_SESSION`.

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

/// Open a read-only session on slot 0. `CKF_RW_SESSION` is intentionally absent.
unsafe fn open_ro_session() -> CK_SESSION_HANDLE {
    let fl = common::fn_list();
    let mut h: CK_SESSION_HANDLE = 0;
    // CKF_SERIAL_SESSION is mandatory; no CKF_RW_SESSION → read-only session.
    let rv = p11!(fl, C_OpenSession, 0, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut h);
    assert_eq!(rv, CKR_OK, "C_OpenSession (RO) failed: {rv:#010x}");
    h
}

fn null_mech() -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism:      CKM_AES_KEY_GEN,
        pParameter:     ptr::null_mut(),
        ulParameterLen: 0,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn ro_session_create_object_returns_session_read_only() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_ro_session();
        let mut dummy: CK_OBJECT_HANDLE = 0;
        let token_true = [CK_TRUE];
        let template = [CK_ATTRIBUTE {
            r#type: CKA_TOKEN,
            pValue: token_true.as_ptr() as *mut _,
            ulValueLen: 1,
        }];
        let rv = p11!(fl, C_CreateObject, h, template.as_ptr(), 1, &mut dummy);
        assert_eq!(rv, CKR_SESSION_READ_ONLY, "expected CKR_SESSION_READ_ONLY, got {rv:#010x}");
        p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn ro_session_copy_object_returns_session_read_only() {
    init();
    unsafe {
        let fl = common::fn_list();
        let rw_h = common::open_session(fl);
        let ro_h = open_ro_session();

        let mech = null_mech();
        let mut src_h = 0;
        p11!(fl, C_GenerateKey, rw_h, &mech, ptr::null(), 0, &mut src_h);

        let token_true = [CK_TRUE];
        let template = [CK_ATTRIBUTE {
            r#type: CKA_TOKEN,
            pValue: token_true.as_ptr() as *mut _,
            ulValueLen: 1,
        }];

        let mut new_h: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_CopyObject, ro_h, src_h, template.as_ptr(), 1, &mut new_h);
        assert_eq!(rv, CKR_SESSION_READ_ONLY, "expected CKR_SESSION_READ_ONLY, got {rv:#010x}");
        p11!(fl, C_CloseSession, rw_h);
        p11!(fl, C_CloseSession, ro_h);
    }
}

#[test]
fn ro_session_destroy_object_returns_session_read_only() {
    init();
    unsafe {
        let fl = common::fn_list();
        let rw_h = common::open_session(fl);
        let h = open_ro_session();

        let mech = null_mech();
        let token_true = [CK_TRUE];
        let template = [CK_ATTRIBUTE {
            r#type: CKA_TOKEN,
            pValue: token_true.as_ptr() as *mut _,
            ulValueLen: 1,
        }];
        let mut obj_h: CK_OBJECT_HANDLE = 0;
        p11!(fl, C_GenerateKey, rw_h, &mech, template.as_ptr(), 1, &mut obj_h);

        let rv = p11!(fl, C_DestroyObject, h, obj_h);
        assert_eq!(rv, CKR_SESSION_READ_ONLY, "expected CKR_SESSION_READ_ONLY, got {rv:#010x}");
        p11!(fl, C_CloseSession, rw_h);
        p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn ro_session_set_attribute_value_returns_session_read_only() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_ro_session();
        // Non-null template so the null-pointer argument check passes; RO fires first.
        let mut attr = CK_ATTRIBUTE { r#type: CKA_LABEL, pValue: ptr::null_mut(), ulValueLen: 0 };
        let rv = p11!(fl, C_SetAttributeValue, h, 999, &mut attr, 1);
        assert_eq!(rv, CKR_SESSION_READ_ONLY, "expected CKR_SESSION_READ_ONLY, got {rv:#010x}");
        p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn ro_session_generate_key_returns_session_read_only() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_ro_session();
        let mech = null_mech();

        let token_true = [CK_TRUE];
        let template = [CK_ATTRIBUTE {
            r#type: CKA_TOKEN,
            pValue: token_true.as_ptr() as *mut _,
            ulValueLen: 1,
        }];
        let mut key_h: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_GenerateKey, h, &mech, template.as_ptr(), 1, &mut key_h);
        assert_eq!(rv, CKR_SESSION_READ_ONLY, "expected CKR_SESSION_READ_ONLY, got {rv:#010x}");
        p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn ro_session_generate_key_pair_returns_session_read_only() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_ro_session();
        let mech = null_mech();
        let token_true = [CK_TRUE];
        let template = [CK_ATTRIBUTE {
            r#type: CKA_TOKEN,
            pValue: token_true.as_ptr() as *mut _,
            ulValueLen: 1,
        }];
        let mut pub_h: CK_OBJECT_HANDLE = 0;
        let mut priv_h: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_GenerateKeyPair,
                      h, &mech,
                      template.as_ptr(), 1,
                      ptr::null(), 0,
                      &mut pub_h, &mut priv_h);
        assert_eq!(rv, CKR_SESSION_READ_ONLY, "expected CKR_SESSION_READ_ONLY, got {rv:#010x}");
        p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn ro_session_unwrap_key_returns_session_read_only() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_ro_session();
        let mech = null_mech();
        let wrapped: [u8; 8] = [0u8; 8];
        let token_true = [CK_TRUE];
        let template = [CK_ATTRIBUTE {
            r#type:     CKA_TOKEN,
            pValue:     token_true.as_ptr() as *mut _,
            ulValueLen: 1,
        }];
        let mut key_h: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_UnwrapKey,
                      h, &mech,
                      999,
                      wrapped.as_ptr(), wrapped.len() as CK_ULONG,
                      template.as_ptr(), template.len() as CK_ULONG,
                      &mut key_h);
        assert_eq!(rv, CKR_SESSION_READ_ONLY, "expected CKR_SESSION_READ_ONLY, got {rv:#010x}");
        p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn ro_session_derive_key_returns_session_read_only() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_ro_session();
        let mech = null_mech();

        let token_true = [CK_TRUE];
        let template = [CK_ATTRIBUTE {
            r#type: CKA_TOKEN,
            pValue: token_true.as_ptr() as *mut _,
            ulValueLen: 1,
        }];
        let mut key_h: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_DeriveKey,
                      h, &mech,
                      999,
                      template.as_ptr(), 1,
                      &mut key_h);
        assert_eq!(rv, CKR_SESSION_READ_ONLY, "expected CKR_SESSION_READ_ONLY, got {rv:#010x}");
        p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn ro_session_init_pin_returns_session_read_only() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_ro_session();
        let pin = b"1234";
        let rv = p11!(fl, C_InitPIN, h, pin.as_ptr(), pin.len() as CK_ULONG);
        assert_eq!(rv, CKR_SESSION_READ_ONLY, "expected CKR_SESSION_READ_ONLY, got {rv:#010x}");
        p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn ro_session_set_pin_returns_session_read_only() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_ro_session();
        let old_pin = b"1234";
        let new_pin = b"5678";
        let rv = p11!(fl, C_SetPIN,
                      h,
                      old_pin.as_ptr(), old_pin.len() as CK_ULONG,
                      new_pin.as_ptr(), new_pin.len() as CK_ULONG);
        assert_eq!(rv, CKR_SESSION_READ_ONLY, "expected CKR_SESSION_READ_ONLY, got {rv:#010x}");
        p11!(fl, C_CloseSession, h);
    }
}

/// Sanity check: an RW session must NOT be rejected by the RW check.
#[test]
fn rw_session_is_not_blocked() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = common::open_session(fl);  // opens with CKF_RW_SESSION
        let mut dummy: CK_OBJECT_HANDLE = 0;
        // null template → CKR_ARGUMENTS_BAD (not CKR_SESSION_READ_ONLY)
        let rv = p11!(fl, C_CreateObject, h, ptr::null(), 0, &mut dummy);
        assert_ne!(rv, CKR_SESSION_READ_ONLY,
                   "RW session must not get CKR_SESSION_READ_ONLY, got {rv:#010x}");
        p11!(fl, C_CloseSession, h);
    }
}
