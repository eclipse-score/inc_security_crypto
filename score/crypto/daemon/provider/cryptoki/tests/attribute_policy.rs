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

//!
//! Integration Tests for: attribute policy — one-way ratchets, immutability,
//! access control, and key-generation defaults.
//!
//! Tests exercise the policy through the public C_* API (C_SetAttributeValue,
//! C_GetAttributeValue, C_GenerateKey, C_GenerateKeyPair) so that both the
//! attribute_policy module and its integration in mod.rs are covered.

mod common;

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use std::ptr;

// ── Process-level init ───────────────────────────────────────────────────────

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

// ── Helpers ──────────────────────────────────────────────────────────────────

unsafe fn open_session() -> CK_SESSION_HANDLE {
    common::open_session(common::fn_list())
}

fn bool_attr(val: bool) -> Vec<u8> {
    vec![if val { CK_TRUE } else { CK_FALSE }]
}

fn ulong_attr(val: CK_ULONG) -> Vec<u8> {
    val.to_le_bytes().to_vec()
}

/// Generate a session AES-128 key with the given extra attributes.
unsafe fn make_aes_key(
    session: CK_SESSION_HANDLE,
    extra_attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> CK_OBJECT_HANDLE {
    let fl = common::fn_list();
    // Build the base template: token=false, value_len=16.
    let mut attrs_data: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = vec![
        (CKA_TOKEN,     bool_attr(false)),
        (CKA_VALUE_LEN, ulong_attr(16)),
    ];
    attrs_data.extend_from_slice(extra_attrs);
    let mut raw: Vec<CK_ATTRIBUTE> = attrs_data
        .iter()
        .map(|(t, v)| CK_ATTRIBUTE {
            r#type:     *t,
            pValue:     v.as_ptr() as *mut _,
            ulValueLen: v.len() as CK_ULONG,
        })
        .collect();
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: ptr::null(),
        ulParameterLen: 0,
    };
    let mut handle: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKey, session, &mut mech, raw.as_mut_ptr(), raw.len() as CK_ULONG, &mut handle);
    assert_eq!(rv, CKR_OK, "C_GenerateKey failed: {rv:#010x}");
    handle
}

/// Read a single boolean attribute from an object. Returns `None` if unavailable.
unsafe fn get_bool_attr(session: CK_SESSION_HANDLE, handle: CK_OBJECT_HANDLE, attr_type: CK_ATTRIBUTE_TYPE) -> Option<bool> {
    let fl = common::fn_list();
    let mut val: CK_BBOOL = 0;
    let mut attr = CK_ATTRIBUTE {
        r#type:     attr_type,
        pValue:     &mut val as *mut _ as *mut _,
        ulValueLen: 1,
    };
    let rv = p11!(fl, C_GetAttributeValue, session, handle, &mut attr, 1);
    if rv == CKR_ATTRIBUTE_SENSITIVE || rv == CKR_ATTRIBUTE_TYPE_INVALID {
        return None;
    }
    assert_eq!(rv, CKR_OK, "C_GetAttributeValue failed: {rv:#010x}");
    Some(val == CK_TRUE)
}

/// Set a boolean attribute. Returns the CK_RV directly.
unsafe fn set_bool_attr(
    session: CK_SESSION_HANDLE,
    handle:  CK_OBJECT_HANDLE,
    attr_type: CK_ATTRIBUTE_TYPE,
    value: bool,
) -> CK_RV {
    let fl = common::fn_list();
    let data = bool_attr(value);
    let mut attr = CK_ATTRIBUTE {
        r#type:     attr_type,
        pValue:     data.as_ptr() as *mut _,
        ulValueLen: 1,
    };
    p11!(fl, C_SetAttributeValue, session, handle, &mut attr, 1)
}

// ── Ratchet: CKA_SENSITIVE ────────────────────────────────────────────

/// CKA_SENSITIVE can go FALSE → TRUE (allowed).
#[test]
fn sensitive_false_to_true_is_allowed() {
    init();
    unsafe {
        let session = open_session();
        // Create a key explicitly with SENSITIVE=FALSE.
        let handle = make_aes_key(session, &[(CKA_SENSITIVE, bool_attr(false)), (CKA_EXTRACTABLE, bool_attr(true))]);
        assert_eq!(get_bool_attr(session, handle, CKA_SENSITIVE), Some(false));
        // Ratchet it to TRUE — must succeed.
        let rv = set_bool_attr(session, handle, CKA_SENSITIVE, true);
        assert_eq!(rv, CKR_OK, "SENSITIVE FALSE → TRUE must be allowed, got {rv:#010x}");
        assert_eq!(get_bool_attr(session, handle, CKA_SENSITIVE), Some(true));
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

/// CKA_SENSITIVE cannot go TRUE → FALSE (ratchet).
#[test]
fn sensitive_true_to_false_is_rejected() {
    init();
    unsafe {
        let session = open_session();
        // Default generated key has SENSITIVE=TRUE.
        let handle = make_aes_key(session, &[]);
        assert_eq!(get_bool_attr(session, handle, CKA_SENSITIVE), Some(true));
        // Attempt the forbidden direction.
        let rv = set_bool_attr(session, handle, CKA_SENSITIVE, false);
        assert_eq!(rv, CKR_ATTRIBUTE_READ_ONLY,
            "SENSITIVE TRUE → FALSE must return CKR_ATTRIBUTE_READ_ONLY, got {rv:#010x}");
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

// ── Ratchet: CKA_EXTRACTABLE ─────────────────────────────────────────

/// CKA_EXTRACTABLE can go TRUE → FALSE (allowed).
#[test]
fn extractable_true_to_false_is_allowed() {
    init();
    unsafe {
        let session = open_session();
        // Create a key with SENSITIVE=FALSE, EXTRACTABLE=TRUE to start.
        let handle = make_aes_key(session, &[
            (CKA_SENSITIVE,   bool_attr(false)),
            (CKA_EXTRACTABLE, bool_attr(true)),
        ]);
        assert_eq!(get_bool_attr(session, handle, CKA_EXTRACTABLE), Some(true));
        let rv = set_bool_attr(session, handle, CKA_EXTRACTABLE, false);
        assert_eq!(rv, CKR_OK, "EXTRACTABLE TRUE → FALSE must be allowed, got {rv:#010x}");
        assert_eq!(get_bool_attr(session, handle, CKA_EXTRACTABLE), Some(false));
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

/// CKA_EXTRACTABLE cannot go FALSE → TRUE (ratchet).
#[test]
fn extractable_false_to_true_is_rejected() {
    init();
    unsafe {
        let session = open_session();
        // Default generated key has EXTRACTABLE=FALSE.
        let handle = make_aes_key(session, &[]);
        assert_eq!(get_bool_attr(session, handle, CKA_EXTRACTABLE), Some(false));
        let rv = set_bool_attr(session, handle, CKA_EXTRACTABLE, true);
        assert_eq!(rv, CKR_ATTRIBUTE_READ_ONLY,
            "EXTRACTABLE FALSE → TRUE must return CKR_ATTRIBUTE_READ_ONLY, got {rv:#010x}");
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

// ── Immutable attributes ──────────────────────────────────────────────

/// CKA_KEY_TYPE is immutable after creation.
#[test]
fn key_type_is_immutable() {
    init();
    unsafe {
        let session = open_session();
        let handle = make_aes_key(session, &[]);
        // Attempt to change CKA_KEY_TYPE to something else (CKK_DES = 0x13).
        let new_type = ulong_attr(0x13);
        let mut attr = CK_ATTRIBUTE {
            r#type:     CKA_KEY_TYPE,
            pValue:     new_type.as_ptr() as *mut _,
            ulValueLen: new_type.len() as CK_ULONG,
        };
        let rv = p11!(common::fn_list(), C_SetAttributeValue, session, handle, &mut attr, 1);
        assert_eq!(rv, CKR_ATTRIBUTE_READ_ONLY,
            "CKA_KEY_TYPE must be immutable, got {rv:#010x}");
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

/// CKA_CLASS is immutable after creation.
#[test]
fn class_is_immutable() {
    init();
    unsafe {
        let session = open_session();
        let handle = make_aes_key(session, &[]);
        let new_class = ulong_attr(CKO_PUBLIC_KEY);
        let mut attr = CK_ATTRIBUTE {
            r#type:     CKA_CLASS,
            pValue:     new_class.as_ptr() as *mut _,
            ulValueLen: new_class.len() as CK_ULONG,
        };
        let rv = p11!(common::fn_list(), C_SetAttributeValue, session, handle, &mut attr, 1);
        assert_eq!(rv, CKR_ATTRIBUTE_READ_ONLY,
            "CKA_CLASS must be immutable, got {rv:#010x}");
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

/// CKA_VALUE_LEN is immutable after creation.
#[test]
fn value_len_is_immutable() {
    init();
    unsafe {
        let session = open_session();
        let handle = make_aes_key(session, &[]);
        let new_len = ulong_attr(32);
        let mut attr = CK_ATTRIBUTE {
            r#type:     CKA_VALUE_LEN,
            pValue:     new_len.as_ptr() as *mut _,
            ulValueLen: new_len.len() as CK_ULONG,
        };
        let rv = p11!(common::fn_list(), C_SetAttributeValue, session, handle, &mut attr, 1);
        assert_eq!(rv, CKR_ATTRIBUTE_READ_ONLY,
            "CKA_VALUE_LEN must be immutable, got {rv:#010x}");
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

// ── CKA_VALUE access control ─────────────────────────────────────────

/// CKA_VALUE must be blocked on a sensitive key.
#[test]
fn value_blocked_when_sensitive() {
    init();
    unsafe {
        let session = open_session();
        // Default key: SENSITIVE=TRUE.
        let handle = make_aes_key(session, &[]);
        assert_eq!(get_bool_attr(session, handle, CKA_SENSITIVE), Some(true));

        let mut val_buf = vec![0u8; 32];
        let mut attr = CK_ATTRIBUTE {
            r#type:     CKA_VALUE,
            pValue:     val_buf.as_mut_ptr() as *mut _,
            ulValueLen: 32,
        };
        let rv = p11!(common::fn_list(), C_GetAttributeValue, session, handle, &mut attr, 1);
        assert_eq!(rv, CKR_ATTRIBUTE_SENSITIVE,
            "CKA_VALUE on a sensitive key must return CKR_ATTRIBUTE_SENSITIVE, got {rv:#010x}");
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

/// CKA_VALUE must be blocked on a non-extractable key (even if not sensitive).
#[test]
fn value_blocked_when_not_extractable() {
    init();
    unsafe {
        let session = open_session();
        // Explicitly sensitive=false but extractable=false.
        let handle = make_aes_key(session, &[
            (CKA_SENSITIVE,   bool_attr(false)),
            (CKA_EXTRACTABLE, bool_attr(false)),
        ]);
        assert_eq!(get_bool_attr(session, handle, CKA_SENSITIVE),   Some(false));
        assert_eq!(get_bool_attr(session, handle, CKA_EXTRACTABLE), Some(false));

        let mut val_buf = vec![0u8; 32];
        let mut attr = CK_ATTRIBUTE {
            r#type:     CKA_VALUE,
            pValue:     val_buf.as_mut_ptr() as *mut _,
            ulValueLen: 32,
        };
        let rv = p11!(common::fn_list(), C_GetAttributeValue, session, handle, &mut attr, 1);
        assert_eq!(rv, CKR_ATTRIBUTE_SENSITIVE,
            "CKA_VALUE on a non-extractable key must return CKR_ATTRIBUTE_SENSITIVE, got {rv:#010x}");
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

// ── Key-generation defaults ──────────────────────────────────────────

/// A generated AES key has SENSITIVE=TRUE and EXTRACTABLE=FALSE by default.
#[test]
fn generated_aes_key_has_secure_defaults() {
    init();
    unsafe {
        let session = open_session();
        let handle = make_aes_key(session, &[]);
        assert_eq!(get_bool_attr(session, handle, CKA_SENSITIVE),   Some(true),  "default SENSITIVE must be TRUE");
        assert_eq!(get_bool_attr(session, handle, CKA_EXTRACTABLE), Some(false), "default EXTRACTABLE must be FALSE");
        p11!(common::fn_list(), C_CloseSession, session);
    }
}

/// A generated RSA key pair: private key has SENSITIVE=TRUE, EXTRACTABLE=FALSE.
#[test]
fn generated_rsa_private_key_has_secure_defaults() {
    init();
    unsafe {
        let fl = common::fn_list();
        let session = open_session();

        let modulus_bits_val = 2048u64.to_le_bytes().to_vec();
        let token_false = bool_attr(false);
        let mut pub_template = vec![
            CK_ATTRIBUTE {
                r#type:     CKA_TOKEN,
                pValue:     token_false.as_ptr() as *mut _,
                ulValueLen: 1,
            },
            CK_ATTRIBUTE {
                r#type:     CKA_MODULUS_BITS,
                pValue:     modulus_bits_val.as_ptr() as *mut _,
                ulValueLen: 8,
            },
        ];
        let mut priv_template = vec![
            CK_ATTRIBUTE {
                r#type:     CKA_TOKEN,
                pValue:     token_false.as_ptr() as *mut _,
                ulValueLen: 1,
            },
        ];
        let mut mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        let mut pub_h: CK_OBJECT_HANDLE = 0;
        let mut priv_h: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_GenerateKeyPair,
            session, &mut mech,
            pub_template.as_mut_ptr(), pub_template.len() as CK_ULONG,
            priv_template.as_mut_ptr(), priv_template.len() as CK_ULONG,
            &mut pub_h, &mut priv_h,
        );
        assert_eq!(rv, CKR_OK, "C_GenerateKeyPair failed: {rv:#010x}");

        assert_eq!(get_bool_attr(session, priv_h, CKA_SENSITIVE),   Some(true),  "private key default SENSITIVE must be TRUE");
        assert_eq!(get_bool_attr(session, priv_h, CKA_EXTRACTABLE), Some(false), "private key default EXTRACTABLE must be FALSE");

        p11!(fl, C_CloseSession, session);
    }
}

// ── update_derived_attributes ────────────────────────────────────────

/// Setting SENSITIVE FALSE → TRUE on a key that started non-sensitive leaves
/// always_sensitive = false (the key was not always sensitive).
/// We verify indirectly: after the ratchet, CKA_ALWAYS_SENSITIVE should be FALSE.
#[test]
fn always_sensitive_stays_false_after_ratchet_up() {
    init();
    unsafe {
        let fl = common::fn_list();
        let session = open_session();
        // Key created with SENSITIVE=FALSE → always_sensitive starts false.
        let handle = make_aes_key(session, &[
            (CKA_SENSITIVE,   bool_attr(false)),
            (CKA_EXTRACTABLE, bool_attr(true)),
        ]);
        // Ratchet SENSITIVE to TRUE.
        let rv = set_bool_attr(session, handle, CKA_SENSITIVE, true);
        assert_eq!(rv, CKR_OK);
        // always_sensitive should remain FALSE (key was not always sensitive).
        assert_eq!(get_bool_attr(session, handle, CKA_ALWAYS_SENSITIVE), Some(false),
            "CKA_ALWAYS_SENSITIVE must stay FALSE when key was created non-sensitive");
        p11!(fl, C_CloseSession, session);
    }
}

/// A key generated by C_GenerateKey with default SENSITIVE=TRUE has
/// CKA_ALWAYS_SENSITIVE=TRUE and CKA_NEVER_EXTRACTABLE=TRUE.
#[test]
fn generated_key_has_always_sensitive_and_never_extractable() {
    init();
    unsafe {
        let fl = common::fn_list();
        let session = open_session();
        let handle = make_aes_key(session, &[]);
        // These are struct fields exposed as attributes via C_GetAttributeValue.
        // The PKCS#11 spec requires them to be readable.
        assert_eq!(
            get_bool_attr(session, handle, CKA_ALWAYS_SENSITIVE),
            Some(true),
            "CKA_ALWAYS_SENSITIVE must be TRUE for a key generated with SENSITIVE=TRUE"
        );
        assert_eq!(
            get_bool_attr(session, handle, CKA_NEVER_EXTRACTABLE),
            Some(true),
            "CKA_NEVER_EXTRACTABLE must be TRUE for a key generated with EXTRACTABLE=FALSE"
        );
        p11!(fl, C_CloseSession, session);
    }
}
