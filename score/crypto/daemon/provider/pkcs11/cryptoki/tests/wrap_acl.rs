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

//! Integration tests for: wrap/unwrap access control.
//!
//! Covers:
//! - `C_WrapKey`: three access-control checks (CKA_WRAP, CKA_EXTRACTABLE,
//!   CKA_WRAP_WITH_TRUSTED / CKA_TRUSTED)
//! - `C_UnwrapKey`: unwrapped key has `CKA_LOCAL=FALSE` and
//!   `CKA_KEY_GEN_MECHANISM` set to the unwrap mechanism.

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
        assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
                "C_Initialize failed: {rv:#010x}");
    });
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Generate an AES-128 session key with `extra_attrs` merged into the template.
///
/// Note: `C_GenerateKey` defaults `CKA_SENSITIVE=TRUE, CKA_EXTRACTABLE=FALSE`.
/// Callers must explicitly pass `CKA_EXTRACTABLE=TRUE` when the key must be
/// wrappable (i.e. extractable).
unsafe fn make_aes_key(
    session:     CK_SESSION_HANDLE,
    extra_attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> CK_OBJECT_HANDLE {
    let fl = common::fn_list();
    let mut attrs_data: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = vec![
        (CKA_TOKEN,     vec![CK_FALSE]),
        (CKA_VALUE_LEN, 16u64.to_le_bytes().to_vec()),
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
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut handle: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKey, session, &mut mech, raw.as_mut_ptr(), raw.len() as CK_ULONG, &mut handle);
    assert_eq!(rv, CKR_OK, "C_GenerateKey failed: {rv:#010x}");
    handle
}

/// Call `C_WrapKey(CKM_AES_KEY_WRAP)` and return the raw CK_RV.
unsafe fn do_wrap(
    session:      CK_SESSION_HANDLE,
    wrapping_key: CK_OBJECT_HANDLE,
    target_key:   CK_OBJECT_HANDLE,
) -> CK_RV {
    let fl = common::fn_list();
    let mech = CK_MECHANISM {
        mechanism:      CKM_AES_KEY_WRAP,
        pParameter:     ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut wrapped_len: CK_ULONG = 0;
    // Size query first (p_wrapped_key = null).
    p11!(fl, C_WrapKey, session, &mech, wrapping_key, target_key,
        ptr::null_mut(), &mut wrapped_len)
}

/// Read a single boolean attribute from a key object. Returns `None` if not found.
unsafe fn get_bool_attr(
    session:   CK_SESSION_HANDLE,
    handle:    CK_OBJECT_HANDLE,
    attr_type: CK_ATTRIBUTE_TYPE,
) -> Option<bool> {
    let fl = common::fn_list();
    let mut val: CK_BBOOL = 0;
    let mut attr = CK_ATTRIBUTE {
        r#type:     attr_type,
        pValue:     &mut val as *mut _ as *mut _,
        ulValueLen: 1,
    };
    let rv = p11!(fl, C_GetAttributeValue, session, handle, &mut attr, 1);
    if rv == CKR_ATTRIBUTE_TYPE_INVALID || rv == CKR_ATTRIBUTE_SENSITIVE { return None; }
    assert_eq!(rv, CKR_OK, "C_GetAttributeValue({attr_type:#010x}) failed: {rv:#010x}");
    Some(val == CK_TRUE)
}

/// Read CKA_KEY_GEN_MECHANISM (a CK_MECHANISM_TYPE / CK_ULONG) from a key.
unsafe fn get_key_gen_mechanism(
    session: CK_SESSION_HANDLE,
    handle:  CK_OBJECT_HANDLE,
) -> CK_ULONG {
    let fl = common::fn_list();
    let mut val: CK_ULONG = 0;
    let mut attr = CK_ATTRIBUTE {
        r#type:     CKA_KEY_GEN_MECHANISM,
        pValue:     &mut val as *mut _ as *mut _,
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    };
    let rv = p11!(fl, C_GetAttributeValue, session, handle, &mut attr, 1);
    assert_eq!(rv, CKR_OK, "C_GetAttributeValue(CKA_KEY_GEN_MECHANISM) failed: {rv:#010x}");
    val
}

// ── C_WrapKey access control tests ───────────────────────────────────────────

/// Wrapping key without CKA_WRAP=TRUE → CKR_KEY_FUNCTION_NOT_PERMITTED.
#[test]
fn wrap_key_without_wrap_flag_rejected() {
    init();
    unsafe {
        let fl = common::fn_list();
        let session = common::open_session(fl);

        // Wrapping key: CKA_WRAP not set (defaults absent → false).
        let wrap_key = make_aes_key(session, &[
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
        ]);
        // Target key: extractable.
        let target = make_aes_key(session, &[
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
        ]);

        let rv = do_wrap(session, wrap_key, target);
        assert_eq!(rv, CKR_KEY_FUNCTION_NOT_PERMITTED,
                   "missing CKA_WRAP must yield CKR_KEY_FUNCTION_NOT_PERMITTED, got {rv:#010x}");

        p11!(fl, C_CloseSession, session);
    }
}

/// Target key not extractable → CKR_KEY_UNEXTRACTABLE.
#[test]
fn wrap_non_extractable_target_rejected() {
    init();
    unsafe {
        let fl = common::fn_list();
        let session = common::open_session(fl);

        // Wrapping key: CKA_WRAP=TRUE.
        let wrap_key = make_aes_key(session, &[
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
            (CKA_WRAP,        vec![CK_TRUE]),
        ]);
        // Target key: CKA_EXTRACTABLE=FALSE (the default from C_GenerateKey).
        let target = make_aes_key(session, &[]);  // no EXTRACTABLE → defaults to FALSE

        let rv = do_wrap(session, wrap_key, target);
        assert_eq!(rv, CKR_KEY_UNEXTRACTABLE,
                   "non-extractable target must yield CKR_KEY_UNEXTRACTABLE, got {rv:#010x}");

        p11!(fl, C_CloseSession, session);
    }
}

/// Target has CKA_WRAP_WITH_TRUSTED=TRUE but wrapping key has CKA_TRUSTED=FALSE
/// → CKR_KEY_NOT_WRAPPABLE.
#[test]
fn wrap_with_trusted_requires_trusted_key() {
    init();
    unsafe {
        let fl = common::fn_list();
        let session = common::open_session(fl);

        // Wrapping key: CKA_WRAP=TRUE but NOT trusted.
        let wrap_key = make_aes_key(session, &[
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
            (CKA_WRAP,        vec![CK_TRUE]),
            // CKA_TRUSTED intentionally absent (= FALSE).
        ]);
        // Target key: extractable but requires a trusted wrapping key.
        let target = make_aes_key(session, &[
            (CKA_EXTRACTABLE,       vec![CK_TRUE]),
            (CKA_WRAP_WITH_TRUSTED, vec![CK_TRUE]),
        ]);

        let rv = do_wrap(session, wrap_key, target);
        assert_eq!(rv, CKR_KEY_NOT_WRAPPABLE,
                   "untrusted key wrapping WRAP_WITH_TRUSTED target must yield CKR_KEY_NOT_WRAPPABLE, got {rv:#010x}");

        p11!(fl, C_CloseSession, session);
    }
}

/// Target has CKA_WRAP_WITH_TRUSTED=TRUE and wrapping key has CKA_TRUSTED=TRUE
/// → wrap succeeds.
#[test]
fn wrap_with_trusted_key_succeeds() {
    init();
    unsafe {
        let fl = common::fn_list();
        let session = common::open_session(fl);

        // Wrapping key: CKA_WRAP=TRUE and CKA_TRUSTED=TRUE.
        let wrap_key = make_aes_key(session, &[
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
            (CKA_WRAP,        vec![CK_TRUE]),
            (CKA_TRUSTED,     vec![CK_TRUE]),
        ]);
        // Target: extractable, requires trusted wrapping key.
        let target = make_aes_key(session, &[
            (CKA_EXTRACTABLE,       vec![CK_TRUE]),
            (CKA_WRAP_WITH_TRUSTED, vec![CK_TRUE]),
        ]);

        // Size-query wrap: expect OK (not an access-control error).
        let rv = do_wrap(session, wrap_key, target);
        assert_eq!(rv, CKR_OK,
                   "trusted key wrapping WRAP_WITH_TRUSTED target must succeed, got {rv:#010x}");

        p11!(fl, C_CloseSession, session);
    }
}

/// Happy path: CKA_WRAP=TRUE on wrapping key, CKA_EXTRACTABLE=TRUE on target,
/// no CKA_WRAP_WITH_TRUSTED constraint → wrap succeeds.
#[test]
fn wrap_happy_path_succeeds() {
    init();
    unsafe {
        let fl = common::fn_list();
        let session = common::open_session(fl);

        let wrap_key = make_aes_key(session, &[
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
            (CKA_WRAP,        vec![CK_TRUE]),
        ]);
        let target = make_aes_key(session, &[
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
        ]);

        let rv = do_wrap(session, wrap_key, target);
        assert_eq!(rv, CKR_OK, "happy-path wrap must succeed, got {rv:#010x}");

        p11!(fl, C_CloseSession, session);
    }
}

// ── C_UnwrapKey attribute tests ───────────────────────────────────────────────

/// After unwrapping, the resulting key must have CKA_LOCAL=FALSE.
#[test]
fn unwrapped_key_is_not_local() {
    init();
    unsafe {
        let fl = common::fn_list();
        let session = common::open_session(fl);

        // Wrapping key.
        let wrap_key = make_aes_key(session, &[
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
            (CKA_WRAP,        vec![CK_TRUE]),
            (CKA_UNWRAP,      vec![CK_TRUE]),
        ]);
        // Target key to wrap.
        let target = make_aes_key(session, &[
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
        ]);

        // Wrap the target key.
        let mech = CK_MECHANISM {
            mechanism: CKM_AES_KEY_WRAP, pParameter: ptr::null_mut(), ulParameterLen: 0,
        };
        // Size query.
        let mut wrapped_len: CK_ULONG = 0;
        let rv = p11!(fl, C_WrapKey, session, &mech, wrap_key, target,
                      ptr::null_mut(), &mut wrapped_len);
        assert_eq!(rv, CKR_OK);
        // Actual wrap.
        let mut wrapped_buf = vec![0u8; wrapped_len as usize];
        let rv = p11!(fl, C_WrapKey, session, &mech, wrap_key, target,
                      wrapped_buf.as_mut_ptr(), &mut wrapped_len);
        assert_eq!(rv, CKR_OK, "wrap failed: {rv:#010x}");

        // Unwrap.
        let unwrap_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)] = &[
            (CKA_TOKEN,       vec![CK_FALSE]),
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
        ];
        let mut raw_tmpl: Vec<CK_ATTRIBUTE> = unwrap_template
            .iter()
            .map(|(t, v)| CK_ATTRIBUTE {
                r#type: *t, pValue: v.as_ptr() as *mut _, ulValueLen: v.len() as CK_ULONG,
            })
            .collect();
        let mut new_key: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_UnwrapKey, session, &mech, wrap_key,
                      wrapped_buf.as_ptr(), wrapped_len,
                      raw_tmpl.as_mut_ptr(), raw_tmpl.len() as CK_ULONG,
                      &mut new_key);
        assert_eq!(rv, CKR_OK, "C_UnwrapKey failed: {rv:#010x}");

        // Verify CKA_LOCAL=FALSE on the unwrapped key.
        let local = get_bool_attr(session, new_key, CKA_LOCAL);
        assert_eq!(local, Some(false),
                   "unwrapped key must have CKA_LOCAL=FALSE, got {local:?}");

        p11!(fl, C_CloseSession, session);
    }
}

/// After unwrapping, the resulting key must have CKA_KEY_GEN_MECHANISM equal
/// to the mechanism used for unwrapping (CKM_AES_KEY_WRAP).
#[test]
fn unwrapped_key_has_correct_key_gen_mechanism() {
    init();
    unsafe {
        let fl = common::fn_list();
        let session = common::open_session(fl);

        let wrap_key = make_aes_key(session, &[
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
            (CKA_WRAP,        vec![CK_TRUE]),
            (CKA_UNWRAP,      vec![CK_TRUE]),
        ]);
        let target = make_aes_key(session, &[
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
        ]);

        let mech = CK_MECHANISM {
            mechanism: CKM_AES_KEY_WRAP, pParameter: ptr::null_mut(), ulParameterLen: 0,
        };

        // Size query then actual wrap.
        let mut wrapped_len: CK_ULONG = 0;
        p11!(fl, C_WrapKey, session, &mech, wrap_key, target, ptr::null_mut(), &mut wrapped_len);
        let mut wrapped_buf = vec![0u8; wrapped_len as usize];
        let rv = p11!(fl, C_WrapKey, session, &mech, wrap_key, target,
                      wrapped_buf.as_mut_ptr(), &mut wrapped_len);
        assert_eq!(rv, CKR_OK);

        // Unwrap.
        let unwrap_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)] = &[
            (CKA_TOKEN,       vec![CK_FALSE]),
            (CKA_EXTRACTABLE, vec![CK_TRUE]),
        ];
        let mut raw_tmpl: Vec<CK_ATTRIBUTE> = unwrap_template
            .iter()
            .map(|(t, v)| CK_ATTRIBUTE {
                r#type: *t, pValue: v.as_ptr() as *mut _, ulValueLen: v.len() as CK_ULONG,
            })
            .collect();
        let mut new_key: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_UnwrapKey, session, &mech, wrap_key,
                      wrapped_buf.as_ptr(), wrapped_len,
                      raw_tmpl.as_mut_ptr(), raw_tmpl.len() as CK_ULONG,
                      &mut new_key);
        assert_eq!(rv, CKR_OK, "C_UnwrapKey failed: {rv:#010x}");

        // Verify CKA_KEY_GEN_MECHANISM = CKM_AES_KEY_WRAP.
        let kgm = get_key_gen_mechanism(session, new_key);
        assert_eq!(kgm, CKM_AES_KEY_WRAP,
                   "unwrapped key must have CKA_KEY_GEN_MECHANISM=CKM_AES_KEY_WRAP, got {kgm:#010x}");

        p11!(fl, C_CloseSession, session);
    }
}
