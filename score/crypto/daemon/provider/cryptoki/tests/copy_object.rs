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

//! Integration tests for: C_CopyObject.
//!
//! Verifies: basic copy (handle differs, attributes identical), copy with
//! attribute override, ratchet enforcement on copy template, and RO session
//! rejection.

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

// ── Helpers ──────────────────────────────────────────────────────────────────

fn bool_attr(val: bool) -> Vec<u8> {
    vec![if val { CK_TRUE } else { CK_FALSE }]
}

fn ulong_attr(val: CK_ULONG) -> Vec<u8> {
    val.to_le_bytes().to_vec()
}

/// Open an RW session on slot 0.
unsafe fn open_rw() -> CK_SESSION_HANDLE {
    let fl = common::fn_list();
    let mut h: CK_SESSION_HANDLE = 0;
    let rv = p11!(fl, C_OpenSession, 0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                  ptr::null_mut(), None, &mut h);
    assert_eq!(rv, CKR_OK, "C_OpenSession (RW) failed: {rv:#010x}");
    h
}

/// Open an RO session on slot 0.
unsafe fn open_ro() -> CK_SESSION_HANDLE {
    let fl = common::fn_list();
    let mut h: CK_SESSION_HANDLE = 0;
    let rv = p11!(fl, C_OpenSession, 0, CKF_SERIAL_SESSION, ptr::null_mut(), None, &mut h);
    assert_eq!(rv, CKR_OK, "C_OpenSession (RO) failed: {rv:#010x}");
    h
}

/// Generate a session AES-128 key.
unsafe fn make_aes_key(
    session: CK_SESSION_HANDLE,
    extra: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> CK_OBJECT_HANDLE {
    let fl = common::fn_list();
    let mut attrs_data: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = vec![
        (CKA_TOKEN,     bool_attr(false)),
        (CKA_VALUE_LEN, ulong_attr(16)),
    ];
    attrs_data.extend_from_slice(extra);
    let mut raw: Vec<CK_ATTRIBUTE> = attrs_data
        .iter()
        .map(|(t, v)| CK_ATTRIBUTE {
            r#type:     *t,
            pValue:     v.as_ptr() as *mut _,
            ulValueLen: v.len() as CK_ULONG,
        })
        .collect();
    let mut mech = CK_MECHANISM {
        mechanism:      CKM_AES_KEY_GEN,
        pParameter:     ptr::null(),
        ulParameterLen: 0,
    };
    let mut handle: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKey, session, &mut mech,
                  raw.as_mut_ptr(), raw.len() as CK_ULONG, &mut handle);
    assert_eq!(rv, CKR_OK, "C_GenerateKey failed: {rv:#010x}");
    handle
}

/// Read a single BBOOL attribute. Returns `None` if the call fails.
unsafe fn get_bool(session: CK_SESSION_HANDLE, obj: CK_OBJECT_HANDLE, attr_type: CK_ATTRIBUTE_TYPE) -> Option<bool> {
    let fl = common::fn_list();
    let mut val: CK_BBOOL = 0;
    let mut attr = CK_ATTRIBUTE {
        r#type:     attr_type,
        pValue:     &mut val as *mut CK_BBOOL as *mut _,
        ulValueLen: 1,
    };
    let rv = p11!(fl, C_GetAttributeValue, session, obj, &mut attr, 1u64);
    if rv == CKR_OK { Some(val != 0) } else { None }
}

/// Copy an object with the given template overrides.
unsafe fn copy(session: CK_SESSION_HANDLE, src: CK_OBJECT_HANDLE,
               overrides: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> (CK_RV, CK_OBJECT_HANDLE) {
    let fl = common::fn_list();
    let mut raw: Vec<CK_ATTRIBUTE> = overrides
        .iter()
        .map(|(t, v)| CK_ATTRIBUTE {
            r#type:     *t,
            pValue:     v.as_ptr() as *mut _,
            ulValueLen: v.len() as CK_ULONG,
        })
        .collect();
    let mut new_handle: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_CopyObject, session, src,
                  raw.as_mut_ptr(), raw.len() as CK_ULONG, &mut new_handle);
    (rv, new_handle)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// A basic copy produces a distinct handle whose attributes match the source.
#[test]
fn copy_basic_produces_new_handle() {
    init();
    unsafe {
        let session = open_rw();
        let fl = common::fn_list();
        let src = make_aes_key(session, &[(CKA_ENCRYPT, bool_attr(true))]);
        let (rv, copy_h) = copy(session, src, &[]);
        assert_eq!(rv, CKR_OK, "C_CopyObject failed: {rv:#010x}");
        assert_ne!(copy_h, src, "copy must have a different handle");
        // CKA_ENCRYPT must be TRUE on the copy too.
        let enc = get_bool(session, copy_h, CKA_ENCRYPT);
        assert_eq!(enc, Some(true), "copy should inherit CKA_ENCRYPT=TRUE");
        p11!(fl, C_CloseSession, session);
    }
}

/// A copy with an attribute override reflects the new value.
#[test]
fn copy_with_attribute_override() {
    init();
    unsafe {
        let session = open_rw();
        let fl = common::fn_list();
        // Source has CKA_ENCRYPT=TRUE, CKA_DECRYPT=FALSE.
        let src = make_aes_key(session, &[
            (CKA_ENCRYPT, bool_attr(true)),
            (CKA_DECRYPT, bool_attr(false)),
        ]);
        // Override: flip DECRYPT to TRUE on the copy.
        let (rv, copy_h) = copy(session, src, &[(CKA_DECRYPT, bool_attr(true))]);
        assert_eq!(rv, CKR_OK, "C_CopyObject with override failed: {rv:#010x}");
        let enc = get_bool(session, copy_h, CKA_ENCRYPT);
        assert_eq!(enc, Some(true), "CKA_ENCRYPT should still be TRUE");
        let dec = get_bool(session, copy_h, CKA_DECRYPT);
        assert_eq!(dec, Some(true), "CKA_DECRYPT override should be TRUE");
        p11!(fl, C_CloseSession, session);
    }
}

/// Ratchet enforcement: trying to copy a SENSITIVE key as non-sensitive must fail.
#[test]
fn copy_ratchet_sensitive_true_to_false_rejected() {
    init();
    unsafe {
        let session = open_rw();
        let fl = common::fn_list();
        let src = make_aes_key(session, &[(CKA_SENSITIVE, bool_attr(true))]);
        // Attempt to lower SENSITIVE on the copy — must be blocked.
        let (rv, _) = copy(session, src, &[(CKA_SENSITIVE, bool_attr(false))]);
        assert_eq!(rv, CKR_ATTRIBUTE_READ_ONLY,
                   "ratchet must prevent SENSITIVE TRUE→FALSE on copy: {rv:#010x}");
        p11!(fl, C_CloseSession, session);
    }
}

/// Ratchet enforcement: trying to copy a non-extractable key as extractable must fail.
#[test]
fn copy_ratchet_extractable_false_to_true_rejected() {
    init();
    unsafe {
        let session = open_rw();
        let fl = common::fn_list();
        let src = make_aes_key(session, &[(CKA_EXTRACTABLE, bool_attr(false))]);
        // Attempt to raise EXTRACTABLE on the copy — must be blocked.
        let (rv, _) = copy(session, src, &[(CKA_EXTRACTABLE, bool_attr(true))]);
        assert_eq!(rv, CKR_ATTRIBUTE_READ_ONLY,
                   "ratchet must prevent EXTRACTABLE FALSE→TRUE on copy: {rv:#010x}");
        p11!(fl, C_CloseSession, session);
    }
}

/// Attempting to copy via an RO session must return CKR_SESSION_READ_ONLY.
#[test]
fn copy_ro_session_rejected() {
    init();
    unsafe {
        let rw = open_rw();
        let ro = open_ro();
        let fl = common::fn_list();
        let src = make_aes_key(rw, &[]);
        let (rv, _) = copy(ro, src, &[(CKA_TOKEN, bool_attr(true))]);
        assert_eq!(rv, CKR_SESSION_READ_ONLY,
                   "RO session must be rejected for C_CopyObject: {rv:#010x}");
        p11!(fl, C_CloseSession, rw);
        p11!(fl, C_CloseSession, ro);
    }
}

/// The copied object is independent: destroying the copy does not affect the source.
#[test]
fn copy_is_independent_of_source() {
    init();
    unsafe {
        let session = open_rw();
        let fl = common::fn_list();
        let src = make_aes_key(session, &[]);
        let (rv, copy_h) = copy(session, src, &[]);
        assert_eq!(rv, CKR_OK);
        // Destroy the copy; source must still be usable.
        let rv2 = p11!(fl, C_DestroyObject, session, copy_h);
        assert_eq!(rv2, CKR_OK, "destroy copy failed: {rv2:#010x}");
        // Confirm source still exists by reading an attribute.
        let class = {
            let mut val: CK_ULONG = 0;
            let mut attr = CK_ATTRIBUTE {
                r#type:     CKA_CLASS,
                pValue:     &mut val as *mut CK_ULONG as *mut _,
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            };
            p11!(fl, C_GetAttributeValue, session, src, &mut attr, 1u64)
        };
        assert_eq!(class, CKR_OK, "source must still exist after copy is destroyed");
        p11!(fl, C_CloseSession, session);
    }
}
