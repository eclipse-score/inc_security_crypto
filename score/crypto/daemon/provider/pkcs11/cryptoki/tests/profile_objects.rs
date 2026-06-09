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

//! Integration tests for: CKO_PROFILE objects.
//!
//! Verifies that every initialized token advertises a `CKP_BASELINE_PROVIDER`
//! profile object and that it can be discovered and queried via the standard
//! `C_FindObjects` / `C_GetAttributeValue` flow.

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

unsafe fn open_rw_session() -> CK_SESSION_HANDLE {
    let fl = common::fn_list();
    let mut h: CK_SESSION_HANDLE = 0;
    let rv = p11!(fl, C_OpenSession, 0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                  ptr::null_mut(), None, &mut h);
    assert_eq!(rv, CKR_OK, "C_OpenSession failed: {rv:#010x}");
    h
}

/// Find objects matching a `(type, value)` template.  Returns collected handles.
unsafe fn find_all(h: CK_SESSION_HANDLE, template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> Vec<CK_OBJECT_HANDLE> {
    let fl = common::fn_list();
    let raw: Vec<CK_ATTRIBUTE> = template
        .iter()
        .map(|(t, v)| CK_ATTRIBUTE { r#type: *t, pValue: v.as_ptr() as *mut _, ulValueLen: v.len() as CK_ULONG })
        .collect();
    let rv = p11!(fl, C_FindObjectsInit, h, raw.as_ptr() as *mut _, raw.len() as CK_ULONG);
    assert_eq!(rv, CKR_OK, "C_FindObjectsInit failed: {rv:#010x}");
    let mut handles = [0u64; 32];
    let mut count: CK_ULONG = 0;
    let rv = p11!(fl, C_FindObjects, h, handles.as_mut_ptr(), handles.len() as CK_ULONG, &mut count);
    assert_eq!(rv, CKR_OK, "C_FindObjects failed: {rv:#010x}");
    let rv = p11!(fl, C_FindObjectsFinal, h);
    assert_eq!(rv, CKR_OK, "C_FindObjectsFinal failed: {rv:#010x}");
    handles[..count as usize].to_vec()
}

/// Fetch a single CK_ULONG attribute from an object.
unsafe fn get_ulong(h: CK_SESSION_HANDLE, obj: CK_OBJECT_HANDLE, attr_type: CK_ATTRIBUTE_TYPE) -> CK_ULONG {
    let fl = common::fn_list();
    let mut buf = [0u8; 8];
    let mut attr = CK_ATTRIBUTE {
        r#type:     attr_type,
        pValue:     buf.as_mut_ptr() as *mut _,
        ulValueLen: buf.len() as CK_ULONG,
    };
    let rv = p11!(fl, C_GetAttributeValue, h, obj, &mut attr, 1);
    assert_eq!(rv, CKR_OK, "C_GetAttributeValue({attr_type:#010x}) failed: {rv:#010x}");
    assert_eq!(attr.ulValueLen, 8, "ULONG attribute should be 8 bytes");
    CK_ULONG::from_le_bytes(buf)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// C_FindObjects with CKA_CLASS=CKO_PROFILE returns at least one profile object.
#[test]
fn profile_object_discoverable_via_find() {
    init();
    unsafe {
        let h = open_rw_session();
        let fl = common::fn_list();

        let template = vec![
            (CKA_CLASS, (CKO_PROFILE as CK_ULONG).to_le_bytes().to_vec()),
        ];
        let handles = find_all(h, &template);
        assert!(!handles.is_empty(), "at least one CKO_PROFILE object must exist after C_Initialize");

        p11!(fl, C_CloseSession, h);
    }
}

/// The profile object reports CKA_PROFILE_ID == CKP_BASELINE_PROVIDER.
#[test]
fn profile_object_has_baseline_provider_id() {
    init();
    unsafe {
        let h = open_rw_session();
        let fl = common::fn_list();

        let template = vec![
            (CKA_CLASS, (CKO_PROFILE as CK_ULONG).to_le_bytes().to_vec()),
        ];
        let handles = find_all(h, &template);
        assert!(!handles.is_empty());

        let profile_id = get_ulong(h, handles[0], CKA_PROFILE_ID);
        assert_eq!(profile_id, CKP_BASELINE_PROVIDER,
                   "profile object must advertise CKP_BASELINE_PROVIDER, got {profile_id:#010x}");

        p11!(fl, C_CloseSession, h);
    }
}

/// The profile object's CKA_CLASS attribute round-trips as CKO_PROFILE.
#[test]
fn profile_object_class_attribute_correct() {
    init();
    unsafe {
        let h = open_rw_session();
        let fl = common::fn_list();

        let template = vec![
            (CKA_CLASS, (CKO_PROFILE as CK_ULONG).to_le_bytes().to_vec()),
        ];
        let handles = find_all(h, &template);
        assert!(!handles.is_empty());

        let class = get_ulong(h, handles[0], CKA_CLASS);
        assert_eq!(class, CKO_PROFILE, "profile object CKA_CLASS must be CKO_PROFILE");

        p11!(fl, C_CloseSession, h);
    }
}

/// Profile objects are public (CKA_PRIVATE = FALSE) and therefore visible to
/// sessions that are not logged in.
#[test]
fn profile_object_is_public() {
    init();
    unsafe {
        let h = open_rw_session();
        let fl = common::fn_list();

        // Not logged in — find must still return the profile.
        let template = vec![
            (CKA_CLASS, (CKO_PROFILE as CK_ULONG).to_le_bytes().to_vec()),
        ];
        let handles = find_all(h, &template);
        assert!(!handles.is_empty(), "public profile must be visible without login");

        // Double-check by asking for CKA_PRIVATE directly.
        let mut priv_byte = [0u8; 1];
        let mut attr = CK_ATTRIBUTE {
            r#type:     CKA_PRIVATE,
            pValue:     priv_byte.as_mut_ptr() as *mut _,
            ulValueLen: 1,
        };
        let rv = p11!(fl, C_GetAttributeValue, h, handles[0], &mut attr, 1);
        assert_eq!(rv, CKR_OK);
        assert_eq!(priv_byte[0], CK_FALSE, "profile CKA_PRIVATE must be FALSE");

        p11!(fl, C_CloseSession, h);
    }
}

/// Profile objects are token objects (CKA_TOKEN = TRUE) so they survive across
/// sessions on the same initialized library.
#[test]
fn profile_object_is_token_object() {
    init();
    unsafe {
        let h = open_rw_session();
        let fl = common::fn_list();

        let template = vec![
            (CKA_CLASS, (CKO_PROFILE as CK_ULONG).to_le_bytes().to_vec()),
        ];
        let handles = find_all(h, &template);
        assert!(!handles.is_empty());

        let mut tok_byte = [0u8; 1];
        let mut attr = CK_ATTRIBUTE {
            r#type:     CKA_TOKEN,
            pValue:     tok_byte.as_mut_ptr() as *mut _,
            ulValueLen: 1,
        };
        let rv = p11!(fl, C_GetAttributeValue, h, handles[0], &mut attr, 1);
        assert_eq!(rv, CKR_OK);
        assert_eq!(tok_byte[0], CK_TRUE, "profile CKA_TOKEN must be TRUE");

        p11!(fl, C_CloseSession, h);
    }
}

/// Profile object survives across a close/open session cycle.
#[test]
fn profile_object_survives_session_close() {
    init();
    unsafe {
        let fl = common::fn_list();

        // First session: find profile, grab handle.
        let h1 = open_rw_session();
        let template = vec![
            (CKA_CLASS, (CKO_PROFILE as CK_ULONG).to_le_bytes().to_vec()),
        ];
        let handles1 = find_all(h1, &template);
        assert!(!handles1.is_empty());
        let original = handles1[0];
        p11!(fl, C_CloseSession, h1);

        // Second session: find profile again — must still exist.
        let h2 = open_rw_session();
        let handles2 = find_all(h2, &template);
        assert!(!handles2.is_empty(), "profile must survive session close");
        assert_eq!(handles2[0], original,
                   "profile handle should remain stable across sessions");
        p11!(fl, C_CloseSession, h2);
    }
}

/// Exactly one profile object is created per slot (no duplicates on repeated init).
#[test]
fn profile_object_is_unique_per_slot() {
    init();
    unsafe {
        let h = open_rw_session();
        let fl = common::fn_list();

        let template = vec![
            (CKA_CLASS, (CKO_PROFILE as CK_ULONG).to_le_bytes().to_vec()),
        ];
        let handles = find_all(h, &template);
        assert_eq!(handles.len(), 1, "exactly one baseline profile per slot, got {}", handles.len());

        p11!(fl, C_CloseSession, h);
    }
}
