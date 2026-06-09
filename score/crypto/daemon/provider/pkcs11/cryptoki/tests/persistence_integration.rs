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

//! Integration tests for persistent token storage.
//!
//! Each test uses a unique temp file via `CRYPTOKI_STORE` to avoid interference.

mod common;

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use serial_test::serial;
use std::ffi::c_void;
use std::ptr;

// ── Helpers ──────────────────────────────────────────────────────────────

unsafe fn init_and_open_session() -> CK_SESSION_HANDLE {
    let fl = common::fn_list();
    let rv = p11!(fl, C_Initialize, ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
        "C_Initialize failed: {rv:#010x}");

    let mut h: CK_SESSION_HANDLE = 0;
    let rv = p11!(fl, C_OpenSession, 0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                   ptr::null_mut(), None, &mut h);
    assert_eq!(rv, CKR_OK, "C_OpenSession failed: {rv:#010x}");

    let pin = b"1234";
    let rv = p11!(fl, C_Login, h, CKU_USER, pin.as_ptr(), pin.len() as CK_ULONG);
    assert!(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN,
        "C_Login failed: {rv:#010x}");
    h
}

unsafe fn generate_aes_token_key(session: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let fl = common::fn_list();
    let key_len: CK_ULONG = 32;
    let ck_true: CK_BBOOL = CK_TRUE;
    let template = [
        CK_ATTRIBUTE { r#type: CKA_VALUE_LEN, pValue: &key_len as *const _ as *mut c_void, ulValueLen: 8 },
        CK_ATTRIBUTE { r#type: CKA_ENCRYPT, pValue: &ck_true as *const _ as *mut c_void, ulValueLen: 1 },
        CK_ATTRIBUTE { r#type: CKA_DECRYPT, pValue: &ck_true as *const _ as *mut c_void, ulValueLen: 1 },
        CK_ATTRIBUTE { r#type: CKA_TOKEN, pValue: &ck_true as *const _ as *mut c_void, ulValueLen: 1 },
    ];
    let mech = CK_MECHANISM { mechanism: CKM_AES_KEY_GEN, pParameter: ptr::null_mut(), ulParameterLen: 0 };
    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKey, session, &mech as *const _ as *mut CK_MECHANISM,
                   template.as_ptr() as *mut CK_ATTRIBUTE, template.len() as CK_ULONG,
                   &mut key_handle);
    assert_eq!(rv, CKR_OK, "C_GenerateKey failed: {rv:#010x}");
    key_handle
}

unsafe fn count_secret_keys(session: CK_SESSION_HANDLE) -> usize {
    let fl = common::fn_list();
    let class: CK_ULONG = CKO_SECRET_KEY;
    let template = [CK_ATTRIBUTE {
        r#type: CKA_CLASS,
        pValue: &class as *const _ as *mut c_void,
        ulValueLen: 8,
    }];
    let rv = p11!(fl, C_FindObjectsInit, session, template.as_ptr() as *mut CK_ATTRIBUTE, 1);
    assert_eq!(rv, CKR_OK);

    let mut handles = [0u64; 64];
    let mut count: CK_ULONG = 0;
    let rv = p11!(fl, C_FindObjects, session, handles.as_mut_ptr(), 64, &mut count);
    assert_eq!(rv, CKR_OK);

    let rv = p11!(fl, C_FindObjectsFinal, session);
    assert_eq!(rv, CKR_OK);

    count as usize
}

// ── Tests ────────────────────────────────────────────────────────────────

#[test]
#[serial]
fn test_token_objects_persist_across_finalize() {
    let store_path = format!("/tmp/pkcs11_persist_test_{}.json", std::process::id());
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    // Clean up any leftover file
    let _ = std::fs::remove_file(&store_path);

    unsafe {
        let fl = common::fn_list();

        // Session 1: create a token AES key
        let session = init_and_open_session();
        let _key = generate_aes_token_key(session);
        let count_before = count_secret_keys(session);
        assert!(count_before >= 1, "Expected at least 1 secret key, got {count_before}");

        p11!(fl, C_CloseSession, session);
        p11!(fl, C_Finalize, ptr::null_mut());

        // Verify file was written
        assert!(std::path::Path::new(&store_path).exists(),
            "Storage file should exist after C_Finalize");

        // Session 2: re-initialize and verify the key survived
        let session = init_and_open_session();
        let count_after = count_secret_keys(session);
        assert_eq!(count_after, count_before,
            "Token key should persist across C_Finalize/C_Initialize: before={count_before}, after={count_after}");

        p11!(fl, C_CloseSession, session);
        p11!(fl, C_Finalize, ptr::null_mut());
    }

    // Clean up
    let _ = std::fs::remove_file(&store_path);
}

#[test]
#[serial]
fn test_session_objects_do_not_persist() {
    let store_path = format!("/tmp/pkcs11_session_test_{}.json", std::process::id());
    std::env::set_var("CRYPTOKI_STORE", &store_path);
    let _ = std::fs::remove_file(&store_path);

    unsafe {
        let fl = common::fn_list();

        // Session 1: create an AES key WITHOUT CKA_TOKEN (defaults to CK_FALSE)
        let session = init_and_open_session();
        let key_len: CK_ULONG = 32;
        let ck_false: CK_BBOOL = CK_FALSE;
        let template = [
            CK_ATTRIBUTE { r#type: CKA_VALUE_LEN, pValue: &key_len as *const _ as *mut c_void, ulValueLen: 8 },
            CK_ATTRIBUTE { r#type: CKA_TOKEN, pValue: &ck_false as *const _ as *mut c_void, ulValueLen: 1 },
        ];
        let mech = CK_MECHANISM { mechanism: CKM_AES_KEY_GEN, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let mut key_handle: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_GenerateKey, session, &mech as *const _ as *mut CK_MECHANISM,
                       template.as_ptr() as *mut CK_ATTRIBUTE, template.len() as CK_ULONG,
                       &mut key_handle);
        assert_eq!(rv, CKR_OK);

        let count_before = count_secret_keys(session);
        assert!(count_before >= 1, "Should have at least 1 session key");

        p11!(fl, C_CloseSession, session);
        p11!(fl, C_Finalize, ptr::null_mut());

        // Session 2: re-initialize — session objects should NOT be restored
        let session = init_and_open_session();
        let count_after = count_secret_keys(session);
        assert_eq!(count_after, 0,
            "Session objects should not persist: got {count_after}");

        p11!(fl, C_CloseSession, session);
        p11!(fl, C_Finalize, ptr::null_mut());
    }

    let _ = std::fs::remove_file(&store_path);
}

#[test]
#[serial]
fn test_rsa_keypair_persists() {
    let store_path = format!("/tmp/pkcs11_rsa_persist_{}.json", std::process::id());
    std::env::set_var("CRYPTOKI_STORE", &store_path);
    let _ = std::fs::remove_file(&store_path);

    unsafe {
        let fl = common::fn_list();

        // Session 1: generate RSA key pair with CKA_TOKEN = true
        let session = init_and_open_session();
        let bits: CK_ULONG = 2048;
        let ck_true: CK_BBOOL = CK_TRUE;
        let pub_template = [
            CK_ATTRIBUTE { r#type: CKA_TOKEN, pValue: &ck_true as *const _ as *mut c_void, ulValueLen: 1 },
            CK_ATTRIBUTE { r#type: CKA_MODULUS_BITS, pValue: &bits as *const _ as *mut c_void, ulValueLen: 8 },
        ];
        let priv_template = [
            CK_ATTRIBUTE { r#type: CKA_TOKEN, pValue: &ck_true as *const _ as *mut c_void, ulValueLen: 1 },
            CK_ATTRIBUTE { r#type: CKA_SIGN, pValue: &ck_true as *const _ as *mut c_void, ulValueLen: 1 },
        ];
        let mech = CK_MECHANISM { mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let mut pub_h: CK_OBJECT_HANDLE = 0;
        let mut priv_h: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_GenerateKeyPair,
            session,
            &mech as *const _ as *mut CK_MECHANISM,
            pub_template.as_ptr() as *mut CK_ATTRIBUTE, pub_template.len() as CK_ULONG,
            priv_template.as_ptr() as *mut CK_ATTRIBUTE, priv_template.len() as CK_ULONG,
            &mut pub_h, &mut priv_h,
        );
        assert_eq!(rv, CKR_OK, "C_GenerateKeyPair failed: {rv:#010x}");

        // Count private keys
        let class: CK_ULONG = CKO_PRIVATE_KEY;
        let tmpl = [CK_ATTRIBUTE { r#type: CKA_CLASS, pValue: &class as *const _ as *mut c_void, ulValueLen: 8 }];
        let rv = p11!(fl, C_FindObjectsInit, session, tmpl.as_ptr() as *mut CK_ATTRIBUTE, 1);
        assert_eq!(rv, CKR_OK);
        let mut found = [0u64; 16];
        let mut n: CK_ULONG = 0;
        p11!(fl, C_FindObjects, session, found.as_mut_ptr(), 16, &mut n);
        p11!(fl, C_FindObjectsFinal, session);
        let priv_count_before = n;

        p11!(fl, C_CloseSession, session);
        p11!(fl, C_Finalize, ptr::null_mut());

        // Session 2: verify key pair survived
        let session = init_and_open_session();
        let rv = p11!(fl, C_FindObjectsInit, session, tmpl.as_ptr() as *mut CK_ATTRIBUTE, 1);
        assert_eq!(rv, CKR_OK);
        let mut n2: CK_ULONG = 0;
        p11!(fl, C_FindObjects, session, found.as_mut_ptr(), 16, &mut n2);
        p11!(fl, C_FindObjectsFinal, session);

        assert_eq!(n2, priv_count_before,
            "RSA private key should persist: before={priv_count_before}, after={n2}");

        p11!(fl, C_CloseSession, session);
        p11!(fl, C_Finalize, ptr::null_mut());
    }

    let _ = std::fs::remove_file(&store_path);
}

#[test]
#[serial]
fn test_storage_file_created_and_valid_json() {
    let store_path = format!("/tmp/pkcs11_json_test_{}.json", std::process::id());
    std::env::set_var("CRYPTOKI_STORE", &store_path);
    let _ = std::fs::remove_file(&store_path);

    unsafe {
        let fl = common::fn_list();

        let session = init_and_open_session();
        let _key = generate_aes_token_key(session);

        p11!(fl, C_CloseSession, session);
        p11!(fl, C_Finalize, ptr::null_mut());
    }

    // Verify the file is valid JSON
    let content = std::fs::read_to_string(&store_path)
        .expect("Storage file should exist");
    let parsed: serde_json::Value = serde_json::from_str(&content)
        .expect("Storage file should be valid JSON");

    assert_eq!(parsed["version"], 1);
    assert!(!parsed["objects"].as_array().unwrap().is_empty());
    // Per-slot token state: slot 0's token should be in read_write state.
    assert_eq!(parsed["tokens"]["0"]["state"].as_str().unwrap(), "read_write");

    let _ = std::fs::remove_file(&store_path);
}
