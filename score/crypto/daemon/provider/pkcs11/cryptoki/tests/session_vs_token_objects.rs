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

//! Tests for: session objects must never trigger disk persistence.
//!
//! Strategy: redirect `CRYPTOKI_STORE` to a fresh temp path before each
//! scenario.  `persist_if_needed()` always writes to disk (even an empty state),
//! so checking whether the file exists is a reliable signal that persistence was
//! triggered.  All env-var tests are serialized with `STORE_LOCK` to prevent
//! parallel tests from racing on the env var.

mod common;

use std::path::PathBuf;
use std::ptr;
use std::sync::{Mutex, Once};

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;

static INIT: Once = Once::new();
fn init() {
    INIT.call_once(|| unsafe {
        let fl = common::fn_list();
        let rv = p11!(fl, C_Initialize, ptr::null_mut());
        assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "C_Initialize failed: {rv:#010x}");
    });
}

/// Serializes all tests that manipulate `CRYPTOKI_STORE`.
static STORE_LOCK: Mutex<()> = Mutex::new(());

fn lock_store() -> std::sync::MutexGuard<'static, ()> {
    STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Return a unique temp file path and guarantee it does not exist.
fn fresh_store_path(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("pkcs11_store_test_{tag}.json"));
    let _ = std::fs::remove_file(&p);
    p
}

// ── Helpers ───────────────────────────────────────────────────────────────

unsafe fn generate_aes_key(
    fl:       &CK_FUNCTION_LIST,
    session:  CK_SESSION_HANDLE,
    is_token: bool,
) -> (CK_RV, CK_OBJECT_HANDLE) {
    let key_len: CK_ULONG = 32;
    let key_len_bytes = key_len.to_le_bytes();
    let token_byte: CK_BBOOL = if is_token { CK_TRUE } else { CK_FALSE };

    let template = [
        CK_ATTRIBUTE {
            r#type:     CKA_VALUE_LEN,
            pValue:     key_len_bytes.as_ptr() as *mut _,
            ulValueLen: key_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            r#type:     CKA_TOKEN,
            pValue:     &token_byte as *const _ as *mut _,
            ulValueLen: 1,
        },
    ];
    let mech = CK_MECHANISM {
        mechanism:      CKM_AES_KEY_GEN,
        pParameter:     ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut key_h: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKey,
        session, &mech,
        template.as_ptr(), template.len() as CK_ULONG,
        &mut key_h,
    );
    (rv, key_h)
}

// ── Session object: no disk write ─────────────────────────────────────────

/// Creating a session object (`CKA_TOKEN = CK_FALSE`) must NOT write to disk.
#[test]
fn session_object_create_does_not_write_disk() {
    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("session_create");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    unsafe {
        let fl = common::fn_list();
        let h = common::open_session(fl);
        let (rv, _) = generate_aes_key(fl, h, /* is_token */ false);
        assert_eq!(rv, CKR_OK, "GenerateKey (session) failed: {rv:#010x}");

        assert!(
            !store_path.exists(),
            "session object must NOT trigger a disk write; file {:?} was created",
            store_path
        );
        p11!(fl, C_CloseSession, h);
    }

    let _ = std::fs::remove_file(&store_path);
    std::env::remove_var("CRYPTOKI_STORE");
}

/// Destroying a session object must NOT write to disk.
#[test]
fn session_object_destroy_does_not_write_disk() {
    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("session_destroy");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    unsafe {
        let fl = common::fn_list();
        let h = common::open_session(fl);

        // Create (still session — no write expected).
        let (rv, key_h) = generate_aes_key(fl, h, false);
        assert_eq!(rv, CKR_OK);
        assert!(!store_path.exists(), "session create must not write disk");

        // Destroy — also must not write.
        let rv = p11!(fl, C_DestroyObject, h, key_h);
        assert_eq!(rv, CKR_OK, "C_DestroyObject failed: {rv:#010x}");
        assert!(
            !store_path.exists(),
            "destroying a session object must NOT trigger a disk write"
        );

        p11!(fl, C_CloseSession, h);
    }

    let _ = std::fs::remove_file(&store_path);
    std::env::remove_var("CRYPTOKI_STORE");
}

/// Mutating an attribute on a session object (`C_SetAttributeValue`) must NOT
/// write to disk.
#[test]
fn session_object_set_attribute_does_not_write_disk() {
    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("session_setattr");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    unsafe {
        let fl = common::fn_list();
        let h = common::open_session(fl);
        let (rv, key_h) = generate_aes_key(fl, h, false);
        assert_eq!(rv, CKR_OK);
        assert!(!store_path.exists(), "session create must not write disk");

        // Mutate a non-sensitive attribute (CKA_LABEL).
        let label = b"test-label";
        let attr = CK_ATTRIBUTE {
            r#type:     CKA_LABEL,
            pValue:     label.as_ptr() as *mut _,
            ulValueLen: label.len() as CK_ULONG,
        };
        let rv = p11!(fl, C_SetAttributeValue, h, key_h, &attr as *const _ as *mut _, 1u64);
        assert_eq!(rv, CKR_OK, "C_SetAttributeValue failed: {rv:#010x}");
        assert!(
            !store_path.exists(),
            "C_SetAttributeValue on a session object must NOT write to disk"
        );

        p11!(fl, C_CloseSession, h);
    }

    let _ = std::fs::remove_file(&store_path);
    std::env::remove_var("CRYPTOKI_STORE");
}

// ── Token object: disk write occurs ──────────────────────────────────────

/// Creating a token object (`CKA_TOKEN = CK_TRUE`) MUST write to disk.
#[test]
fn token_object_create_writes_disk() {
    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("token_create");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    unsafe {
        let fl = common::fn_list();
        let h = common::open_session(fl);
        let (rv, _) = generate_aes_key(fl, h, /* is_token */ true);
        assert_eq!(rv, CKR_OK, "GenerateKey (token) failed: {rv:#010x}");

        assert!(
            store_path.exists(),
            "token object MUST trigger a disk write; file {:?} was not created",
            store_path
        );
        p11!(fl, C_CloseSession, h);
    }

    let _ = std::fs::remove_file(&store_path);
    std::env::remove_var("CRYPTOKI_STORE");
}

/// Destroying a token object MUST write to disk (to remove it from the store).
#[test]
fn token_object_destroy_writes_disk() {
    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("token_destroy");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    unsafe {
        let fl = common::fn_list();
        let h = common::open_session(fl);
        let (rv, key_h) = generate_aes_key(fl, h, true);
        assert_eq!(rv, CKR_OK);
        assert!(store_path.exists(), "token create must write disk");

        // Record mtime before destroy.
        let mtime_before = std::fs::metadata(&store_path).unwrap().modified().unwrap();

        // Small sleep so mtime can advance on coarse-grained filesystems.
        std::thread::sleep(std::time::Duration::from_millis(10));

        let rv = p11!(fl, C_DestroyObject, h, key_h);
        assert_eq!(rv, CKR_OK, "C_DestroyObject failed: {rv:#010x}");

        let mtime_after = std::fs::metadata(&store_path).unwrap().modified().unwrap();
        assert!(
            mtime_after > mtime_before,
            "destroying a token object must rewrite disk (mtime unchanged)"
        );

        p11!(fl, C_CloseSession, h);
    }

    let _ = std::fs::remove_file(&store_path);
    std::env::remove_var("CRYPTOKI_STORE");
}

/// Mutating an attribute on a token object (`C_SetAttributeValue`) MUST write
/// to disk so the change survives across sessions.
#[test]
fn token_object_set_attribute_writes_disk() {
    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("token_setattr");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    unsafe {
        let fl = common::fn_list();
        let h = common::open_session(fl);
        let (rv, key_h) = generate_aes_key(fl, h, true);
        assert_eq!(rv, CKR_OK);
        assert!(store_path.exists(), "token create must write disk");

        let mtime_before = std::fs::metadata(&store_path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        let label = b"persistent-label";
        let attr = CK_ATTRIBUTE {
            r#type:     CKA_LABEL,
            pValue:     label.as_ptr() as *mut _,
            ulValueLen: label.len() as CK_ULONG,
        };
        let rv = p11!(fl, C_SetAttributeValue, h, key_h, &attr as *const _ as *mut _, 1u64);
        assert_eq!(rv, CKR_OK, "C_SetAttributeValue failed: {rv:#010x}");

        let mtime_after = std::fs::metadata(&store_path).unwrap().modified().unwrap();
        assert!(
            mtime_after > mtime_before,
            "C_SetAttributeValue on a token object must rewrite disk (mtime unchanged)"
        );

        p11!(fl, C_CloseSession, h);
    }

    let _ = std::fs::remove_file(&store_path);
    std::env::remove_var("CRYPTOKI_STORE");
}

// ── Session object vanishes on session close; token object survives ───────

/// A session object must be gone after the creating session closes.
/// A token object must survive.
#[test]
fn session_object_gone_after_session_close_token_object_survives() {
    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("lifetime");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    unsafe {
        let fl = common::fn_list();
        let h = common::open_session(fl);

        let (rv, session_key_h) = generate_aes_key(fl, h, false);
        assert_eq!(rv, CKR_OK);
        let (rv, token_key_h) = generate_aes_key(fl, h, true);
        assert_eq!(rv, CKR_OK);

        // Close the session — session objects must be destroyed.
        let rv = p11!(fl, C_CloseSession, h);
        assert_eq!(rv, CKR_OK);

        // Open a new session and verify object handles.
        let h2 = common::open_session(fl);

        // Session object: handle should be invalid now.
        let mut class: CK_OBJECT_CLASS = 0;
        let mut attr = CK_ATTRIBUTE {
            r#type:     CKA_CLASS,
            pValue:     &mut class as *mut _ as *mut _,
            ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        };
        let rv = p11!(fl, C_GetAttributeValue, h2, session_key_h, &mut attr, 1u64);
        assert_eq!(rv, CKR_OBJECT_HANDLE_INVALID,
            "session object must be gone after session close");

        // Token object: must still be accessible.
        let rv = p11!(fl, C_GetAttributeValue, h2, token_key_h, &mut attr, 1u64);
        assert_eq!(rv, CKR_OK,
            "token object must survive session close");

        p11!(fl, C_CloseSession, h2);
    }

    let _ = std::fs::remove_file(&store_path);
    std::env::remove_var("CRYPTOKI_STORE");
}
