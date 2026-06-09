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

//! Tests for mechanism tier policy:
//!   - RSA keygen < 2048 bits → CKR_KEY_SIZE_RANGE
//!   - Legacy mechanisms (MD5, SHA-1, SHA1_RSA_PKCS, SHA1_RSA_PKCS_PSS)
//!     hidden from C_GetMechanismList and rejected by C_GetMechanismInfo
//!     unless CRYPTOKI_LEGACY=1
//!   - Env-var opt-in exposes legacy mechanisms

mod common;

use std::mem;
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

/// Mutex that serializes all tests touching `CRYPTOKI_LEGACY`.
/// Without this, parallel tests that set/remove the env var race each other.
static LEGACY_ENV: Mutex<()> = Mutex::new(());

fn lock_legacy_env() -> std::sync::MutexGuard<'static, ()> {
    LEGACY_ENV.lock().unwrap_or_else(|e| e.into_inner())
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Collect mechanism list for slot 0.
unsafe fn get_mechanism_list() -> Vec<CK_MECHANISM_TYPE> {
    let fl = common::fn_list();
    let mut count: CK_ULONG = 0;
    let rv = p11!(fl, C_GetMechanismList, 0u64, ptr::null_mut(), &mut count);
    assert_eq!(rv, CKR_OK, "C_GetMechanismList (count) failed: {rv:#010x}");
    let mut mechs = vec![0u64; count as usize];
    let rv = p11!(fl, C_GetMechanismList, 0u64, mechs.as_mut_ptr(), &mut count);
    assert_eq!(rv, CKR_OK, "C_GetMechanismList (fill) failed: {rv:#010x}");
    mechs.truncate(count as usize);
    mechs
}

/// Query C_GetMechanismInfo for slot 0.
unsafe fn get_mech_info(mech: CK_MECHANISM_TYPE) -> (CK_RV, CK_MECHANISM_INFO) {
    let fl = common::fn_list();
    let mut info: CK_MECHANISM_INFO = mem::zeroed();
    let rv = p11!(fl, C_GetMechanismInfo, 0u64, mech, &mut info);
    (rv, info)
}

// ── Unit-level classify() tests ───────────────────────────────────────────

#[test]
fn classify_standard_mechanisms() {
    use cryptoki::pkcs11::mechanisms::{classify, MechanismTier};
    assert_eq!(classify(CKM_RSA_PKCS_KEY_PAIR_GEN, None),      MechanismTier::Standard);
    assert_eq!(classify(CKM_RSA_PKCS_KEY_PAIR_GEN, Some(2048)), MechanismTier::Standard);
    assert_eq!(classify(CKM_RSA_PKCS_KEY_PAIR_GEN, Some(4096)), MechanismTier::Standard);
    assert_eq!(classify(CKM_AES_GCM, None),                    MechanismTier::Standard);
    assert_eq!(classify(CKM_ECDSA_SHA256, None),               MechanismTier::Standard);
}

#[test]
fn classify_legacy_mechanisms() {
    use cryptoki::pkcs11::mechanisms::{classify, MechanismTier};
    assert_eq!(classify(CKM_MD5, None),              MechanismTier::Legacy);
    assert_eq!(classify(CKM_SHA_1, None),            MechanismTier::Legacy);
    assert_eq!(classify(CKM_SHA1_RSA_PKCS, None),    MechanismTier::Legacy);
    assert_eq!(classify(CKM_SHA1_RSA_PKCS_PSS, None), MechanismTier::Legacy);
}

#[test]
fn classify_forbidden_rsa_small_key() {
    use cryptoki::pkcs11::mechanisms::{classify, MechanismTier};
    assert_eq!(classify(CKM_RSA_PKCS_KEY_PAIR_GEN, Some(512)),  MechanismTier::Standard);
    assert_eq!(classify(CKM_RSA_PKCS_KEY_PAIR_GEN, Some(1024)), MechanismTier::Standard);
    assert_eq!(classify(CKM_RSA_PKCS_KEY_PAIR_GEN, Some(2047)), MechanismTier::Standard);
}

// ── C_GetMechanismList filtering ──────────────────────────────────────────

#[test]
fn mechanism_list_excludes_legacy_by_default() {
    init();
    let _guard = lock_legacy_env();
    std::env::remove_var("CRYPTOKI_LEGACY");
    unsafe {
        let mechs = get_mechanism_list();
        assert!(!mechs.contains(&CKM_MD5),
            "CKM_MD5 should be absent from mechanism list without legacy env var");
        assert!(!mechs.contains(&CKM_SHA_1),
            "CKM_SHA_1 should be absent from mechanism list without legacy env var");
        assert!(!mechs.contains(&CKM_SHA1_RSA_PKCS),
            "CKM_SHA1_RSA_PKCS should be absent without legacy env var");
        assert!(!mechs.contains(&CKM_SHA1_RSA_PKCS_PSS),
            "CKM_SHA1_RSA_PKCS_PSS should be absent without legacy env var");
    }
}

#[test]
fn mechanism_list_includes_standard_mechs() {
    init();
    let _guard = lock_legacy_env();
    std::env::remove_var("CRYPTOKI_LEGACY");
    unsafe {
        let mechs = get_mechanism_list();
        assert!(mechs.contains(&CKM_RSA_PKCS_KEY_PAIR_GEN), "RSA keygen missing");
        assert!(mechs.contains(&CKM_AES_GCM),               "AES-GCM missing");
        assert!(mechs.contains(&CKM_ECDSA_SHA256),          "ECDSA-SHA256 missing");
        assert!(mechs.contains(&CKM_SHA256),                "SHA-256 missing");
    }
}

#[test]
fn mechanism_list_includes_legacy_when_env_var_set() {
    init();
    let _guard = lock_legacy_env();
    std::env::set_var("CRYPTOKI_LEGACY", "1");
    unsafe {
        let mechs = get_mechanism_list();
        assert!(mechs.contains(&CKM_MD5),   "CKM_MD5 should appear with CRYPTOKI_LEGACY=1");
        assert!(mechs.contains(&CKM_SHA_1), "CKM_SHA_1 should appear with CRYPTOKI_LEGACY=1");
        assert!(mechs.contains(&CKM_SHA1_RSA_PKCS),
            "CKM_SHA1_RSA_PKCS should appear with CRYPTOKI_LEGACY=1");
    }
    std::env::remove_var("CRYPTOKI_LEGACY");
}

// ── C_GetMechanismInfo gating ─────────────────────────────────────────────

#[test]
fn get_mech_info_legacy_rejected_by_default() {
    init();
    let _guard = lock_legacy_env();
    std::env::remove_var("CRYPTOKI_LEGACY");
    unsafe {
        let (rv, _) = get_mech_info(CKM_MD5);
        assert_eq!(rv, CKR_MECHANISM_INVALID,
            "CKM_MD5 info should be CKR_MECHANISM_INVALID without legacy opt-in");

        let (rv, _) = get_mech_info(CKM_SHA_1);
        assert_eq!(rv, CKR_MECHANISM_INVALID,
            "CKM_SHA_1 info should be CKR_MECHANISM_INVALID without legacy opt-in");

        let (rv, _) = get_mech_info(CKM_SHA1_RSA_PKCS);
        assert_eq!(rv, CKR_MECHANISM_INVALID,
            "CKM_SHA1_RSA_PKCS info should be CKR_MECHANISM_INVALID without legacy opt-in");
    }
}

#[test]
fn get_mech_info_legacy_allowed_when_env_var_set() {
    init();
    let _guard = lock_legacy_env();
    std::env::set_var("CRYPTOKI_LEGACY", "1");
    unsafe {
        let (rv, info) = get_mech_info(CKM_MD5);
        assert_eq!(rv, CKR_OK, "CKM_MD5 info should succeed with CRYPTOKI_LEGACY=1");
        assert_eq!(info.flags & CKF_DIGEST, CKF_DIGEST);

        let (rv, _) = get_mech_info(CKM_SHA1_RSA_PKCS);
        assert_eq!(rv, CKR_OK, "CKM_SHA1_RSA_PKCS info should succeed with CRYPTOKI_LEGACY=1");
    }
    std::env::remove_var("CRYPTOKI_LEGACY");
}

// ── RSA minimum key size in C_GetMechanismInfo ────────────────────────────

#[test]
fn rsa_keygen_min_key_size_is_1024() {
    init();
    let _guard = lock_legacy_env();
    std::env::remove_var("CRYPTOKI_LEGACY");
    unsafe {
        let (rv, info) = get_mech_info(CKM_RSA_PKCS_KEY_PAIR_GEN);
        assert_eq!(rv, CKR_OK);
        assert_eq!(info.ulMinKeySize, 1024,
            "RSA keygen ulMinKeySize must be 2048, got {}", info.ulMinKeySize);
    }
}

// ── C_GenerateKeyPair RSA < 1024 rejection ────────────────────────────────

#[test]
fn rsa_keygen_1024_succeeds() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = common::open_session(fl);

        let bits: CK_ULONG = 1024;
        let bits_bytes = bits.to_le_bytes();
        let pub_template = [CK_ATTRIBUTE {
            r#type:     CKA_MODULUS_BITS,
            pValue:     bits_bytes.as_ptr() as *mut _,
            ulValueLen: bits_bytes.len() as CK_ULONG,
        }];
        let priv_template: [CK_ATTRIBUTE; 0] = [];
        let mech = CK_MECHANISM {
            mechanism:      CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter:     ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut pub_h:  CK_OBJECT_HANDLE = 0;
        let mut priv_h: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_GenerateKeyPair,
            h, &mech,
            pub_template.as_ptr(), pub_template.len() as CK_ULONG,
            priv_template.as_ptr(), priv_template.len() as CK_ULONG,
            &mut pub_h, &mut priv_h,
        );
        assert_eq!(rv, CKR_OK,
            "RSA 1024-bit keygen should succeed, got {rv:#010x}");

        p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn rsa_keygen_512_returns_key_size_range() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = common::open_session(fl);

        let bits: CK_ULONG = 512;
        let bits_bytes = bits.to_le_bytes();
        let pub_template = [CK_ATTRIBUTE {
            r#type:     CKA_MODULUS_BITS,
            pValue:     bits_bytes.as_ptr() as *mut _,
            ulValueLen: bits_bytes.len() as CK_ULONG,
        }];
        let priv_template: [CK_ATTRIBUTE; 0] = [];
        let mech = CK_MECHANISM {
            mechanism:      CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter:     ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut pub_h:  CK_OBJECT_HANDLE = 0;
        let mut priv_h: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_GenerateKeyPair,
            h, &mech,
            pub_template.as_ptr(), pub_template.len() as CK_ULONG,
            priv_template.as_ptr(), priv_template.len() as CK_ULONG,
            &mut pub_h, &mut priv_h,
        );
        assert_eq!(rv, CKR_KEY_SIZE_RANGE,
            "RSA 512-bit keygen should return CKR_KEY_SIZE_RANGE, got {rv:#010x}");

        p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn rsa_keygen_2048_succeeds() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = common::open_session(fl);

        let bits: CK_ULONG = 2048;
        let bits_bytes = bits.to_le_bytes();
        let pub_template = [CK_ATTRIBUTE {
            r#type:     CKA_MODULUS_BITS,
            pValue:     bits_bytes.as_ptr() as *mut _,
            ulValueLen: bits_bytes.len() as CK_ULONG,
        }];
        let priv_template: [CK_ATTRIBUTE; 0] = [];
        let mech = CK_MECHANISM {
            mechanism:      CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter:     ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut pub_h:  CK_OBJECT_HANDLE = 0;
        let mut priv_h: CK_OBJECT_HANDLE = 0;
        let rv = p11!(fl, C_GenerateKeyPair,
            h, &mech,
            pub_template.as_ptr(), pub_template.len() as CK_ULONG,
            priv_template.as_ptr(), priv_template.len() as CK_ULONG,
            &mut pub_h, &mut priv_h,
        );
        assert_eq!(rv, CKR_OK,
            "RSA 2048-bit keygen should succeed, got {rv:#010x}");

        p11!(fl, C_CloseSession, h);
    }
}
