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
//! Each Test follows:
//!   loadHSMLibrary → connectToSlot (Initialize + OpenSession + Login)
//!   → generateKeyPair → signData → verifyData
//!   → disconnectFromSlot (Logout + CloseSession + Finalize)

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{
    C_Initialize,
    C_OpenSession, C_CloseSession,
    C_Login, C_Logout,
    C_SignInit, C_Sign, C_SignUpdate, C_SignFinal,
    C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal,
    C_GenerateKeyPair,
};
use std::ffi::c_void;
use std::ptr;
use std::sync::Once;

const SLOT_PIN: &[u8] = b"1234";

static INIT: Once = Once::new();

fn init() {
    INIT.call_once(|| unsafe {
        let rv = C_Initialize(ptr::null_mut());
        assert!(
            rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "C_Initialize failed: {rv:#010x}",
        );
    });
}

// ── Shared helpers ────────────────────────────────────────────────────────

unsafe fn connect_to_slot() -> CK_SESSION_HANDLE {
    let mut h: CK_SESSION_HANDLE = 0;
    assert_eq!(
        C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h),
        CKR_OK,
    );
    let rv = C_Login(h, CKU_USER, SLOT_PIN.as_ptr(), SLOT_PIN.len() as CK_ULONG);
    assert!(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN, "C_Login failed: {rv:#x}");
    h
}

unsafe fn disconnect_from_slot(h: CK_SESSION_HANDLE) {
    let rv = C_Logout(h);
    assert!(rv == CKR_OK || rv == CKR_USER_NOT_LOGGED_IN, "C_Logout failed: {rv:#x}");
    assert_eq!(C_CloseSession(h), CKR_OK);
}

/// Generate RSA-2048 key pair
/// (generateRsaKeyPair() — CKM_RSA_PKCS_KEY_PAIR_GEN, keySize=2048)
unsafe fn generate_rsa_key_pair(h: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let key_bits: u64 = 2048;
    let bits_le = key_bits.to_le_bytes();
    let mut pub_attrs = [CK_ATTRIBUTE {
        r#type: CKA_MODULUS_BITS,
        pValue: bits_le.as_ptr() as *mut c_void,
        ulValueLen: 8,
    }];
    let mut priv_attrs: [CK_ATTRIBUTE; 0] = [];
    let mech = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        pParameter: ptr::null(),
        ulParameterLen: 0,
    };
    let mut h_public: CK_OBJECT_HANDLE = 0;
    let mut h_private: CK_OBJECT_HANDLE = 0;
    assert_eq!(
        C_GenerateKeyPair(h, &mech, pub_attrs.as_mut_ptr(), 1, priv_attrs.as_mut_ptr(), 0, &mut h_public, &mut h_private),
        CKR_OK,
    );
    (h_public, h_private)
}

/// Generate P-256 EC key pair
/// (generateECDSAKeyPair() — CKM_EC_KEY_PAIR_GEN, curve OID for secp256r1)
unsafe fn generate_ec_key_pair(h: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    // DER-encoded OID for P-256 (secp256r1): 06 08 2a 86 48 ce 3d 03 01 07
    // (CK_BYTE curve[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07})
    let p256_oid = [0x06u8, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let mut pub_attrs = [CK_ATTRIBUTE {
        r#type: CKA_EC_PARAMS,
        pValue: p256_oid.as_ptr() as *mut c_void,
        ulValueLen: p256_oid.len() as CK_ULONG,
    }];
    let mut priv_attrs: [CK_ATTRIBUTE; 0] = [];
    let mech = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        pParameter: ptr::null(),
        ulParameterLen: 0,
    };
    let mut h_public: CK_OBJECT_HANDLE = 0;
    let mut h_private: CK_OBJECT_HANDLE = 0;
    assert_eq!(
        C_GenerateKeyPair(h, &mech, pub_attrs.as_mut_ptr(), 1, priv_attrs.as_mut_ptr(), 0, &mut h_public, &mut h_private),
        CKR_OK,
    );
    (h_public, h_private)
}

// ═════════════════════════════════════════════════════════════════════════════
// CKM_SHA256_RSA_PKCS
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateRsaKeyPair() →
///   signData() → verifyData() → disconnectFromSlot()
///
/// signData():   C_SignInit(CKM_SHA256_RSA_PKCS, hPrivate) → C_Sign(NULL, &sigLen) → C_Sign(sig, &sigLen)
/// verifyData(): C_VerifyInit(CKM_SHA256_RSA_PKCS, hPublic) → C_Verify(data, sig)
#[test]
fn ckm_sha256_rsa_pkcs() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Generate RSA-2048 key pair
        // (generateRsaKeyPair() → C_GenerateKeyPair(..., &hPublic, &hPrivate))
        let (h_public, h_private) = generate_rsa_key_pair(h_session);

        // plainData (CK_BYTE plainData[] = "Earth is the third planet of our Solar System.")
        let plain_data = b"Earth is the third planet of our Solar System.";

        // Step 4: Sign with private key
        // (CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS}; C_SignInit → C_Sign(NULL, &sigLen) → C_Sign(sig, &sigLen))
        let mech = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        assert_eq!(C_SignInit(h_session, &mech, h_private), CKR_OK);
        let mut sig_len: CK_ULONG = 512;
        let mut signature = vec![0u8; 512];
        assert_eq!(
            C_Sign(h_session, plain_data.as_ptr(), plain_data.len() as CK_ULONG, signature.as_mut_ptr(), &mut sig_len),
            CKR_OK,
        );
        signature.truncate(sig_len as usize);
        assert_eq!(sig_len, 256, "RSA-2048 signature must be 256 bytes");

        // Step 5: Verify with public key — must succeed
        // (CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS}; C_VerifyInit → C_Verify(data, sig))
        assert_eq!(C_VerifyInit(h_session, &mech, h_public), CKR_OK);
        assert_eq!(
            C_Verify(h_session, plain_data.as_ptr(), plain_data.len() as CK_ULONG, signature.as_ptr(), sig_len),
            CKR_OK,
            "signature verification must succeed",
        );

        // Step 6: Tamper test — verify with wrong data must return CKR_SIGNATURE_INVALID
        let wrong_data = b"Mars is the fourth planet of our Solar System.";
        assert_eq!(C_VerifyInit(h_session, &mech, h_public), CKR_OK);
        assert_eq!(
            C_Verify(h_session, wrong_data.as_ptr(), wrong_data.len() as CK_ULONG, signature.as_ptr(), sig_len),
            CKR_SIGNATURE_INVALID,
            "tampered data must fail verification",
        );

        // Step 7: Logout and close session
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Extension: multi-part sign / verify (C_SignUpdate + C_SignFinal)
// ═════════════════════════════════════════════════════════════════════════════

/// Multi-part signing via C_SignUpdate + C_SignFinal, then verified both ways:
///   multi-part verify (C_VerifyUpdate + C_VerifyFinal) and one-shot (C_Verify on full message)
#[test]
fn ckm_sha256_rsa_pkcs_multipart() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Generate RSA-2048 key pair
        let (h_public, h_private) = generate_rsa_key_pair(h_session);

        let mech = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        let part1 = b"Earth is the third ";
        let part2 = b"planet of our Solar System.";
        let full  = b"Earth is the third planet of our Solar System.";

        // Step 4: Multi-part sign — C_SignInit → C_SignUpdate × N → C_SignFinal
        assert_eq!(C_SignInit(h_session, &mech, h_private), CKR_OK);
        assert_eq!(C_SignUpdate(h_session, part1.as_ptr(), part1.len() as CK_ULONG), CKR_OK);
        assert_eq!(C_SignUpdate(h_session, part2.as_ptr(), part2.len() as CK_ULONG), CKR_OK);
        let mut sig_len: CK_ULONG = 512;
        let mut signature = vec![0u8; 512];
        assert_eq!(C_SignFinal(h_session, signature.as_mut_ptr(), &mut sig_len), CKR_OK);
        signature.truncate(sig_len as usize);

        // Step 5: One-shot verify against the full concatenated message
        assert_eq!(C_VerifyInit(h_session, &mech, h_public), CKR_OK);
        assert_eq!(
            C_Verify(h_session, full.as_ptr(), full.len() as CK_ULONG, signature.as_ptr(), sig_len),
            CKR_OK,
            "one-shot verify of multi-part signature must succeed",
        );

        // Step 6: Multi-part verify — C_VerifyInit → C_VerifyUpdate × N → C_VerifyFinal
        assert_eq!(C_VerifyInit(h_session, &mech, h_public), CKR_OK);
        assert_eq!(C_VerifyUpdate(h_session, part1.as_ptr(), part1.len() as CK_ULONG), CKR_OK);
        assert_eq!(C_VerifyUpdate(h_session, part2.as_ptr(), part2.len() as CK_ULONG), CKR_OK);
        assert_eq!(C_VerifyFinal(h_session, signature.as_ptr(), sig_len), CKR_OK);

        // Step 7: Logout and close session
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// CKM_SHA256_RSA_PKCS_PSS
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateRsaKeyPair() →
///   initPSSParam() → signData() → verifyData() → disconnectFromSlot()
///
/// initPSSParam(): pssParam.hashAlg = CKM_SHA256; pssParam.mgf = CKG_MGF1_SHA256; pssParam.sLen = sizeof(plainData)-1
/// signData():     C_SignInit(CKM_SHA256_RSA_PKCS_PSS, &pssParam, hPrivate) → C_Sign(NULL, &sigLen) → C_Sign(sig, &sigLen)
/// verifyData():   C_VerifyInit(CKM_SHA256_RSA_PKCS_PSS, &pssParam, hPublic) → C_Verify
///
/// Note: our backend accepts CKM_SHA256_RSA_PKCS_PSS and ignores the param struct (uses OpenSSL PSS defaults).
#[test]
fn ckm_sha256_rsa_pkcs_pss() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Generate RSA-2048 key pair
        let (h_public, h_private) = generate_rsa_key_pair(h_session);

        let plain_data = b"Earth is the third planet of our Solar System.";

        // Step 4: Sign with PSS padding
        // (CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS_PSS, &pssParam, sizeof(pssParam)})
        let mech = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS_PSS,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        assert_eq!(C_SignInit(h_session, &mech, h_private), CKR_OK);
        let mut sig_len: CK_ULONG = 512;
        let mut signature = vec![0u8; 512];
        assert_eq!(
            C_Sign(h_session, plain_data.as_ptr(), plain_data.len() as CK_ULONG, signature.as_mut_ptr(), &mut sig_len),
            CKR_OK,
        );
        signature.truncate(sig_len as usize);
        assert_eq!(sig_len, 256, "RSA-2048 PSS signature must be 256 bytes");

        // Step 5: Verify PSS signature with public key
        // (C_VerifyInit(hSession, &mech, hPublic) → C_Verify(plainData, sigLen, signature, sigLen))
        assert_eq!(C_VerifyInit(h_session, &mech, h_public), CKR_OK);
        assert_eq!(
            C_Verify(h_session, plain_data.as_ptr(), plain_data.len() as CK_ULONG, signature.as_ptr(), sig_len),
            CKR_OK,
            "PSS signature verification must succeed",
        );

        // Step 6: Logout and close session
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// CKM_ECDSA
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateECDSAKeyPair() →
///   signData() → verifyData() → disconnectFromSlot()
///
/// generateECDSAKeyPair(): CKM_EC_KEY_PAIR_GEN with CKA_EC_PARAMS = secp256r1 OID
/// signData():   C_SignInit(CKM_ECDSA, hPrivate) → C_Sign(NULL, &sigLen) → C_Sign(sig, &sigLen)
/// verifyData(): C_VerifyInit(CKM_ECDSA, hPublic) → C_Verify(data, sigLen, sig, sigLen)
#[test]
fn ckm_ecdsa() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Generate EC P-256 key pair
        // (generateECDSAKeyPair() — curve OID bytes for secp256r1)
        let (h_public, h_private) = generate_ec_key_pair(h_session);

        let plain_data = b"Earth is the third planet of our Solar System.";

        // Step 4: Sign with ECDSA (our backend applies SHA-256 internally)
        // (CK_MECHANISM mech = {CKM_ECDSA}; C_SignInit(hSession, &mech, hPrivate))
        let mech = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        assert_eq!(C_SignInit(h_session, &mech, h_private), CKR_OK);
        let mut sig_len: CK_ULONG = 128;
        let mut signature = vec![0u8; 128];
        assert_eq!(
            C_Sign(h_session, plain_data.as_ptr(), plain_data.len() as CK_ULONG, signature.as_mut_ptr(), &mut sig_len),
            CKR_OK,
        );
        signature.truncate(sig_len as usize);
        assert!(sig_len > 0, "ECDSA signature must be non-empty");

        // Step 5: Verify with the public key — must succeed
        // (C_VerifyInit(hSession, &mech, hPublic) → C_Verify(plainData, ..., signature, sigLen))
        assert_eq!(C_VerifyInit(h_session, &mech, h_public), CKR_OK);
        assert_eq!(
            C_Verify(h_session, plain_data.as_ptr(), plain_data.len() as CK_ULONG, signature.as_ptr(), sig_len),
            CKR_OK,
            "ECDSA verification must succeed",
        );

        // Step 6: Tamper test — wrong data must return CKR_SIGNATURE_INVALID
        let wrong_data = b"Mars is the fourth planet of our Solar System.";
        assert_eq!(C_VerifyInit(h_session, &mech, h_public), CKR_OK);
        assert_eq!(
            C_Verify(h_session, wrong_data.as_ptr(), wrong_data.len() as CK_ULONG, signature.as_ptr(), sig_len),
            CKR_SIGNATURE_INVALID,
            "tampered data must fail ECDSA verification",
        );

        // Step 7: Logout and close session
        disconnect_from_slot(h_session);
    }
}
