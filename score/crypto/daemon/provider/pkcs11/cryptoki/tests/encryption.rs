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
//! Each test follows the same lifecycle:
//!   loadHSMLibrary → connectToSlot (Initialize + OpenSession + Login)
//!   → generateKey → encryptData → decryptData
//!   → disconnectFromSlot (Logout + CloseSession + Finalize)

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{
    C_Initialize,
    C_OpenSession, C_CloseSession,
    C_Login, C_Logout,
    C_EncryptInit, C_Encrypt,
    C_DecryptInit, C_Decrypt,
    C_GenerateKey, C_GenerateKeyPair,
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

// ── Shared helper: open RW session + login ────────────────────────────────

unsafe fn connect_to_slot() -> CK_SESSION_HANDLE {
    let mut h: CK_SESSION_HANDLE = 0;
    assert_eq!(
        C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h),
        CKR_OK,
    );
    // Login — tolerate CKR_USER_ALREADY_LOGGED_IN (token-wide login from parallel test).
    let rv = C_Login(h, CKU_USER, SLOT_PIN.as_ptr(), SLOT_PIN.len() as CK_ULONG);
    assert!(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN, "C_Login failed: {rv:#x}");
    h
}

unsafe fn disconnect_from_slot(h: CK_SESSION_HANDLE) {
    let rv = C_Logout(h);
    assert!(rv == CKR_OK || rv == CKR_USER_NOT_LOGGED_IN, "C_Logout failed: {rv:#x}");
    assert_eq!(C_CloseSession(h), CKR_OK);
}

// ── Shared helper: generate AES key ──────────────────────────────────────

unsafe fn generate_aes_key(h: CK_SESSION_HANDLE, key_size_bytes: u64) -> CK_OBJECT_HANDLE {
    // generateAesKey(): CK_ATTRIBUTE attrib[] = { ..., {CKA_VALUE_LEN, &keySize, sizeof(CK_ULONG)} }
    let key_len_le = key_size_bytes.to_le_bytes();
    let mut attribs = [CK_ATTRIBUTE {
        r#type: CKA_VALUE_LEN,
        pValue: key_len_le.as_ptr() as *mut c_void,
        ulValueLen: 8,
    }];
    let mech = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: ptr::null(),
        ulParameterLen: 0,
    };
    let mut key_handle: CK_OBJECT_HANDLE = 0;
    assert_eq!(
        C_GenerateKey(h, &mech, attribs.as_mut_ptr(), 1, &mut key_handle),
        CKR_OK,
    );
    key_handle
}

// ── Shared helper: generate RSA-2048 key pair ─────────────────────────────

unsafe fn generate_rsa_key_pair(h: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    // generateRsaKeyPair(): CKM_RSA_PKCS_KEY_PAIR_GEN, keySize=2048
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
        C_GenerateKeyPair(
            h, &mech,
            pub_attrs.as_mut_ptr(), 1,
            priv_attrs.as_mut_ptr(), 0,
            &mut h_public, &mut h_private,
        ),
        CKR_OK,
    );
    (h_public, h_private)
}

// ── GCM parameter block (mirrors CK_GCM_PARAMS from cryptoki.h) ──────────

#[repr(C)]
#[allow(non_snake_case)]
struct GcmParams {
    pIv:      *const u8,
    ulIvLen:  u64,
    ulIvBits: u64,
    pAAD:     *const u8,
    ulAADLen: u64,
    ulTagBits: u64,
}

// ═════════════════════════════════════════════════════════════════════════════
// CKM_AES_CBC_PAD
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateAesKey() →
///   encryptData() → decryptData() → disconnectFromSlot()
///
/// encryptData():  C_EncryptInit(CKM_AES_CBC_PAD, IV) → C_Encrypt(NULL, &len) → C_Encrypt(buf, &len)
/// decryptData():  C_DecryptInit(CKM_AES_CBC_PAD, IV) → C_Decrypt(NULL, &len) → C_Decrypt(buf, &len)
#[test]
fn ckm_aes_cbc_pad() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Generate AES-256 key
        // (CK_ULONG keySize = 32; attrib CKA_VALUE_LEN = &keySize)
        let obj_handle = generate_aes_key(h_session, 32);

        // IV for CBC mode (CK_BYTE IV[] = "1234567812345678")
        let iv = b"1234567812345678";
        let mech = CK_MECHANISM {
            mechanism: CKM_AES_CBC_PAD,
            pParameter: iv.as_ptr() as *const c_void,
            ulParameterLen: 16,
        };

        // Plaintext (unsigned char plainData[] = "Earth is the third planet...")
        let plain_data = b"Earth is the third planet of our Solar System.";

        // Step 4: Encrypt — C_EncryptInit then C_Encrypt
        // (C_EncryptInit → C_Encrypt(NULL, &encLen) → C_Encrypt(encryptedData, &encLen))
        assert_eq!(C_EncryptInit(h_session, &mech, obj_handle), CKR_OK);
        let mut enc_len: CK_ULONG = 128;
        let mut encrypted_data = vec![0u8; 128];
        assert_eq!(
            C_Encrypt(
                h_session,
                plain_data.as_ptr(), plain_data.len() as CK_ULONG,
                encrypted_data.as_mut_ptr(), &mut enc_len,
            ),
            CKR_OK,
        );
        encrypted_data.truncate(enc_len as usize);
        assert!(enc_len > 0);
        assert_ne!(encrypted_data.as_slice(), plain_data.as_slice(), "ciphertext must differ from plaintext");

        // Step 5: Decrypt — C_DecryptInit then C_Decrypt
        // (C_DecryptInit → C_Decrypt(NULL, &decLen) → C_Decrypt(decryptedData, &decLen))
        assert_eq!(C_DecryptInit(h_session, &mech, obj_handle), CKR_OK);
        let mut dec_len: CK_ULONG = 128;
        let mut decrypted_data = vec![0u8; 128];
        assert_eq!(
            C_Decrypt(
                h_session,
                encrypted_data.as_ptr(), enc_len,
                decrypted_data.as_mut_ptr(), &mut dec_len,
            ),
            CKR_OK,
        );
        decrypted_data.truncate(dec_len as usize);
        assert_eq!(decrypted_data, plain_data.as_slice(), "decrypted must equal original plaintext");

        // Step 6: Logout and close session
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// CKM_AES_GCM
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateAesKey() →
///   initGCMParam() → encryptData() → decryptData() → disconnectFromSlot()
///
/// GCM params (gcmParam.pIv / .ulIvLen / .pAAD / .ulAADLen / .ulTagBits = 128)
/// encryptData():  C_EncryptInit(CKM_AES_GCM, &gcmParam) → C_Encrypt(NULL, &encLen) → C_Encrypt(buf, &encLen)
/// decryptData():  C_DecryptInit(CKM_AES_GCM, &gcmParam) → C_Decrypt → verify plaintext
#[test]
fn ckm_aes_gcm() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Generate AES-256 key
        let obj_handle = generate_aes_key(h_session, 32);

        // Step 4: Initialize GCM parameters
        // (IV[] = "1234567812345678", AAD[] = "127.0.0.1", ulTagBits = 128)
        let iv  = b"1234567812345678";
        let aad = b"127.0.0.1";
        let gcm_params = GcmParams {
            pIv: iv.as_ptr(), ulIvLen: 16, ulIvBits: 128,
            pAAD: aad.as_ptr(), ulAADLen: aad.len() as u64,
            ulTagBits: 128,
        };
        let mech = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: &gcm_params as *const _ as *const c_void,
            ulParameterLen: std::mem::size_of::<GcmParams>() as CK_ULONG,
        };

        let plain_data = b"Earth is the third planet of our Solar System.";

        // Step 5: Encrypt — output is ciphertext || 16-byte authentication tag
        // (C_EncryptInit → C_Encrypt(NULL, &encLen) → allocate → C_Encrypt(buf, &encLen))
        assert_eq!(C_EncryptInit(h_session, &mech, obj_handle), CKR_OK);
        let mut enc_len: CK_ULONG = 256;
        let mut encrypted_data = vec![0u8; 256];
        assert_eq!(
            C_Encrypt(
                h_session,
                plain_data.as_ptr(), plain_data.len() as CK_ULONG,
                encrypted_data.as_mut_ptr(), &mut enc_len,
            ),
            CKR_OK,
        );
        encrypted_data.truncate(enc_len as usize);
        // GCM output = plaintext_len + 16-byte tag
        assert_eq!(enc_len as usize, plain_data.len() + 16, "GCM output must be plaintext + 16-byte tag");

        // Step 6: Decrypt with same GCM params (AAD must match for auth to pass)
        // (initGCMParam() → C_DecryptInit → C_Decrypt(NULL, &decLen) → C_Decrypt(buf, &decLen))
        assert_eq!(C_DecryptInit(h_session, &mech, obj_handle), CKR_OK);
        let mut dec_len: CK_ULONG = 256;
        let mut decrypted_data = vec![0u8; 256];
        assert_eq!(
            C_Decrypt(
                h_session,
                encrypted_data.as_ptr(), enc_len,
                decrypted_data.as_mut_ptr(), &mut dec_len,
            ),
            CKR_OK,
        );
        decrypted_data.truncate(dec_len as usize);
        assert_eq!(decrypted_data, plain_data.as_slice());

        // Step 7: Tamper test — flip a ciphertext byte; decryption must fail
        encrypted_data[0] ^= 0xFF;
        assert_eq!(C_DecryptInit(h_session, &mech, obj_handle), CKR_OK);
        let mut bad_len: CK_ULONG = 256;
        let mut bad = vec![0u8; 256];
        let rv = C_Decrypt(h_session, encrypted_data.as_ptr(), enc_len, bad.as_mut_ptr(), &mut bad_len);
        assert_ne!(rv, CKR_OK, "tampered GCM ciphertext must not decrypt successfully");

        // Step 8: Logout and close session
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// CKM_RSA_PKCS
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateRsaKeyPair() →
///   encryptData() → decryptData() → disconnectFromSlot()
///
/// encryptData():  C_EncryptInit(CKM_RSA_PKCS, hPublic) → C_Encrypt(NULL, &encLen) → C_Encrypt(buf, &encLen)
/// decryptData():  C_DecryptInit(CKM_RSA_PKCS, hPrivate) → C_Decrypt(NULL, &decLen) → C_Decrypt(buf, &decLen)
#[test]
fn ckm_rsa_pkcs() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Generate RSA-2048 key pair
        // (generateRsaKeyPair() → C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, ...))
        let (h_public, h_private) = generate_rsa_key_pair(h_session);

        let plain_data = b"Earth is the third planet of our Solar System.";

        // Step 4: Encrypt with the public key
        // (CK_MECHANISM mech = {CKM_RSA_PKCS}; C_EncryptInit(hSession, &mech, hPublic))
        let mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        assert_eq!(C_EncryptInit(h_session, &mech, h_public), CKR_OK);
        let mut enc_len: CK_ULONG = 512;
        let mut encrypted_data = vec![0u8; 512];
        assert_eq!(
            C_Encrypt(
                h_session,
                plain_data.as_ptr(), plain_data.len() as CK_ULONG,
                encrypted_data.as_mut_ptr(), &mut enc_len,
            ),
            CKR_OK,
        );
        encrypted_data.truncate(enc_len as usize);
        // RSA-2048 ciphertext is always 256 bytes
        assert_eq!(enc_len, 256, "RSA-2048 ciphertext must be 256 bytes");

        // Step 5: Decrypt with the private key
        // (CK_MECHANISM mech = {CKM_RSA_PKCS}; C_DecryptInit(hSession, &mech, hPrivate))
        assert_eq!(C_DecryptInit(h_session, &mech, h_private), CKR_OK);
        let mut dec_len: CK_ULONG = 512;
        let mut decrypted_data = vec![0u8; 512];
        assert_eq!(
            C_Decrypt(
                h_session,
                encrypted_data.as_ptr(), enc_len,
                decrypted_data.as_mut_ptr(), &mut dec_len,
            ),
            CKR_OK,
        );
        decrypted_data.truncate(dec_len as usize);
        assert_eq!(decrypted_data, plain_data.as_slice(), "decrypted must equal original plaintext");

        // Step 6: Logout and close session
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// CKM_RSA_PKCS_OAEP
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateRsaKeyPair() →
///   initOAEP() → encryptData() → decryptData() → disconnectFromSlot()
///
/// initOAEP():     oaepParam.hashAlg = CKM_SHA_1; oaepParam.mgf = CKG_MGF1_SHA1
/// encryptData():  C_EncryptInit(CKM_RSA_PKCS_OAEP, &oaepParam, hPublic) → C_Encrypt
/// decryptData():  C_DecryptInit(CKM_RSA_PKCS_OAEP, &oaepParam, hPrivate) → C_Decrypt
///
/// Note: our backend ignores the OAEP parameter struct and uses OpenSSL defaults.
#[test]
fn ckm_rsa_pkcs_oaep() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Generate RSA-2048 key pair
        let (h_public, h_private) = generate_rsa_key_pair(h_session);

        let plain_data = b"Earth is the third planet of our Solar System.";

        // Step 4: Encrypt with OAEP padding
        // (CK_MECHANISM mech = {CKM_RSA_PKCS_OAEP, &oaepParam, sizeof(oaepParam)})
        let mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        assert_eq!(C_EncryptInit(h_session, &mech, h_public), CKR_OK);
        let mut enc_len: CK_ULONG = 512;
        let mut encrypted_data = vec![0u8; 512];
        assert_eq!(
            C_Encrypt(
                h_session,
                plain_data.as_ptr(), plain_data.len() as CK_ULONG,
                encrypted_data.as_mut_ptr(), &mut enc_len,
            ),
            CKR_OK,
        );
        encrypted_data.truncate(enc_len as usize);
        assert_eq!(enc_len, 256, "RSA-2048 OAEP ciphertext must be 256 bytes");

        // Step 5: Decrypt with OAEP padding
        assert_eq!(C_DecryptInit(h_session, &mech, h_private), CKR_OK);
        let mut dec_len: CK_ULONG = 512;
        let mut decrypted_data = vec![0u8; 512];
        assert_eq!(
            C_Decrypt(
                h_session,
                encrypted_data.as_ptr(), enc_len,
                decrypted_data.as_mut_ptr(), &mut dec_len,
            ),
            CKR_OK,
        );
        decrypted_data.truncate(dec_len as usize);
        assert_eq!(decrypted_data, plain_data.as_slice(), "OAEP decrypted must equal original plaintext");

        // Step 6: Logout and close session
        disconnect_from_slot(h_session);
    }
}
