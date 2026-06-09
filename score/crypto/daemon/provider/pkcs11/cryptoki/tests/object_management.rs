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
//! Tests follow:
//!   loadHSMLibrary → connectToSlot (Initialize + OpenSession + Login)
//!   → generate/find operations
//!   → disconnectFromSlot (Logout + CloseSession + Finalize)

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{
    C_Initialize,
    C_OpenSession, C_CloseSession,
    C_Login, C_Logout,
    C_GenerateKey, C_GenerateKeyPair,
    C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal,
    C_GetAttributeValue,
    C_DestroyObject,
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

// ═════════════════════════════════════════════════════════════════════════════
// generate_aes_key
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateAesKey() → disconnectFromSlot()
///
/// generateAesKey():
///   CK_MECHANISM mech = {CKM_AES_KEY_GEN}
///   CK_ATTRIBUTE attrib[] = { ..., {CKA_VALUE_LEN, &keySize, sizeof(CK_ULONG)} }
///   C_GenerateKey(hSession, &mech, attrib, attribLen, &objHandle)
#[test]
fn generate_aes_key() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        // (connectToSlot() → C_Initialize + C_OpenSession + C_Login)
        let h_session = connect_to_slot();

        // Step 3: Set up the AES-256 key generation template
        // (CK_ULONG keySize = 32; attrib[] = { CKA_VALUE_LEN = 32, ... })
        let key_size: u64 = 32; // 256-bit key
        let key_size_le = key_size.to_le_bytes();
        let mut attribs = [CK_ATTRIBUTE {
            r#type: CKA_VALUE_LEN,
            pValue: key_size_le.as_ptr() as *mut c_void,
            ulValueLen: 8,
        }];

        // Step 4: Generate the AES-256 key
        // (C_GenerateKey(hSession, &mech, attrib, attribLen, &objHandle))
        let mech = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        let mut obj_handle: CK_OBJECT_HANDLE = 0;
        assert_eq!(
            C_GenerateKey(h_session, &mech, attribs.as_mut_ptr(), 1, &mut obj_handle),
            CKR_OK,
            "C_GenerateKey failed",
        );
        assert_ne!(obj_handle, 0, "key handle must be non-zero");

        // Step 5: Verify the key attribute (CKA_VALUE_LEN must report 32)
        let mut val_len: u64 = 0;
        let mut attr = CK_ATTRIBUTE {
            r#type: CKA_VALUE_LEN,
            pValue: &mut val_len as *mut u64 as *mut c_void,
            ulValueLen: 8,
        };
        assert_eq!(C_GetAttributeValue(h_session, obj_handle, &mut attr, 1), CKR_OK);
        assert_eq!(val_len, 32, "CKA_VALUE_LEN must be 32 for AES-256");

        // Step 6: Logout and close session
        // (disconnectFromSlot() → C_Logout + C_CloseSession + C_Finalize)
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// generate_rsa_keypair
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateRsaKeyPair() → disconnectFromSlot()
///
/// generateRsaKeyPair():
///   CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN}
///   attribPub[] = { CKA_MODULUS_BITS=2048, CKA_PUBLIC_EXPONENT, CKA_VERIFY, CKA_ENCRYPT, ... }
///   attribPri[] = { CKA_SIGN, CKA_DECRYPT, CKA_SENSITIVE, ... }
///   C_GenerateKeyPair(hSession, &mech, attribPub, ..., attribPri, ..., &hPublic, &hPrivate)
#[test]
fn generate_rsa_keypair() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Set up the RSA-2048 key pair generation template
        // (keySize = 2048; attribPub[] = { CKA_MODULUS_BITS = 2048, ... })
        let key_bits: u64 = 2048;
        let bits_le = key_bits.to_le_bytes();
        let mut pub_attrs = [CK_ATTRIBUTE {
            r#type: CKA_MODULUS_BITS,
            pValue: bits_le.as_ptr() as *mut c_void,
            ulValueLen: 8,
        }];
        let mut priv_attrs: [CK_ATTRIBUTE; 0] = [];

        // Step 4: Generate the RSA key pair
        // (C_GenerateKeyPair(hSession, &mech, attribPub, attribLenPub, attribPri, attribLenPri, &hPublic, &hPrivate))
        let mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        let mut h_public: CK_OBJECT_HANDLE = 0;
        let mut h_private: CK_OBJECT_HANDLE = 0;
        assert_eq!(
            C_GenerateKeyPair(
                h_session, &mech,
                pub_attrs.as_mut_ptr(), 1,
                priv_attrs.as_mut_ptr(), 0,
                &mut h_public, &mut h_private,
            ),
            CKR_OK,
            "C_GenerateKeyPair (RSA) failed",
        );
        assert_ne!(h_public, 0, "public key handle must be non-zero");
        assert_ne!(h_private, 0, "private key handle must be non-zero");
        assert_ne!(h_public, h_private, "public and private handles must differ");

        // Step 5: Verify the modulus bits attribute on the public key
        let mut modulus_bits: u64 = 0;
        let mut attr = CK_ATTRIBUTE {
            r#type: CKA_MODULUS_BITS,
            pValue: &mut modulus_bits as *mut u64 as *mut c_void,
            ulValueLen: 8,
        };
        assert_eq!(C_GetAttributeValue(h_session, h_public, &mut attr, 1), CKR_OK);
        assert_eq!(modulus_bits, 2048, "CKA_MODULUS_BITS must be 2048");

        // Step 6: Logout and close session
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// generate_ecdsa_keypair
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateECDSAKeyPair() → disconnectFromSlot()
///
/// generateECDSAKeyPair():
///   CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN}
///   attribPub[] = { CKA_EC_PARAMS = secp256r1 OID, CKA_VERIFY, ... }
///   attribPri[] = { CKA_SIGN, CKA_SENSITIVE, ... }
///   C_GenerateKeyPair(hSession, &mech, attribPub, ..., attribPri, ..., &hPublic, &hPrivate)
#[test]
fn generate_ecdsa_keypair() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Set up the EC P-256 key pair generation template
        // (CK_BYTE curve[] = {0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07}  — secp256r1 OID)
        let p256_oid = [0x06u8, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let mut pub_attrs = [CK_ATTRIBUTE {
            r#type: CKA_EC_PARAMS,
            pValue: p256_oid.as_ptr() as *mut c_void,
            ulValueLen: p256_oid.len() as CK_ULONG,
        }];
        let mut priv_attrs: [CK_ATTRIBUTE; 0] = [];

        // Step 4: Generate the EC key pair
        // (C_GenerateKeyPair(hSession, &mech, attribPub, attribLenPub, attribPri, attribLenPri, &hPublic, &hPrivate))
        let mech = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        let mut h_public: CK_OBJECT_HANDLE = 0;
        let mut h_private: CK_OBJECT_HANDLE = 0;
        assert_eq!(
            C_GenerateKeyPair(
                h_session, &mech,
                pub_attrs.as_mut_ptr(), 1,
                priv_attrs.as_mut_ptr(), 0,
                &mut h_public, &mut h_private,
            ),
            CKR_OK,
            "C_GenerateKeyPair (EC) failed",
        );
        assert_ne!(h_public, 0, "EC public key handle must be non-zero");
        assert_ne!(h_private, 0, "EC private key handle must be non-zero");

        // Step 5: Logout and close session
        disconnect_from_slot(h_session);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// count_all_keys
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() →
///   countAllObjects() → countPrivateKeys() → countPublicKeys() → countSecretKeys()
///   → disconnectFromSlot()
///
/// countAllObjects():
///   C_FindObjectsInit(CKA_TOKEN=TRUE) →
///   [loop] C_FindObjects(objHandle, 10, &objCount) until objCount == 0 →
///   C_FindObjectsFinal
///
/// countPrivateKeys():
///   attrib[] = { CKA_CLASS=CKO_PRIVATE_KEY, CKA_KEY_TYPE=CKK_EC }
///   C_FindObjectsInit → C_FindObjects → C_FindObjectsFinal
///
/// Similar for public and secret keys.
#[test]
fn count_all_keys() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        let h_session = connect_to_slot();

        // Step 3: Generate a set of keys to find
        // (ensures there are known objects in the store)
        let aes_key = {
            let key_size: u64 = 32;
            let key_size_le = key_size.to_le_bytes();
            let mut attrs = [CK_ATTRIBUTE {
                r#type: CKA_VALUE_LEN,
                pValue: key_size_le.as_ptr() as *mut c_void,
                ulValueLen: 8,
            }];
            let mech = CK_MECHANISM { mechanism: CKM_AES_KEY_GEN, pParameter: ptr::null(), ulParameterLen: 0 };
            let mut kh: CK_OBJECT_HANDLE = 0;
            assert_eq!(C_GenerateKey(h_session, &mech, attrs.as_mut_ptr(), 1, &mut kh), CKR_OK);
            kh
        };
        let (rsa_pub, rsa_priv) = {
            let bits: u64 = 2048;
            let bits_le = bits.to_le_bytes();
            let mut pub_attrs = [CK_ATTRIBUTE { r#type: CKA_MODULUS_BITS, pValue: bits_le.as_ptr() as *mut c_void, ulValueLen: 8 }];
            let mut priv_attrs: [CK_ATTRIBUTE; 0] = [];
            let mech = CK_MECHANISM { mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, pParameter: ptr::null(), ulParameterLen: 0 };
            let mut h_pub: CK_OBJECT_HANDLE = 0;
            let mut h_priv: CK_OBJECT_HANDLE = 0;
            assert_eq!(C_GenerateKeyPair(h_session, &mech, pub_attrs.as_mut_ptr(), 1, priv_attrs.as_mut_ptr(), 0, &mut h_pub, &mut h_priv), CKR_OK);
            (h_pub, h_priv)
        };
        let (ec_pub, ec_priv) = {
            let oid = [0x06u8, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
            let mut pub_attrs = [CK_ATTRIBUTE { r#type: CKA_EC_PARAMS, pValue: oid.as_ptr() as *mut c_void, ulValueLen: oid.len() as CK_ULONG }];
            let mut priv_attrs: [CK_ATTRIBUTE; 0] = [];
            let mech = CK_MECHANISM { mechanism: CKM_EC_KEY_PAIR_GEN, pParameter: ptr::null(), ulParameterLen: 0 };
            let mut h_pub: CK_OBJECT_HANDLE = 0;
            let mut h_priv: CK_OBJECT_HANDLE = 0;
            assert_eq!(C_GenerateKeyPair(h_session, &mech, pub_attrs.as_mut_ptr(), 1, priv_attrs.as_mut_ptr(), 0, &mut h_pub, &mut h_priv), CKR_OK);
            (h_pub, h_priv)
        };

        // Step 4: countAllObjects() — find all objects with no class filter
        // (C_FindObjectsInit(hSession, NULL, 0) or with CKA_TOKEN=TRUE)
        // Justification:
        // 1. Diagnostics: Verifies the token is responsive and readable before targeted searches.
        // 2. Capacity: Identifies 'ghost' or non-key objects (Certificates, Data) taking up HSM space.
        // 3. Integrity: Used to cross-reference (Total == Priv + Pub + Secret) to ensure no orphaned objects exist.
        // 4. Optimization: If Total is 0, we can skip specific key searches entirely.
        // Syntax: Using an empty template ([]) triggers a "vacuous truth" match for all objects.
        {
            assert_eq!(C_FindObjectsInit(h_session, ptr::null_mut(), 0), CKR_OK);
            let mut handles = vec![0u64; 64];
            let mut count: CK_ULONG = 0;
            let mut total: usize = 0;
            loop {
                assert_eq!(C_FindObjects(h_session, handles.as_mut_ptr(), 64, &mut count), CKR_OK);
                if count == 0 { break; }
                total += count as usize;
            }
            assert_eq!(C_FindObjectsFinal(h_session), CKR_OK);
            assert!(total >= 5, "must find at least the 5 generated objects, found {total}");
        }

        // Step 5: countPrivateKeys() — filter by CKO_PRIVATE_KEY
        // (attrib[] = { CKA_CLASS=CKO_PRIVATE_KEY, CKA_KEY_TYPE=CKK_EC }; C_FindObjectsInit → loop C_FindObjects → C_FindObjectsFinal)
        {
            let class_priv = CKO_PRIVATE_KEY.to_le_bytes();
            let mut tmpl = [CK_ATTRIBUTE {
                r#type: CKA_CLASS,
                pValue: class_priv.as_ptr() as *mut c_void,
                ulValueLen: 8,
            }];
            assert_eq!(C_FindObjectsInit(h_session, tmpl.as_mut_ptr(), 1), CKR_OK);
            let mut handles = vec![0u64; 20];
            let mut count: CK_ULONG = 0;
            assert_eq!(C_FindObjects(h_session, handles.as_mut_ptr(), 20, &mut count), CKR_OK);
            assert_eq!(C_FindObjectsFinal(h_session), CKR_OK);
            let found = &handles[..count as usize];
            assert!(found.contains(&rsa_priv), "RSA private key must be found");
            assert!(found.contains(&ec_priv),  "EC private key must be found");
        }

        // Step 6: countPublicKeys() — filter by CKO_PUBLIC_KEY
        // (attrib[] = { CKA_CLASS=CKO_PUBLIC_KEY, CKA_KEY_TYPE=... })
        {
            let class_pub = CKO_PUBLIC_KEY.to_le_bytes();
            let mut tmpl = [CK_ATTRIBUTE {
                r#type: CKA_CLASS,
                pValue: class_pub.as_ptr() as *mut c_void,
                ulValueLen: 8,
            }];
            assert_eq!(C_FindObjectsInit(h_session, tmpl.as_mut_ptr(), 1), CKR_OK);
            let mut handles = vec![0u64; 20];
            let mut count: CK_ULONG = 0;
            assert_eq!(C_FindObjects(h_session, handles.as_mut_ptr(), 20, &mut count), CKR_OK);
            assert_eq!(C_FindObjectsFinal(h_session), CKR_OK);
            let found = &handles[..count as usize];
            assert!(found.contains(&rsa_pub), "RSA public key must be found");
            assert!(found.contains(&ec_pub),  "EC public key must be found");
        }

        // Step 7: countSecretKeys() — filter by CKO_SECRET_KEY
        {
            let class_sec = CKO_SECRET_KEY.to_le_bytes();
            let mut tmpl = [CK_ATTRIBUTE {
                r#type: CKA_CLASS,
                pValue: class_sec.as_ptr() as *mut c_void,
                ulValueLen: 8,
            }];
            assert_eq!(C_FindObjectsInit(h_session, tmpl.as_mut_ptr(), 1), CKR_OK);
            let mut handles = vec![0u64; 20];
            let mut count: CK_ULONG = 0;
            assert_eq!(C_FindObjects(h_session, handles.as_mut_ptr(), 20, &mut count), CKR_OK);
            assert_eq!(C_FindObjectsFinal(h_session), CKR_OK);
            let found = &handles[..count as usize];
            assert!(found.contains(&aes_key), "AES secret key must be found");
        }

        // Step 8: Destroy the AES key and verify it is gone
        // (C_DestroyObject — standard cleanup)
        assert_eq!(C_DestroyObject(h_session, aes_key), CKR_OK);
        assert_eq!(
            C_DestroyObject(h_session, aes_key),
            CKR_OBJECT_HANDLE_INVALID,
            "double-destroy must return CKR_OBJECT_HANDLE_INVALID",
        );

        // Silence unused handle warnings
        let _ = (rsa_pub, rsa_priv, ec_pub, ec_priv);

        // Step 9: Logout and close session
        // (disconnectFromSlot() → C_Logout + C_CloseSession + C_Finalize)
        disconnect_from_slot(h_session);
    }
}
