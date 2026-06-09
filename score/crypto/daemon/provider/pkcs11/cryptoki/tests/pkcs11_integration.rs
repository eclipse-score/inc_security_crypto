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

//! Integration tests for the PKCS#11 C API layer.
//!
//! Exercises the full C_* call sequence through the function-list dispatch:
//!   C_Initialize → C_OpenSession → C_Generate* → C_EncryptInit+C_Encrypt
//!   → C_DecryptInit+C_Decrypt → C_CloseSession → C_Finalize

mod common;

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use std::ffi::c_void;
use std::ptr;

// ── Test fixture ──────────────────────────────────────────────────────────

/// Open a read-write session on slot 0.
unsafe fn open_session() -> CK_SESSION_HANDLE {
    common::open_session(common::fn_list())
}

// Shared process-level init guard (tests run in the same process).
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

// ── Library info ──────────────────────────────────────────────────────────

#[test]
fn test_get_info() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mut info: CK_INFO = std::mem::zeroed();
        assert_eq!(p11!(fl, C_GetInfo, &mut info), CKR_OK);
        assert_eq!(info.cryptokiVersion.major, 3);
        assert_eq!(info.cryptokiVersion.minor, 0);
    }
}

#[test]
fn test_get_slot_list() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mut count: CK_ULONG = 0;
        assert_eq!(p11!(fl, C_GetSlotList, CK_TRUE, ptr::null_mut(), &mut count), CKR_OK);
        assert_eq!(count, 1);
        let mut slot: CK_SLOT_ID = 0;
        assert_eq!(p11!(fl, C_GetSlotList, CK_TRUE, &mut slot, &mut count), CKR_OK);
        assert_eq!(slot, 0);
    }
}

#[test]
fn test_get_mechanism_list() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mut count: CK_ULONG = 0;
        assert_eq!(p11!(fl, C_GetMechanismList, 0, ptr::null_mut(), &mut count), CKR_OK);
        assert!(count >= 10);
        let mut list = vec![0u64; count as usize];
        assert_eq!(p11!(fl, C_GetMechanismList, 0, list.as_mut_ptr(), &mut count), CKR_OK);
        assert!(list.contains(&CKM_AES_KEY_GEN));
        assert!(list.contains(&CKM_RSA_PKCS_KEY_PAIR_GEN));
        assert!(list.contains(&CKM_EC_KEY_PAIR_GEN));
        assert!(list.contains(&CKM_AES_GCM));
        assert!(list.contains(&CKM_SHA256));
    }
}

// ── Session ────────────────────────────────────────────────────────────────

#[test]
fn test_open_close_session() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        assert_ne!(h, CK_INVALID_HANDLE);
        assert_eq!(p11!(fl, C_CloseSession, h), CKR_OK);
        // Closing again → invalid handle
        assert_eq!(p11!(fl, C_CloseSession, h), CKR_SESSION_HANDLE_INVALID);
    }
}

#[test]
fn test_get_session_info() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let mut info: CK_SESSION_INFO = std::mem::zeroed();
        assert_eq!(p11!(fl, C_GetSessionInfo, h, &mut info), CKR_OK);
        assert_eq!(info.slotID, 0);
        assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);
        let _ = p11!(fl, C_CloseSession, h);
    }
}

// ── AES key generation + encrypt/decrypt ──────────────────────────────────

unsafe fn generate_aes_key(h: CK_SESSION_HANDLE, key_len_bytes: u64) -> CK_OBJECT_HANDLE {
    let fl = common::fn_list();
    let value_len = key_len_bytes.to_le_bytes();
    let mut attrs = [CK_ATTRIBUTE {
        r#type:     CKA_VALUE_LEN,
        pValue:     value_len.as_ptr() as *mut c_void,
        ulValueLen: 8,
    }];
    let mech = CK_MECHANISM { mechanism: CKM_AES_KEY_GEN, pParameter: ptr::null(), ulParameterLen: 0 };
    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKey, h, &mech, attrs.as_mut_ptr(), 1, &mut key_handle);
    assert_eq!(rv, CKR_OK, "C_GenerateKey failed: {rv:#010x}");
    assert_ne!(key_handle, CK_INVALID_HANDLE);
    key_handle
}

#[test]
fn test_aes_cbc_roundtrip_128() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let key = generate_aes_key(h, 16);

        let iv = [0x42u8; 16];
        let mech = CK_MECHANISM {
            mechanism:      CKM_AES_CBC_PAD,
            pParameter:     iv.as_ptr() as *const c_void,
            ulParameterLen: 16,
        };
        let plaintext = b"PKCS11 AES-CBC test message";

        // Encrypt
        assert_eq!(p11!(fl, C_EncryptInit, h, &mech, key), CKR_OK);
        let mut ct_len: CK_ULONG = 64;
        let mut ct = vec![0u8; 64];
        let rv = p11!(fl, C_Encrypt, h, plaintext.as_ptr(), plaintext.len() as CK_ULONG,
                       ct.as_mut_ptr(), &mut ct_len);
        assert_eq!(rv, CKR_OK);
        ct.truncate(ct_len as usize);

        // Decrypt
        assert_eq!(p11!(fl, C_DecryptInit, h, &mech, key), CKR_OK);
        let mut pt_len: CK_ULONG = 64;
        let mut pt = vec![0u8; 64];
        let rv = p11!(fl, C_Decrypt, h, ct.as_ptr(), ct_len,
                       pt.as_mut_ptr(), &mut pt_len);
        assert_eq!(rv, CKR_OK);
        pt.truncate(pt_len as usize);
        assert_eq!(pt, plaintext);

        let _ = p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn test_aes_gcm_roundtrip() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let key = generate_aes_key(h, 32);

        let iv  = [0xAAu8; 12];
        let aad = b"additional authenticated data";

        #[repr(C)]
        #[allow(non_snake_case)]
        struct GcmParams {
            pIv: *const u8, ulIvLen: u64, ulIvBits: u64,
            pAAD: *const u8, ulAADLen: u64, ulTagBits: u64,
        }
        let params = GcmParams {
            pIv: iv.as_ptr(), ulIvLen: 12, ulIvBits: 96,
            pAAD: aad.as_ptr(), ulAADLen: aad.len() as u64, ulTagBits: 128,
        };
        let mech = CK_MECHANISM {
            mechanism:      CKM_AES_GCM,
            pParameter:     &params as *const _ as *const c_void,
            ulParameterLen: std::mem::size_of::<GcmParams>() as CK_ULONG,
        };
        let plaintext = b"GCM authenticated encryption";

        // Encrypt (output = ciphertext || 16-byte tag)
        assert_eq!(p11!(fl, C_EncryptInit, h, &mech, key), CKR_OK);
        let mut ct_len: CK_ULONG = 64;
        let mut ct = vec![0u8; 64];
        assert_eq!(p11!(fl, C_Encrypt, h, plaintext.as_ptr(), plaintext.len() as CK_ULONG,
                          ct.as_mut_ptr(), &mut ct_len), CKR_OK);
        ct.truncate(ct_len as usize);
        // ct = ciphertext + tag (last 16 bytes)
        assert_eq!(ct.len(), plaintext.len() + 16);

        // Decrypt
        assert_eq!(p11!(fl, C_DecryptInit, h, &mech, key), CKR_OK);
        let mut pt_len: CK_ULONG = 64;
        let mut pt = vec![0u8; 64];
        assert_eq!(p11!(fl, C_Decrypt, h, ct.as_ptr(), ct.len() as CK_ULONG,
                         pt.as_mut_ptr(), &mut pt_len), CKR_OK);
        pt.truncate(pt_len as usize);
        assert_eq!(pt, plaintext);

        let _ = p11!(fl, C_CloseSession, h);
    }
}

// ── RSA key pair generation + sign/verify ────────────────────────────────

unsafe fn generate_rsa_key_pair(h: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let fl = common::fn_list();
    let bits: u64 = 2048u64;
    let bits_bytes = bits.to_le_bytes();
    let mut pub_attrs = [CK_ATTRIBUTE {
        r#type:     CKA_MODULUS_BITS,
        pValue:     bits_bytes.as_ptr() as *mut c_void,
        ulValueLen: 8,
    }];
    let mut priv_attrs: [CK_ATTRIBUTE; 0] = [];
    let mech = CK_MECHANISM { mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, pParameter: ptr::null(), ulParameterLen: 0 };
    let mut pub_key: CK_OBJECT_HANDLE  = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKeyPair,
        h, &mech,
        pub_attrs.as_mut_ptr(), 1,
        priv_attrs.as_mut_ptr(), 0,
        &mut pub_key, &mut priv_key,
    );
    assert_eq!(rv, CKR_OK, "C_GenerateKeyPair (RSA) failed: {rv:#010x}");
    (pub_key, priv_key)
}

#[test]
fn test_rsa_sign_verify() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let (pub_key, priv_key) = generate_rsa_key_pair(h);
        let message = b"C_Sign(CKM_SHA256_RSA_PKCS) via PKCS#11 C API";
        let mech = CK_MECHANISM { mechanism: CKM_SHA256_RSA_PKCS, pParameter: ptr::null(), ulParameterLen: 0 };

        // Sign
        assert_eq!(p11!(fl, C_SignInit, h, &mech, priv_key), CKR_OK);
        let mut sig_len: CK_ULONG = 512;
        let mut sig = vec![0u8; 512];
        let rv = p11!(fl, C_Sign, h, message.as_ptr(), message.len() as CK_ULONG,
                        sig.as_mut_ptr(), &mut sig_len);
        assert_eq!(rv, CKR_OK);
        sig.truncate(sig_len as usize);
        assert_eq!(sig_len, 256); // 2048-bit key

        // Verify with correct message
        assert_eq!(p11!(fl, C_VerifyInit, h, &mech, pub_key), CKR_OK);
        assert_eq!(p11!(fl, C_Verify, h, message.as_ptr(), message.len() as CK_ULONG,
                         sig.as_ptr(), sig_len), CKR_OK);

        // Verify with tampered message
        let bad = b"tampered";
        assert_eq!(p11!(fl, C_VerifyInit, h, &mech, pub_key), CKR_OK);
        assert_eq!(p11!(fl, C_Verify, h, bad.as_ptr(), bad.len() as CK_ULONG,
                         sig.as_ptr(), sig_len), CKR_SIGNATURE_INVALID);

        let _ = p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn test_rsa_pkcs1_encrypt_decrypt() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let (pub_key, priv_key) = generate_rsa_key_pair(h);
        let mech = CK_MECHANISM { mechanism: CKM_RSA_PKCS, pParameter: ptr::null(), ulParameterLen: 0 };
        let plaintext = b"RSA PKCS1 via PKCS#11";

        assert_eq!(p11!(fl, C_EncryptInit, h, &mech, pub_key), CKR_OK);
        let mut ct_len: CK_ULONG = 512;
        let mut ct = vec![0u8; 512];
        assert_eq!(p11!(fl, C_Encrypt, h, plaintext.as_ptr(), plaintext.len() as CK_ULONG,
                          ct.as_mut_ptr(), &mut ct_len), CKR_OK);
        ct.truncate(ct_len as usize);

        assert_eq!(p11!(fl, C_DecryptInit, h, &mech, priv_key), CKR_OK);
        let mut pt_len: CK_ULONG = 512;
        let mut pt = vec![0u8; 512];
        assert_eq!(p11!(fl, C_Decrypt, h, ct.as_ptr(), ct.len() as CK_ULONG,
                         pt.as_mut_ptr(), &mut pt_len), CKR_OK);
        pt.truncate(pt_len as usize);
        assert_eq!(pt, plaintext);

        let _ = p11!(fl, C_CloseSession, h);
    }
}

// ── EC key pair + ECDSA ───────────────────────────────────────────────────

unsafe fn generate_ec_key_pair(h: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let fl = common::fn_list();
    // P-256 OID
    let p256_oid = [0x06u8, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let mut pub_attrs = [CK_ATTRIBUTE {
        r#type:     CKA_EC_PARAMS,
        pValue:     p256_oid.as_ptr() as *mut c_void,
        ulValueLen: p256_oid.len() as CK_ULONG,
    }];
    let mut priv_attrs: [CK_ATTRIBUTE; 0] = [];
    let mech = CK_MECHANISM { mechanism: CKM_EC_KEY_PAIR_GEN, pParameter: ptr::null(), ulParameterLen: 0 };
    let mut pub_key: CK_OBJECT_HANDLE  = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKeyPair, h, &mech,
        pub_attrs.as_mut_ptr(), 1,
        priv_attrs.as_mut_ptr(), 0,
        &mut pub_key, &mut priv_key);
    assert_eq!(rv, CKR_OK, "C_GenerateKeyPair (EC) failed: {rv:#010x}");
    (pub_key, priv_key)
}

#[test]
fn test_ecdsa_sign_verify() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let (pub_key, priv_key) = generate_ec_key_pair(h);
        let message = b"C_Sign(CKM_ECDSA) over P-256";
        let mech = CK_MECHANISM { mechanism: CKM_ECDSA, pParameter: ptr::null(), ulParameterLen: 0 };

        assert_eq!(p11!(fl, C_SignInit, h, &mech, priv_key), CKR_OK);
        let mut sig_len: CK_ULONG = 128;
        let mut sig = vec![0u8; 128];
        assert_eq!(p11!(fl, C_Sign, h, message.as_ptr(), message.len() as CK_ULONG,
                          sig.as_mut_ptr(), &mut sig_len), CKR_OK);
        sig.truncate(sig_len as usize);

        assert_eq!(p11!(fl, C_VerifyInit, h, &mech, pub_key), CKR_OK);
        assert_eq!(p11!(fl, C_Verify, h, message.as_ptr(), message.len() as CK_ULONG,
                         sig.as_ptr(), sig_len), CKR_OK);
        let _ = p11!(fl, C_CloseSession, h);
    }
}

// ── Digest (multi-part + one-shot) ────────────────────────────────────────

#[test]
fn test_digest_sha256_one_shot() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let mech = CK_MECHANISM { mechanism: CKM_SHA256, pParameter: ptr::null(), ulParameterLen: 0 };
        let data = b"hello world";

        assert_eq!(p11!(fl, C_DigestInit, h, &mech), CKR_OK);
        let mut len: CK_ULONG = 64;
        let mut digest = vec![0u8; 64];
        assert_eq!(p11!(fl, C_Digest, h, data.as_ptr(), data.len() as CK_ULONG,
                        digest.as_mut_ptr(), &mut len), CKR_OK);
        assert_eq!(len, 32);
        assert_ne!(digest[..32], [0u8; 32]);
        let _ = p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn test_digest_sha256_multi_part() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let mech = CK_MECHANISM { mechanism: CKM_SHA256, pParameter: ptr::null(), ulParameterLen: 0 };

        // C_DigestUpdate × 2 → C_DigestFinal
        assert_eq!(p11!(fl, C_DigestInit, h, &mech), CKR_OK);
        assert_eq!(p11!(fl, C_DigestUpdate, h, b"hello ".as_ptr(), 6), CKR_OK);
        assert_eq!(p11!(fl, C_DigestUpdate, h, b"world".as_ptr(), 5), CKR_OK);
        let mut len: CK_ULONG = 64;
        let mut digest_multi = vec![0u8; 64];
        assert_eq!(p11!(fl, C_DigestFinal, h, digest_multi.as_mut_ptr(), &mut len), CKR_OK);
        digest_multi.truncate(32);

        // One-shot reference
        assert_eq!(p11!(fl, C_DigestInit, h, &mech), CKR_OK);
        let mut len2: CK_ULONG = 64;
        let mut digest_one = vec![0u8; 64];
        assert_eq!(p11!(fl, C_Digest, h, b"hello world".as_ptr(), 11, digest_one.as_mut_ptr(), &mut len2), CKR_OK);
        digest_one.truncate(32);

        assert_eq!(digest_multi, digest_one);
        let _ = p11!(fl, C_CloseSession, h);
    }
}

// ── Random ────────────────────────────────────────────────────────────────

#[test]
fn test_generate_random() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let mut buf = vec![0u8; 32];
        assert_eq!(p11!(fl, C_GenerateRandom, h, buf.as_mut_ptr(), 32), CKR_OK);
        assert_ne!(buf, vec![0u8; 32]);
        let _ = p11!(fl, C_CloseSession, h);
    }
}

// ── Object management ─────────────────────────────────────────────────────

#[test]
fn test_find_objects_by_class() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        // Generate two different key types
        let _aes = generate_aes_key(h, 16);
        let (_pub, _priv) = generate_rsa_key_pair(h);

        // Find all secret keys
        let class_aes: u64 = CKO_SECRET_KEY;
        let class_bytes = class_aes.to_le_bytes();
        let mut tmpl = [CK_ATTRIBUTE {
            r#type:     CKA_CLASS,
            pValue:     class_bytes.as_ptr() as *mut c_void,
            ulValueLen: 8,
        }];
        assert_eq!(p11!(fl, C_FindObjectsInit, h, tmpl.as_mut_ptr(), 1), CKR_OK);
        let mut handles = vec![0u64; 10];
        let mut count: CK_ULONG = 0;
        assert_eq!(p11!(fl, C_FindObjects, h, handles.as_mut_ptr(), 10, &mut count), CKR_OK);
        assert!(count >= 1); // at least the AES key we just created
        assert_eq!(p11!(fl, C_FindObjectsFinal, h), CKR_OK);

        let _ = p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn test_get_attribute_value_aes_key_len() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let key = generate_aes_key(h, 32);

        let mut val: u64 = 0;
        let mut attr = CK_ATTRIBUTE {
            r#type:     CKA_VALUE_LEN,
            pValue:     &mut val as *mut u64 as *mut c_void,
            ulValueLen: 8,
        };
        assert_eq!(p11!(fl, C_GetAttributeValue, h, key, &mut attr, 1), CKR_OK);
        assert_eq!(val, 32u64);

        let _ = p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn test_destroy_object() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let key = generate_aes_key(h, 16);
        assert_eq!(p11!(fl, C_DestroyObject, h, key), CKR_OK);
        // Second destroy → object already gone
        assert_eq!(p11!(fl, C_DestroyObject, h, key), CKR_OBJECT_HANDLE_INVALID);
        let _ = p11!(fl, C_CloseSession, h);
    }
}

// ── Attribute engine fallback ─────────────────────────────────────────────

/// `CKA_VALUE` on an RSA private key must return `CKR_ATTRIBUTE_SENSITIVE`.
/// This exercises the engine fallback path (not in HashMap) with a sensitive attr.
#[test]
fn test_get_attribute_rsa_private_value_is_sensitive() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let (_pub_key, priv_key) = generate_rsa_key_pair(h);

        let mut buf = vec![0u8; 512];
        let mut attr = CK_ATTRIBUTE {
            r#type:     CKA_VALUE,
            pValue:     buf.as_mut_ptr() as *mut c_void,
            ulValueLen: buf.len() as CK_ULONG,
        };
        // CKA_VALUE is not in the HashMap for RSA private keys;
        // engine fallback returns AttributeSensitive → CKR_ATTRIBUTE_SENSITIVE.
        assert_eq!(
            p11!(fl, C_GetAttributeValue, h, priv_key, &mut attr, 1),
            CKR_ATTRIBUTE_SENSITIVE,
            "CKA_VALUE on RSA private key must be sensitive",
        );

        let _ = p11!(fl, C_CloseSession, h);
    }
}

/// `CKA_EC_POINT` on an EC private key is not pre-cached in the HashMap
/// (only inserted for the public key at generation time).
/// The engine fallback must derive and return it from the private DER.
#[test]
fn test_get_attribute_ec_point_from_private_key() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let (_pub_key, priv_key) = generate_ec_key_pair(h);

        // Step 1: query length (pValue = NULL).
        let mut attr = CK_ATTRIBUTE {
            r#type:     CKA_EC_POINT,
            pValue:     ptr::null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            p11!(fl, C_GetAttributeValue, h, priv_key, &mut attr, 1),
            CKR_OK,
            "length query for CKA_EC_POINT on EC private key must succeed",
        );
        let point_len = attr.ulValueLen as usize;
        assert!(point_len > 0, "EC point length must be non-zero");

        // Step 2: retrieve the value.
        let mut buf = vec![0u8; point_len];
        attr.pValue     = buf.as_mut_ptr() as *mut c_void;
        attr.ulValueLen = point_len as CK_ULONG;
        assert_eq!(
            p11!(fl, C_GetAttributeValue, h, priv_key, &mut attr, 1),
            CKR_OK,
            "CKA_EC_POINT must be retrievable from EC private key via engine",
        );
        // P-256 uncompressed point is 65 bytes, DER-wrapped adds a few more.
        assert!(buf.len() >= 65, "EC point must be at least 65 bytes");

        let _ = p11!(fl, C_CloseSession, h);
    }
}

/// An unrecognised attribute type must return `CKR_ATTRIBUTE_TYPE_INVALID`
/// (set on the attribute and returned as the function result).
#[test]
fn test_get_attribute_unknown_type_returns_invalid() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h   = open_session();
        let key = generate_aes_key(h, 16);

        let mut attr = CK_ATTRIBUTE {
            r#type:     0xDEADBEEF,   // not a valid CKA_* constant
            pValue:     ptr::null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            p11!(fl, C_GetAttributeValue, h, key, &mut attr, 1),
            CKR_ATTRIBUTE_TYPE_INVALID,
        );
        assert_eq!(attr.ulValueLen, CK_UNAVAILABLE_INFORMATION);

        let _ = p11!(fl, C_CloseSession, h);
    }
}

// ── Error cases ────────────────────────────────────────────────────────────

#[test]
fn test_invalid_session_handle() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mech = CK_MECHANISM { mechanism: CKM_SHA256, pParameter: ptr::null(), ulParameterLen: 0 };
        assert_eq!(p11!(fl, C_DigestInit, 9999999, &mech), CKR_SESSION_HANDLE_INVALID);
    }
}

#[test]
fn test_operation_active_error() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let mech = CK_MECHANISM { mechanism: CKM_SHA256, pParameter: ptr::null(), ulParameterLen: 0 };
        assert_eq!(p11!(fl, C_DigestInit, h, &mech), CKR_OK);
        // Second init without finishing first → OPERATION_ACTIVE
        assert_eq!(p11!(fl, C_DigestInit, h, &mech), CKR_OPERATION_ACTIVE);
        // Finish to clean up
        let mut len: CK_ULONG = 64;
        let mut d = vec![0u8; 64];
        let _ = p11!(fl, C_DigestFinal, h, d.as_mut_ptr(), &mut len);
        let _ = p11!(fl, C_CloseSession, h);
    }
}

#[test]
fn test_double_initialize() {
    // C_Initialize already called by INIT; second call should return ALREADY_INITIALIZED.
    init();
    unsafe {
        let fl = common::fn_list();
        let rv = p11!(fl, C_Initialize, ptr::null_mut());
        assert_eq!(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED);
    }
}
