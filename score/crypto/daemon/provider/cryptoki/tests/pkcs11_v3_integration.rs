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

//! Integration tests for PKCS#11 v3.0 features.
//!
//! Covers: EdDSA, ChaCha20-Poly1305, SHA-3/SHA-384/SHA-512 digests,
//! interface discovery, token management, C_SessionCancel, C_LoginUser.

mod common;

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use serial_test::serial;
use std::ffi::c_void;
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

unsafe fn open_session() -> CK_SESSION_HANDLE {
    let fl = common::fn_list();
    let mut h: CK_SESSION_HANDLE = 0;
    let rv = p11!(fl, C_OpenSession,
        0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
        ptr::null_mut(), None, &mut h,
    );
    assert_eq!(rv, CKR_OK, "C_OpenSession failed: {rv:#010x}");
    h
}

unsafe fn open_logged_in_session() -> CK_SESSION_HANDLE {
    let fl = common::fn_list();
    let h = open_session();
    let pin = b"1234";
    let rv = p11!(fl, C_Login, h, CKU_USER, pin.as_ptr(), 4);
    assert!(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN, "C_Login failed: {rv:#x}");
    h
}

// -- EdDSA (Ed25519) ----------------------------------------------------------

unsafe fn generate_ed_key_pair(h: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let fl = common::fn_list();
    // Ed25519 OID: 06 03 2b 65 70
    let ed25519_oid = [0x06u8, 0x03, 0x2b, 0x65, 0x70];
    let mut pub_attrs = [CK_ATTRIBUTE {
        r#type:     CKA_EC_PARAMS,
        pValue:     ed25519_oid.as_ptr() as *mut c_void,
        ulValueLen: ed25519_oid.len() as CK_ULONG,
    }];
    let mut priv_attrs: [CK_ATTRIBUTE; 0] = [];
    let mech = CK_MECHANISM {
        mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN,
        pParameter: ptr::null(),
        ulParameterLen: 0,
    };
    let mut pub_key: CK_OBJECT_HANDLE = 0;
    let mut priv_key: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKeyPair,
        h, &mech,
        pub_attrs.as_mut_ptr(), 1,
        priv_attrs.as_mut_ptr(), 0,
        &mut pub_key, &mut priv_key,
    );
    assert_eq!(rv, CKR_OK, "C_GenerateKeyPair (EdDSA) failed: {rv:#010x}");
    (pub_key, priv_key)
}

#[test]
#[serial]
fn test_eddsa_sign_verify() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let (pub_key, priv_key) = generate_ed_key_pair(h);
        let message = b"EdDSA sign/verify via PKCS#11 v3.0";
        let mech = CK_MECHANISM { mechanism: CKM_EDDSA, pParameter: ptr::null(), ulParameterLen: 0 };

        // Sign
        assert_eq!(p11!(fl, C_SignInit, h, &mech, priv_key), CKR_OK);
        let mut sig_len: CK_ULONG = 128;
        let mut sig = vec![0u8; 128];
        let rv = p11!(fl, C_Sign, h, message.as_ptr(), message.len() as CK_ULONG,
                        sig.as_mut_ptr(), &mut sig_len);
        assert_eq!(rv, CKR_OK);
        sig.truncate(sig_len as usize);
        assert_eq!(sig_len, 64, "Ed25519 signature must be 64 bytes");

        // Verify
        assert_eq!(p11!(fl, C_VerifyInit, h, &mech, pub_key), CKR_OK);
        assert_eq!(p11!(fl, C_Verify, h, message.as_ptr(), message.len() as CK_ULONG,
                             sig.as_ptr(), sig_len), CKR_OK);

        // Tampered signature must fail
        sig[0] ^= 0xFF;
        assert_eq!(p11!(fl, C_VerifyInit, h, &mech, pub_key), CKR_OK);
        assert_eq!(p11!(fl, C_Verify, h, message.as_ptr(), message.len() as CK_ULONG,
                             sig.as_ptr(), sig_len), CKR_SIGNATURE_INVALID);

        let _ = p11!(fl, C_CloseSession, h);
    }
}

// -- ChaCha20-Poly1305 --------------------------------------------------------

unsafe fn generate_chacha20_key(h: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let fl = common::fn_list();
    let mech = CK_MECHANISM { mechanism: CKM_CHACHA20_KEY_GEN, pParameter: ptr::null(), ulParameterLen: 0 };
    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKey, h, &mech, ptr::null(), 0, &mut key_handle);
    assert_eq!(rv, CKR_OK, "C_GenerateKey (ChaCha20) failed: {rv:#010x}");
    key_handle
}

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

#[test]
#[serial]
fn test_chacha20_poly1305_roundtrip() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let key = generate_chacha20_key(h);

        let nonce = [0x42u8; 12];
        let aad = b"additional data";
        let params = GcmParams {
            pIv: nonce.as_ptr(), ulIvLen: 12, ulIvBits: 96,
            pAAD: aad.as_ptr(), ulAADLen: aad.len() as u64, ulTagBits: 128,
        };
        let mech = CK_MECHANISM {
            mechanism: CKM_CHACHA20_POLY1305,
            pParameter: &params as *const _ as *const c_void,
            ulParameterLen: std::mem::size_of::<GcmParams>() as CK_ULONG,
        };
        let plaintext = b"ChaCha20-Poly1305 AEAD test";

        // Encrypt
        assert_eq!(p11!(fl, C_EncryptInit, h, &mech, key), CKR_OK);
        let mut ct_len: CK_ULONG = 128;
        let mut ct = vec![0u8; 128];
        assert_eq!(p11!(fl, C_Encrypt, h, plaintext.as_ptr(), plaintext.len() as CK_ULONG,
                              ct.as_mut_ptr(), &mut ct_len), CKR_OK);
        ct.truncate(ct_len as usize);
        assert_eq!(ct.len(), plaintext.len() + 16, "output = ciphertext + 16-byte tag");

        // Decrypt
        assert_eq!(p11!(fl, C_DecryptInit, h, &mech, key), CKR_OK);
        let mut pt_len: CK_ULONG = 128;
        let mut pt = vec![0u8; 128];
        assert_eq!(p11!(fl, C_Decrypt, h, ct.as_ptr(), ct.len() as CK_ULONG,
                             pt.as_mut_ptr(), &mut pt_len), CKR_OK);
        pt.truncate(pt_len as usize);
        assert_eq!(pt, plaintext);

        // Tamper test -- corrupt ciphertext
        ct[0] ^= 0xFF;
        assert_eq!(p11!(fl, C_DecryptInit, h, &mech, key), CKR_OK);
        let mut bad_len: CK_ULONG = 128;
        let mut bad = vec![0u8; 128];
        let rv = p11!(fl, C_Decrypt, h, ct.as_ptr(), ct.len() as CK_ULONG,
                           bad.as_mut_ptr(), &mut bad_len);
        assert_ne!(rv, CKR_OK, "tampered ChaCha20-Poly1305 ciphertext must not decrypt");

        let _ = p11!(fl, C_CloseSession, h);
    }
}

// -- SHA-3 and SHA-384/512 digests --------------------------------------------

#[test]
#[serial]
fn test_digest_sha384() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let mech = CK_MECHANISM { mechanism: CKM_SHA384, pParameter: ptr::null(), ulParameterLen: 0 };
        let data = b"hello world";

        assert_eq!(p11!(fl, C_DigestInit, h, &mech), CKR_OK);
        let mut len: CK_ULONG = 64;
        let mut digest = vec![0u8; 64];
        assert_eq!(p11!(fl, C_Digest, h, data.as_ptr(), data.len() as CK_ULONG,
                            digest.as_mut_ptr(), &mut len), CKR_OK);
        assert_eq!(len, 48, "SHA-384 digest must be 48 bytes");
        let _ = p11!(fl, C_CloseSession, h);
    }
}

#[test]
#[serial]
fn test_digest_sha512() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let mech = CK_MECHANISM { mechanism: CKM_SHA512, pParameter: ptr::null(), ulParameterLen: 0 };
        let data = b"hello world";

        assert_eq!(p11!(fl, C_DigestInit, h, &mech), CKR_OK);
        let mut len: CK_ULONG = 128;
        let mut digest = vec![0u8; 128];
        assert_eq!(p11!(fl, C_Digest, h, data.as_ptr(), data.len() as CK_ULONG,
                            digest.as_mut_ptr(), &mut len), CKR_OK);
        assert_eq!(len, 64, "SHA-512 digest must be 64 bytes");
        let _ = p11!(fl, C_CloseSession, h);
    }
}

#[test]
#[serial]
fn test_digest_sha3_256() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let mech = CK_MECHANISM { mechanism: CKM_SHA3_256, pParameter: ptr::null(), ulParameterLen: 0 };
        let data = b"hello world";

        assert_eq!(p11!(fl, C_DigestInit, h, &mech), CKR_OK);
        let mut len: CK_ULONG = 64;
        let mut digest = vec![0u8; 64];
        assert_eq!(p11!(fl, C_Digest, h, data.as_ptr(), data.len() as CK_ULONG,
                            digest.as_mut_ptr(), &mut len), CKR_OK);
        assert_eq!(len, 32, "SHA3-256 digest must be 32 bytes");
        let _ = p11!(fl, C_CloseSession, h);
    }
}

#[test]
#[serial]
fn test_digest_sha3_384() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let mech = CK_MECHANISM { mechanism: CKM_SHA3_384, pParameter: ptr::null(), ulParameterLen: 0 };
        let data = b"hello world";

        assert_eq!(p11!(fl, C_DigestInit, h, &mech), CKR_OK);
        let mut len: CK_ULONG = 64;
        let mut digest = vec![0u8; 64];
        assert_eq!(p11!(fl, C_Digest, h, data.as_ptr(), data.len() as CK_ULONG,
                            digest.as_mut_ptr(), &mut len), CKR_OK);
        assert_eq!(len, 48, "SHA3-384 digest must be 48 bytes");
        let _ = p11!(fl, C_CloseSession, h);
    }
}

#[test]
#[serial]
fn test_digest_sha3_512() {
    init();
    unsafe {
        let fl = common::fn_list();
        let h = open_session();
        let mech = CK_MECHANISM { mechanism: CKM_SHA3_512, pParameter: ptr::null(), ulParameterLen: 0 };
        let data = b"hello world";

        assert_eq!(p11!(fl, C_DigestInit, h, &mech), CKR_OK);
        let mut len: CK_ULONG = 128;
        let mut digest = vec![0u8; 128];
        assert_eq!(p11!(fl, C_Digest, h, data.as_ptr(), data.len() as CK_ULONG,
                            digest.as_mut_ptr(), &mut len), CKR_OK);
        assert_eq!(len, 64, "SHA3-512 digest must be 64 bytes");
        let _ = p11!(fl, C_CloseSession, h);
    }
}

// -- Interface discovery (v3.0) -----------------------------------------------

#[test]
#[serial]
fn test_get_interface_list() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        // Query count
        let mut count: CK_ULONG = 0;
        assert_eq!(p11!(fl3, C_GetInterfaceList, ptr::null_mut(), &mut count), CKR_OK);
        assert!(count >= 1, "must have at least 1 interface");

        // Retrieve
        let mut iface: CK_INTERFACE = std::mem::zeroed();
        assert_eq!(p11!(fl3, C_GetInterfaceList, &mut iface, &mut count), CKR_OK);
        assert!(!iface.pInterfaceName.is_null());
        assert!(!iface.pFunctionList.is_null());
    }
}

#[test]
#[serial]
fn test_get_interface_default() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let mut iface_ptr: *const CK_INTERFACE = ptr::null();
        // NULL name + NULL version -> return default interface
        let rv = p11!(fl3, C_GetInterface,
            ptr::null(), ptr::null_mut(),
            &mut iface_ptr, 0,
        );
        assert_eq!(rv, CKR_OK);
        assert!(!iface_ptr.is_null());
        let iface = &*iface_ptr;
        assert!(!iface.pFunctionList.is_null());
    }
}

// -- Mechanism list includes v3.0 mechanisms ----------------------------------

#[test]
#[serial]
fn test_mechanism_list_v3() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mut count: CK_ULONG = 0;
        assert_eq!(p11!(fl, C_GetMechanismList, 0, ptr::null_mut(), &mut count), CKR_OK);
        let mut list = vec![0u64; count as usize];
        assert_eq!(p11!(fl, C_GetMechanismList, 0, list.as_mut_ptr(), &mut count), CKR_OK);

        assert!(list.contains(&CKM_EC_EDWARDS_KEY_PAIR_GEN), "missing CKM_EC_EDWARDS_KEY_PAIR_GEN");
        assert!(list.contains(&CKM_EDDSA), "missing CKM_EDDSA");
        assert!(list.contains(&CKM_CHACHA20_POLY1305), "missing CKM_CHACHA20_POLY1305");
        assert!(list.contains(&CKM_CHACHA20_KEY_GEN), "missing CKM_CHACHA20_KEY_GEN");
        assert!(list.contains(&CKM_SHA3_256), "missing CKM_SHA3_256");
        assert!(list.contains(&CKM_SHA384), "missing CKM_SHA384");
        assert!(list.contains(&CKM_SHA512), "missing CKM_SHA512");
    }
}

// -- Token management ---------------------------------------------------------

#[test]
#[serial]
fn test_token_info_has_label() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mut info: CK_TOKEN_INFO = std::mem::zeroed();
        assert_eq!(p11!(fl, C_GetTokenInfo, 0, &mut info), CKR_OK);
        // Label should be padded to 32 bytes, not all zeros
        let label = &info.label[..];
        assert!(!label.iter().all(|&b| b == 0), "token label must not be empty");
    }
}

// -- C_SessionCancel ----------------------------------------------------------

#[test]
#[serial]
fn test_session_cancel() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let h = open_session();
        // Start a digest operation
        let mech = CK_MECHANISM { mechanism: CKM_SHA256, pParameter: ptr::null(), ulParameterLen: 0 };
        assert_eq!(p11!(fl3, C_DigestInit, h, &mech), CKR_OK);

        // Cancel it
        assert_eq!(p11!(fl3, C_SessionCancel, h, 0), CKR_OK);

        // Now we should be able to start a new digest (no OPERATION_ACTIVE)
        assert_eq!(p11!(fl3, C_DigestInit, h, &mech), CKR_OK);

        // Clean up
        let mut len: CK_ULONG = 64;
        let mut d = vec![0u8; 64];
        let _ = p11!(fl3, C_Digest, h, b"x".as_ptr(), 1, d.as_mut_ptr(), &mut len);
        let _ = p11!(fl3, C_CloseSession, h);
    }
}

// -- C_LoginUser (CKU_CONTEXT_SPECIFIC) ---------------------------------------

#[test]
#[serial]
fn test_login_user_context_specific() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let h = open_logged_in_session();
        let pin = b"1234";

        // C_LoginUser with CKU_CONTEXT_SPECIFIC should succeed
        // (context-specific login for always-authenticate operations)
        let rv = p11!(fl3, C_LoginUser,
            h, CKU_CONTEXT_SPECIFIC,
            pin.as_ptr(), pin.len() as CK_ULONG,
            ptr::null(), 0,
        );
        assert_eq!(rv, CKR_OK, "C_LoginUser(CKU_CONTEXT_SPECIFIC) failed: {rv:#010x}");

        let _ = p11!(fl3, C_Logout, h);
        let _ = p11!(fl3, C_CloseSession, h);
    }
}

// -- C_InitToken / C_InitPIN / C_SetPIN ---------------------------------------

/// This test is destructive (C_InitToken closes all sessions and clears objects).
/// It must not run in parallel with other tests that use sessions.
/// Run with `--test-threads=1` or isolate via `cargo test --test pkcs11_v3_integration -- --test-threads=1`.
#[test]
#[serial]
fn test_init_token_and_pin_management() {
    init();
    unsafe {
        let fl = common::fn_list();

        // InitToken with SO PIN -- this closes all sessions and clears objects!
        let so_pin = b"so-pin";
        let label = b"TestToken                       "; // 32 bytes padded
        let rv = p11!(fl, C_InitToken, 0, so_pin.as_ptr(), so_pin.len() as CK_ULONG, label.as_ptr());
        assert_eq!(rv, CKR_OK, "C_InitToken failed: {rv:#010x}");

        // Open session, login as SO
        let h = open_session();
        assert_eq!(p11!(fl, C_Login, h, CKU_SO, so_pin.as_ptr(), so_pin.len() as CK_ULONG), CKR_OK);

        // InitPIN -- set user PIN
        let new_user_pin = b"newpin";
        assert_eq!(p11!(fl, C_InitPIN, h, new_user_pin.as_ptr(), new_user_pin.len() as CK_ULONG), CKR_OK);

        // Logout SO
        assert_eq!(p11!(fl, C_Logout, h), CKR_OK);

        // Login with new user PIN
        assert_eq!(p11!(fl, C_Login, h, CKU_USER, new_user_pin.as_ptr(), new_user_pin.len() as CK_ULONG), CKR_OK);

        // SetPIN -- change user PIN back to default for other tests
        let default_pin = b"1234";
        assert_eq!(p11!(fl, C_SetPIN, h,
            new_user_pin.as_ptr(), new_user_pin.len() as CK_ULONG,
            default_pin.as_ptr(), default_pin.len() as CK_ULONG), CKR_OK);

        let _ = p11!(fl, C_Logout, h);
        let _ = p11!(fl, C_CloseSession, h);
    }
}

// -- Cryptoki version is 3.0 --------------------------------------------------

#[test]
#[serial]
fn test_v3_info() {
    init();
    unsafe {
        let fl = common::fn_list();
        let mut info: CK_INFO = std::mem::zeroed();
        assert_eq!(p11!(fl, C_GetInfo, &mut info), CKR_OK);
        assert_eq!(info.cryptokiVersion.major, 3);
        assert_eq!(info.cryptokiVersion.minor, 0);
    }
}
