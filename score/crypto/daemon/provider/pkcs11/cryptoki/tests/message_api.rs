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

//! Integration tests for: v3.0 message-based encrypt/decrypt API.
//!
//! Tests cover:
//! - `C_MessageEncryptInit` / `C_MessageDecryptInit` with unsupported mechanisms
//!   return `CKR_MECHANISM_INVALID`
//! - `C_MessageSignInit` / `C_MessageVerifyInit` return `CKR_FUNCTION_NOT_SUPPORTED`
//! - Full AES-GCM encrypt/decrypt round-trip via message API
//! - Full ChaCha20-Poly1305 encrypt/decrypt round-trip via message API
//! - Tag is written to pTag (not appended to ciphertext)
//! - `C_MessageEncryptFinal` clears the context (subsequent use without re-init fails)
//! - Per-message IV: two messages under the same init can use different IVs
//!
//! Run with:
//!   cargo test --test message_api

mod common;

use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::constants::*;
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

unsafe fn open_rw_session() -> CK_SESSION_HANDLE {
    let fl = common::fn_list();
    let mut h: CK_SESSION_HANDLE = 0;
    let rv = p11!(fl, C_OpenSession, 0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                  ptr::null_mut(), None, &mut h);
    assert_eq!(rv, CKR_OK, "C_OpenSession failed: {rv:#010x}");
    h
}

/// Generate a 16-byte AES session key.
unsafe fn make_aes_key(h: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let fl = common::fn_list();
    let attrs_data: Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> = vec![
        (CKA_TOKEN,     vec![CK_FALSE]),
        (CKA_VALUE_LEN, 16u64.to_le_bytes().to_vec()),
    ];
    let mut raw: Vec<CK_ATTRIBUTE> = attrs_data
        .iter()
        .map(|(t, v)| CK_ATTRIBUTE { r#type: *t, pValue: v.as_ptr() as *mut _, ulValueLen: v.len() as CK_ULONG })
        .collect();
    let mut mech = CK_MECHANISM { mechanism: CKM_AES_KEY_GEN, pParameter: ptr::null_mut(), ulParameterLen: 0 };
    let mut handle: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKey, h, &mut mech, raw.as_mut_ptr(), raw.len() as CK_ULONG, &mut handle);
    assert_eq!(rv, CKR_OK, "AES C_GenerateKey failed: {rv:#010x}");
    handle
}

/// Generate a ChaCha20 session key.
unsafe fn make_chacha20_key(h: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let fl = common::fn_list();
    let mut mech = CK_MECHANISM { mechanism: CKM_CHACHA20_KEY_GEN, pParameter: ptr::null_mut(), ulParameterLen: 0 };
    let mut handle: CK_OBJECT_HANDLE = 0;
    let rv = p11!(fl, C_GenerateKey, h, &mut mech, ptr::null_mut(), 0, &mut handle);
    assert_eq!(rv, CKR_OK, "ChaCha20 C_GenerateKey failed: {rv:#010x}");
    handle
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Unsupported mechanism in C_MessageEncryptInit must return CKR_MECHANISM_INVALID.
#[test]
fn message_encrypt_init_unsupported_mechanism_rejected() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let fl  = common::fn_list();
        let h   = open_rw_session();
        let key = make_aes_key(h);

        // AES-CBC is not a per-message AEAD — no per-message IV semantics.
        let mech = CK_MECHANISM { mechanism: CKM_AES_CBC_PAD, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let rv = p11!(fl3, C_MessageEncryptInit, h, &mech, key);
        assert_eq!(rv, CKR_MECHANISM_INVALID,
                   "AES-CBC must be rejected by C_MessageEncryptInit, got {rv:#010x}");

        p11!(fl, C_CloseSession, h);
    }
}

/// Unsupported mechanism in C_MessageDecryptInit must return CKR_MECHANISM_INVALID.
#[test]
fn message_decrypt_init_unsupported_mechanism_rejected() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let fl  = common::fn_list();
        let h   = open_rw_session();
        let key = make_aes_key(h);

        let mech = CK_MECHANISM { mechanism: CKM_AES_CBC_PAD, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let rv = p11!(fl3, C_MessageDecryptInit, h, &mech, key);
        assert_eq!(rv, CKR_MECHANISM_INVALID,
                   "AES-CBC must be rejected by C_MessageDecryptInit, got {rv:#010x}");

        p11!(fl, C_CloseSession, h);
    }
}

/// C_MessageSignInit must return CKR_FUNCTION_NOT_SUPPORTED for any mechanism.
#[test]
fn message_sign_init_not_supported() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let fl  = common::fn_list();
        let h   = open_rw_session();

        let mech = CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let rv = p11!(fl3, C_MessageSignInit, h, &mech, 0);
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED,
                   "C_MessageSignInit must return CKR_FUNCTION_NOT_SUPPORTED, got {rv:#010x}");

        p11!(fl, C_CloseSession, h);
    }
}

/// C_MessageVerifyInit must return CKR_FUNCTION_NOT_SUPPORTED for any mechanism.
#[test]
fn message_verify_init_not_supported() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let fl  = common::fn_list();
        let h   = open_rw_session();

        let mech = CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let rv = p11!(fl3, C_MessageVerifyInit, h, &mech, 0);
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED,
                   "C_MessageVerifyInit must return CKR_FUNCTION_NOT_SUPPORTED, got {rv:#010x}");

        p11!(fl, C_CloseSession, h);
    }
}

/// AES-GCM message round-trip: encrypt then decrypt restores plaintext.
/// Verifies that the tag is written to pTag (not appended to ciphertext).
#[test]
fn aes_gcm_message_roundtrip() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let fl  = common::fn_list();
        let h   = open_rw_session();
        let key = make_aes_key(h);

        let plaintext = b"AES-GCM message API test payload";
        let aad       = b"authenticated data";
        let iv        = [0xAAu8; 12];
        let mut tag   = [0u8; 16];

        // ── Encrypt ───────────────────────────────────────────────────────────
        let enc_mech = CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let rv = p11!(fl3, C_MessageEncryptInit, h, &enc_mech, key);
        assert_eq!(rv, CKR_OK, "C_MessageEncryptInit failed: {rv:#010x}");

        let enc_params = CK_GCM_MESSAGE_PARAMS {
            pIv:           iv.as_ptr() as *mut _,
            ulIvLen:       iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator:   0,
            pTag:          tag.as_mut_ptr(),
            ulTagBits:     128,
        };
        let mut ct_len: CK_ULONG = 0;
        // Size query
        let rv = p11!(fl3, C_EncryptMessage,
                      h,
                      &enc_params as *const _ as *const c_void,
                      std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                      aad.as_ptr(), aad.len() as CK_ULONG,
                      plaintext.as_ptr(), plaintext.len() as CK_ULONG,
                      ptr::null_mut(), &mut ct_len);
        assert_eq!(rv, CKR_OK, "C_EncryptMessage size query failed: {rv:#010x}");
        assert_eq!(ct_len as usize, plaintext.len(), "ciphertext length must equal plaintext length (tag is separate)");

        let mut ct = vec![0u8; ct_len as usize];
        let rv = p11!(fl3, C_EncryptMessage,
                      h,
                      &enc_params as *const _ as *const c_void,
                      std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                      aad.as_ptr(), aad.len() as CK_ULONG,
                      plaintext.as_ptr(), plaintext.len() as CK_ULONG,
                      ct.as_mut_ptr(), &mut ct_len);
        assert_eq!(rv, CKR_OK, "C_EncryptMessage failed: {rv:#010x}");
        ct.truncate(ct_len as usize);
        assert_ne!(&ct[..], plaintext, "ciphertext must differ from plaintext");
        assert_ne!(tag, [0u8; 16], "tag must be non-zero after encryption");

        let rv = p11!(fl3, C_MessageEncryptFinal, h);
        assert_eq!(rv, CKR_OK, "C_MessageEncryptFinal failed: {rv:#010x}");

        // ── Decrypt ───────────────────────────────────────────────────────────
        let dec_mech = CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let rv = p11!(fl3, C_MessageDecryptInit, h, &dec_mech, key);
        assert_eq!(rv, CKR_OK, "C_MessageDecryptInit failed: {rv:#010x}");

        let dec_params = CK_GCM_MESSAGE_PARAMS {
            pIv:           iv.as_ptr() as *mut _,
            ulIvLen:       iv.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator:   0,
            pTag:          tag.as_mut_ptr(), // same tag from encrypt
            ulTagBits:     128,
        };
        let mut pt_len: CK_ULONG = ct.len() as CK_ULONG + 32; // generous buffer
        let mut pt = vec![0u8; pt_len as usize];
        let rv = p11!(fl3, C_DecryptMessage,
                      h,
                      &dec_params as *const _ as *const c_void,
                      std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                      aad.as_ptr(), aad.len() as CK_ULONG,
                      ct.as_ptr(), ct.len() as CK_ULONG,
                      pt.as_mut_ptr(), &mut pt_len);
        assert_eq!(rv, CKR_OK, "C_DecryptMessage failed: {rv:#010x}");
        pt.truncate(pt_len as usize);
        assert_eq!(&pt[..], plaintext, "decrypted plaintext must match original");

        let rv = p11!(fl3, C_MessageDecryptFinal, h);
        assert_eq!(rv, CKR_OK, "C_MessageDecryptFinal failed: {rv:#010x}");

        p11!(fl, C_CloseSession, h);
    }
}

/// ChaCha20-Poly1305 message round-trip.
#[test]
fn chacha20_poly1305_message_roundtrip() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let fl  = common::fn_list();
        let h   = open_rw_session();
        let key = make_chacha20_key(h);

        let plaintext = b"ChaCha20-Poly1305 message API test";
        let aad       = b"per-message aad";
        let nonce     = [0xBBu8; 12];
        let mut tag   = [0u8; 16];

        // Encrypt
        let enc_mech = CK_MECHANISM { mechanism: CKM_CHACHA20_POLY1305, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let rv = p11!(fl3, C_MessageEncryptInit, h, &enc_mech, key);
        assert_eq!(rv, CKR_OK, "C_MessageEncryptInit (ChaCha20) failed: {rv:#010x}");

        let enc_params = CK_GCM_MESSAGE_PARAMS {
            pIv:           nonce.as_ptr() as *mut _,
            ulIvLen:       nonce.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator:   0,
            pTag:          tag.as_mut_ptr(),
            ulTagBits:     128,
        };
        let mut ct_len: CK_ULONG = 256;
        let mut ct = vec![0u8; 256];
        let rv = p11!(fl3, C_EncryptMessage,
                      h,
                      &enc_params as *const _ as *const c_void,
                      std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                      aad.as_ptr(), aad.len() as CK_ULONG,
                      plaintext.as_ptr(), plaintext.len() as CK_ULONG,
                      ct.as_mut_ptr(), &mut ct_len);
        assert_eq!(rv, CKR_OK, "C_EncryptMessage (ChaCha20) failed: {rv:#010x}");
        ct.truncate(ct_len as usize);
        p11!(fl3, C_MessageEncryptFinal, h);

        // Decrypt
        let dec_mech = CK_MECHANISM { mechanism: CKM_CHACHA20_POLY1305, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let rv = p11!(fl3, C_MessageDecryptInit, h, &dec_mech, key);
        assert_eq!(rv, CKR_OK, "C_MessageDecryptInit (ChaCha20) failed: {rv:#010x}");

        let dec_params = CK_GCM_MESSAGE_PARAMS {
            pIv:           nonce.as_ptr() as *mut _,
            ulIvLen:       nonce.len() as CK_ULONG,
            ulIvFixedBits: 0,
            ivGenerator:   0,
            pTag:          tag.as_mut_ptr(),
            ulTagBits:     128,
        };
        let mut pt_len: CK_ULONG = 256;
        let mut pt = vec![0u8; 256];
        let rv = p11!(fl3, C_DecryptMessage,
                      h,
                      &dec_params as *const _ as *const c_void,
                      std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                      aad.as_ptr(), aad.len() as CK_ULONG,
                      ct.as_ptr(), ct.len() as CK_ULONG,
                      pt.as_mut_ptr(), &mut pt_len);
        assert_eq!(rv, CKR_OK, "C_DecryptMessage (ChaCha20) failed: {rv:#010x}");
        pt.truncate(pt_len as usize);
        assert_eq!(&pt[..], plaintext);
        p11!(fl3, C_MessageDecryptFinal, h);

        p11!(fl, C_CloseSession, h);
    }
}

/// After C_MessageEncryptFinal, C_EncryptMessage must return CKR_OPERATION_NOT_INITIALIZED.
#[test]
fn message_encrypt_final_clears_context() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let fl  = common::fn_list();
        let h   = open_rw_session();
        let key = make_aes_key(h);

        let mech = CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let rv = p11!(fl3, C_MessageEncryptInit, h, &mech, key);
        assert_eq!(rv, CKR_OK);
        let rv = p11!(fl3, C_MessageEncryptFinal, h);
        assert_eq!(rv, CKR_OK);

        // Context is gone — C_EncryptMessage must fail.
        let iv  = [0u8; 12];
        let mut tag = [0u8; 16];
        let params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_ptr() as *mut _, ulIvLen: 12, ulIvFixedBits: 0,
            ivGenerator: 0, pTag: tag.as_mut_ptr(), ulTagBits: 128,
        };
        let mut ct_len: CK_ULONG = 64;
        let mut ct = vec![0u8; 64];
        let rv = p11!(fl3, C_EncryptMessage,
                      h,
                      &params as *const _ as *const c_void,
                      std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                      ptr::null(), 0,
                      b"data".as_ptr(), 4,
                      ct.as_mut_ptr(), &mut ct_len);
        assert_eq!(rv, CKR_OPERATION_NOT_INITIALIZED,
                   "C_EncryptMessage after Final must return CKR_OPERATION_NOT_INITIALIZED, got {rv:#010x}");

        p11!(fl, C_CloseSession, h);
    }
}

/// Two messages under the same C_MessageEncryptInit can use different IVs.
#[test]
fn per_message_different_ivs() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let fl  = common::fn_list();
        let h   = open_rw_session();
        let key = make_aes_key(h);

        let plaintext = b"same key, different IVs";
        let iv1 = [0x11u8; 12];
        let iv2 = [0x22u8; 12];
        let mut tag1 = [0u8; 16];
        let mut tag2 = [0u8; 16];

        let mech = CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        let rv = p11!(fl3, C_MessageEncryptInit, h, &mech, key);
        assert_eq!(rv, CKR_OK);

        let params1 = CK_GCM_MESSAGE_PARAMS {
            pIv: iv1.as_ptr() as *mut _, ulIvLen: 12, ulIvFixedBits: 0,
            ivGenerator: 0, pTag: tag1.as_mut_ptr(), ulTagBits: 128,
        };
        let mut ct1_len = plaintext.len() as CK_ULONG;
        let mut ct1 = vec![0u8; plaintext.len()];
        let rv = p11!(fl3, C_EncryptMessage,
                      h, &params1 as *const _ as *const c_void,
                      std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                      ptr::null(), 0,
                      plaintext.as_ptr(), plaintext.len() as CK_ULONG,
                      ct1.as_mut_ptr(), &mut ct1_len);
        assert_eq!(rv, CKR_OK, "first encrypt failed: {rv:#010x}");

        let params2 = CK_GCM_MESSAGE_PARAMS {
            pIv: iv2.as_ptr() as *mut _, ulIvLen: 12, ulIvFixedBits: 0,
            ivGenerator: 0, pTag: tag2.as_mut_ptr(), ulTagBits: 128,
        };
        let mut ct2_len = plaintext.len() as CK_ULONG;
        let mut ct2 = vec![0u8; plaintext.len()];
        let rv = p11!(fl3, C_EncryptMessage,
                      h, &params2 as *const _ as *const c_void,
                      std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                      ptr::null(), 0,
                      plaintext.as_ptr(), plaintext.len() as CK_ULONG,
                      ct2.as_mut_ptr(), &mut ct2_len);
        assert_eq!(rv, CKR_OK, "second encrypt failed: {rv:#010x}");

        // Different IVs → different ciphertexts.
        assert_ne!(ct1, ct2, "different IVs must produce different ciphertexts");

        p11!(fl3, C_MessageEncryptFinal, h);
        p11!(fl, C_CloseSession, h);
    }
}

/// Tampered ciphertext must cause decryption to fail with CKR_ENCRYPTED_DATA_INVALID.
#[test]
fn aes_gcm_message_tampered_ciphertext_rejected() {
    init();
    unsafe {
        let fl3 = common::fn_list_3_0();
        let fl  = common::fn_list();
        let h   = open_rw_session();
        let key = make_aes_key(h);

        let plaintext = b"integrity protected data";
        let iv        = [0xCCu8; 12];
        let mut tag   = [0u8; 16];

        let enc_mech = CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        p11!(fl3, C_MessageEncryptInit, h, &enc_mech, key);
        let params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_ptr() as *mut _, ulIvLen: 12, ulIvFixedBits: 0,
            ivGenerator: 0, pTag: tag.as_mut_ptr(), ulTagBits: 128,
        };
        let mut ct_len = plaintext.len() as CK_ULONG;
        let mut ct = vec![0u8; plaintext.len()];
        p11!(fl3, C_EncryptMessage,
             h, &params as *const _ as *const c_void,
             std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
             ptr::null(), 0,
             plaintext.as_ptr(), plaintext.len() as CK_ULONG,
             ct.as_mut_ptr(), &mut ct_len);
        p11!(fl3, C_MessageEncryptFinal, h);

        // Tamper
        ct[0] ^= 0xFF;

        let dec_mech = CK_MECHANISM { mechanism: CKM_AES_GCM, pParameter: ptr::null_mut(), ulParameterLen: 0 };
        p11!(fl3, C_MessageDecryptInit, h, &dec_mech, key);
        let dec_params = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_ptr() as *mut _, ulIvLen: 12, ulIvFixedBits: 0,
            ivGenerator: 0, pTag: tag.as_mut_ptr(), ulTagBits: 128,
        };
        let mut pt_len: CK_ULONG = 256;
        let mut pt = vec![0u8; 256];
        let rv = p11!(fl3, C_DecryptMessage,
                      h, &dec_params as *const _ as *const c_void,
                      std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
                      ptr::null(), 0,
                      ct.as_ptr(), ct.len() as CK_ULONG,
                      pt.as_mut_ptr(), &mut pt_len);
        assert_ne!(rv, CKR_OK, "tampered ciphertext must not decrypt successfully");
        p11!(fl3, C_MessageDecryptFinal, h);

        p11!(fl, C_CloseSession, h);
    }
}
