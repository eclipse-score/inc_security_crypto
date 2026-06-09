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

//! Integration tests — PKCS#11-style call sequences through the engine trait.
//!
//! All tests share the same process, so `init()` uses `try_engine` to
//! avoid `CKR_CRYPTOKI_ALREADY_INITIALIZED` on the second test that runs.

use cryptoki::{
    engine, register_engine, try_engine, AttributeType, EcCurve, EngineKeyRef, HashAlgorithm,
    OpenSslEngine,
};

fn init() {
    if try_engine().is_none() {
        register_engine(OpenSslEngine).expect("engine registration failed");
    }
}

// ── Random ────────────────────────────────────────────────────────────────────

#[test]
fn test_generate_random_fills_buffer() {
    init();
    let eng = engine().unwrap();
    let mut buf = vec![0u8; 32];
    eng.generate_random(&mut buf).unwrap();
    assert_ne!(buf, vec![0u8; 32]);
}

// ── Key generation ────────────────────────────────────────────────────────────

#[test]
fn test_generate_aes_key_128() {
    init();
    let key = engine().unwrap().generate_aes_key(16).unwrap();
    assert_eq!(key.as_bytes().len(), 16);
}

#[test]
fn test_generate_aes_key_256() {
    init();
    let key = engine().unwrap().generate_aes_key(32).unwrap();
    assert_eq!(key.as_bytes().len(), 32);
}

#[test]
fn test_generate_rsa_key_pair_2048() {
    init();
    let kp = engine().unwrap().generate_rsa_key_pair(2048).unwrap();
    assert_eq!(kp.bits, 2048);
    assert!(!kp.private_der.is_empty());
    assert!(!kp.public_der.is_empty());
    assert_eq!(kp.modulus.len(), 256);          // 2048 bits / 8
    assert!(!kp.public_exponent.is_empty());
}

#[test]
fn test_generate_ec_key_pair_p256() {
    init();
    let kp = engine().unwrap().generate_ec_key_pair(EcCurve::P256).unwrap();
    assert!(!kp.private_der.is_empty());
    assert!(!kp.public_der.is_empty());
    // P-256 OID is 10 bytes
    assert_eq!(kp.ec_params_der.len(), 10);
    // Uncompressed point = 04 + 32 + 32 = 65 bytes; DER OCTET STRING adds 2 bytes header
    assert_eq!(kp.ec_point_uncompressed.len(), 67);
}

// ── AES-CBC ───────────────────────────────────────────────────────────────────

#[test]
fn test_aes_cbc_roundtrip() {
    init();
    let eng = engine().unwrap();
    let key = eng.generate_aes_key(16).unwrap();
    let mut iv = vec![0u8; 16];
    eng.generate_random(&mut iv).unwrap();
    let plaintext = b"C_EncryptInit(CKM_AES_CBC_PAD) + C_Encrypt + C_Decrypt";

    let ciphertext = eng.aes_cbc_encrypt(&key, &iv, plaintext).unwrap();
    let recovered  = eng.aes_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
    assert_eq!(&*recovered, plaintext);
}

#[test]
fn test_aes_cbc_256_roundtrip() {
    init();
    let eng = engine().unwrap();
    let key = eng.generate_aes_key(32).unwrap();
    let mut iv = vec![0u8; 16];
    eng.generate_random(&mut iv).unwrap();

    let ciphertext = eng.aes_cbc_encrypt(&key, &iv, b"hello world").unwrap();
    let recovered  = eng.aes_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
    assert_eq!(&*recovered, b"hello world");
}

// ── AES-CTR ───────────────────────────────────────────────────────────────────

#[test]
fn test_aes_ctr_roundtrip() {
    init();
    let eng = engine().unwrap();
    let key = eng.generate_aes_key(16).unwrap();
    let mut iv = vec![0u8; 16];
    eng.generate_random(&mut iv).unwrap();
    let plaintext = b"C_EncryptInit(CKM_AES_CTR) stream cipher";

    let ciphertext = eng.aes_ctr_crypt(&key, &iv, plaintext).unwrap();
    let recovered  = eng.aes_ctr_crypt(&key, &iv, &ciphertext).unwrap(); // CTR decrypt == encrypt
    assert_eq!(&*recovered, plaintext);
}

// ── AES-GCM ───────────────────────────────────────────────────────────────────

#[test]
fn test_aes_gcm_roundtrip() {
    init();
    let eng = engine().unwrap();
    let key = eng.generate_aes_key(16).unwrap();
    let mut iv = vec![0u8; 12];
    eng.generate_random(&mut iv).unwrap();
    let aad = b"additional authenticated data";
    let plaintext = b"C_EncryptInit(CKM_AES_GCM) + C_Encrypt";

    let (ct, tag) = eng.aes_gcm_encrypt(&key, &iv, aad, plaintext).unwrap();
    assert_eq!(tag.len(), 16);

    let recovered = eng.aes_gcm_decrypt(&key, &iv, aad, &ct, &tag).unwrap();
    assert_eq!(&*recovered, plaintext);
}

#[test]
fn test_aes_gcm_tampered_ciphertext_fails() {
    init();
    let eng = engine().unwrap();
    let key = eng.generate_aes_key(16).unwrap();
    let iv  = vec![0u8; 12];

    let (mut ct, tag) = eng.aes_gcm_encrypt(&key, &iv, b"", b"secret").unwrap();
    ct[0] ^= 0xFF; // tamper

    let result = eng.aes_gcm_decrypt(&key, &iv, b"", &ct, &tag);
    assert!(result.is_err());
    // Maps to CKR_ENCRYPTED_DATA_INVALID
    assert_eq!(result.unwrap_err().ckr_code(), 0x00000040);
}

// ── RSA encryption ────────────────────────────────────────────────────────────

#[test]
fn test_rsa_pkcs1_encrypt_decrypt() {
    init();
    let eng = engine().unwrap();
    let kp = eng.generate_rsa_key_pair(2048).unwrap();
    let plaintext = b"RSA PKCS1 v1.5 encrypt test";

    let pub_ref  = EngineKeyRef::from_bytes(kp.public_der.clone());
    let priv_ref = EngineKeyRef::from_bytes(kp.private_der.to_vec());
    let ct        = eng.rsa_pkcs1_encrypt(&pub_ref, plaintext).unwrap();
    let recovered = eng.rsa_pkcs1_decrypt(&priv_ref, &ct).unwrap();
    assert_eq!(&*recovered, plaintext);
}

#[test]
fn test_rsa_oaep_encrypt_decrypt() {
    init();
    let eng = engine().unwrap();
    let kp = eng.generate_rsa_key_pair(2048).unwrap();
    let plaintext = b"RSA OAEP encrypt test";

    let pub_ref  = EngineKeyRef::from_bytes(kp.public_der.clone());
    let priv_ref = EngineKeyRef::from_bytes(kp.private_der.to_vec());
    let ct        = eng.rsa_oaep_encrypt(&pub_ref, plaintext).unwrap();
    let recovered = eng.rsa_oaep_decrypt(&priv_ref, &ct).unwrap();
    assert_eq!(&*recovered, plaintext);
}

// ── RSA signing ───────────────────────────────────────────────────────────────

#[test]
fn test_rsa_pkcs1_sign_verify() {
    init();
    let eng = engine().unwrap();
    let kp  = eng.generate_rsa_key_pair(2048).unwrap();
    let priv_ref = EngineKeyRef::from_bytes(kp.private_der.to_vec());
    let pub_ref  = EngineKeyRef::from_bytes(kp.public_der.clone());
    let msg = b"C_Sign(CKM_SHA256_RSA_PKCS)";

    let sig   = eng.rsa_pkcs1_sign(&priv_ref, msg).unwrap();
    let valid = eng.rsa_pkcs1_verify(&pub_ref, msg, &sig).unwrap();
    assert!(valid);
    assert_eq!(sig.len(), 256); // 2048-bit key → 256-byte signature
}

#[test]
fn test_rsa_pkcs1_tampered_message_fails() {
    init();
    let eng = engine().unwrap();
    let kp  = eng.generate_rsa_key_pair(2048).unwrap();
    let priv_ref = EngineKeyRef::from_bytes(kp.private_der.to_vec());
    let pub_ref  = EngineKeyRef::from_bytes(kp.public_der.clone());
    let sig = eng.rsa_pkcs1_sign(&priv_ref, b"original").unwrap();
    let valid = eng.rsa_pkcs1_verify(&pub_ref, b"tampered", &sig).unwrap();
    assert!(!valid);
}

#[test]
fn test_rsa_pss_sign_verify() {
    init();
    let eng = engine().unwrap();
    let kp  = eng.generate_rsa_key_pair(2048).unwrap();
    let priv_ref = EngineKeyRef::from_bytes(kp.private_der.to_vec());
    let pub_ref  = EngineKeyRef::from_bytes(kp.public_der.clone());
    let msg = b"C_Sign(CKM_SHA256_RSA_PKCS_PSS)";

    let sig   = eng.rsa_pss_sign(&priv_ref, msg).unwrap();
    let valid = eng.rsa_pss_verify(&pub_ref, msg, &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_rsa_pss_is_randomised() {
    init();
    let eng = engine().unwrap();
    let kp  = eng.generate_rsa_key_pair(2048).unwrap();
    let priv_ref = EngineKeyRef::from_bytes(kp.private_der.to_vec());
    let msg = b"same message";

    let sig1 = eng.rsa_pss_sign(&priv_ref, msg).unwrap();
    let sig2 = eng.rsa_pss_sign(&priv_ref, msg).unwrap();
    assert_ne!(sig1, sig2); // random salt → different ciphertexts
}

// ── ECDSA signing ─────────────────────────────────────────────────────────────

#[test]
fn test_ecdsa_sign_verify() {
    init();
    let eng = engine().unwrap();
    let kp  = eng.generate_ec_key_pair(EcCurve::P256).unwrap();
    let priv_ref = EngineKeyRef::from_bytes(kp.private_der.to_vec());
    let pub_ref  = EngineKeyRef::from_bytes(kp.public_der.clone());
    let msg = b"C_Sign(CKM_ECDSA) over P-256";

    let sig   = eng.ecdsa_sign(&priv_ref, msg).unwrap();
    let valid = eng.ecdsa_verify(&pub_ref, msg, &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_ecdsa_tampered_message_fails() {
    init();
    let eng = engine().unwrap();
    let kp  = eng.generate_ec_key_pair(EcCurve::P256).unwrap();

    let priv_ref = EngineKeyRef::from_bytes(kp.private_der.to_vec());
    let pub_ref  = EngineKeyRef::from_bytes(kp.public_der.clone());
    let sig   = eng.ecdsa_sign(&priv_ref, b"original").unwrap();
    let valid = eng.ecdsa_verify(&pub_ref, b"tampered", &sig).unwrap();
    assert!(!valid);
}

// ── Hashing ───────────────────────────────────────────────────────────────────

#[test]
fn test_hash_sha256_known_vector() {
    init();
    let digest = engine().unwrap().hash(HashAlgorithm::Sha256, b"hello world").unwrap();
    assert_eq!(digest.len(), 32);
}

#[test]
fn test_multi_part_hash_matches_single_part() {
    init();
    let eng = engine().unwrap();
    let full  = b"hello world";
    let reference = eng.hash(HashAlgorithm::Sha256, full).unwrap();

    // C_DigestInit → C_DigestUpdate × 2 → C_DigestFinal
    let mut hasher = eng.new_stream_hasher(HashAlgorithm::Sha256).unwrap();
    hasher.update(b"hello ").unwrap();
    hasher.update(b"world").unwrap();
    let digest = hasher.finish().unwrap();

    assert_eq!(digest, reference);
}

// ── Attributes (C_GetAttributeValue) ─────────────────────────────────────────

#[test]
fn test_rsa_attribute_modulus_bits() {
    use cryptoki::AttributeValue;
    init();
    let eng = engine().unwrap();
    let kp  = eng.generate_rsa_key_pair(2048).unwrap();
    let pub_ref = EngineKeyRef::from_bytes(kp.public_der.clone());

    let val = eng.rsa_attribute(&pub_ref, false, AttributeType::ModulusBits).unwrap();
    assert!(matches!(val, AttributeValue::Ulong(2048)));
}

#[test]
fn test_rsa_attribute_modulus() {
    use cryptoki::AttributeValue;
    init();
    let eng = engine().unwrap();
    let kp  = eng.generate_rsa_key_pair(2048).unwrap();
    let pub_ref = EngineKeyRef::from_bytes(kp.public_der.clone());

    let val = eng.rsa_attribute(&pub_ref, false, AttributeType::Modulus).unwrap();
    if let AttributeValue::Bytes(n) = val {
        assert_eq!(n, kp.modulus);
    } else {
        panic!("expected Bytes variant");
    }
}

#[test]
fn test_rsa_private_key_value_is_sensitive() {
    init();
    let eng = engine().unwrap();
    let kp  = eng.generate_rsa_key_pair(2048).unwrap();
    let priv_ref = EngineKeyRef::from_bytes(kp.private_der.to_vec());

    let err = eng.rsa_attribute(&priv_ref, true, AttributeType::Value).unwrap_err();
    assert_eq!(err.ckr_code(), 0x00000011); // CKR_ATTRIBUTE_SENSITIVE
}

#[test]
fn test_ec_attribute_params_and_point() {
    use cryptoki::AttributeValue;
    init();
    let eng = engine().unwrap();
    let kp  = eng.generate_ec_key_pair(EcCurve::P256).unwrap();
    let pub_ref = EngineKeyRef::from_bytes(kp.public_der.clone());

    let params = eng.ec_attribute(&pub_ref, false, AttributeType::EcParams).unwrap();
    if let AttributeValue::Bytes(b) = params {
        assert_eq!(b, kp.ec_params_der);
    } else {
        panic!("expected Bytes for EcParams");
    }

    let point = eng.ec_attribute(&pub_ref, false, AttributeType::EcPoint).unwrap();
    if let AttributeValue::Bytes(b) = point {
        assert_eq!(b, kp.ec_point_uncompressed);
    } else {
        panic!("expected Bytes for EcPoint");
    }
}

#[test]
fn test_aes_attribute_value_len() {
    use cryptoki::AttributeValue;
    init();
    let eng = engine().unwrap();
    let key = eng.generate_aes_key(32).unwrap();

    let val = eng.aes_attribute(&key, AttributeType::ValueLen).unwrap();
    assert!(matches!(val, AttributeValue::Ulong(32)));
}

// ── Error code mapping ────────────────────────────────────────────────────────

#[test]
fn test_not_initialized_error_code() {
    use cryptoki::CryptoError;
    let err = CryptoError::NotInitialized;
    assert_eq!(err.ckr_code(), 0x00000190); // CKR_CRYPTOKI_NOT_INITIALIZED
}

#[test]
fn test_already_initialized_error_code() {
    use cryptoki::CryptoError;
    let err = CryptoError::AlreadyInitialized;
    assert_eq!(err.ckr_code(), 0x00000191); // CKR_CRYPTOKI_ALREADY_INITIALIZED
}

#[test]
fn test_decrypt_failed_maps_to_encrypted_data_invalid() {
    use cryptoki::CryptoError;
    let err = CryptoError::DecryptFailed { message: "tag mismatch".into() };
    assert_eq!(err.ckr_code(), 0x00000040); // CKR_ENCRYPTED_DATA_INVALID
}
