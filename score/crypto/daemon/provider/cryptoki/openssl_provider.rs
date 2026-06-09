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

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher, Crypter, Mode};

use zeroize::Zeroizing;

use crate::attributes::{AttributeType, AttributeValue};
use crate::error::CryptoError;
use crate::traits::{CryptoProvider, EngineMechanismInfo, EngineKeyRef, StreamHasher};
use crate::types::{EcCurve, EcKeyPair, EdKeyPair, EdwardsCurve, HashAlgorithm, RsaKeyPair};

// ── Error conversion helpers ──────────────────────────────────────────────────

fn key_err(e: openssl::error::ErrorStack) -> CryptoError {
    CryptoError::KeyGenFailed { message: e.to_string() }
}

fn invalid_key_err(e: openssl::error::ErrorStack) -> CryptoError {
    CryptoError::InvalidKeyData { message: e.to_string() }
}

fn encrypt_err(e: openssl::error::ErrorStack) -> CryptoError {
    CryptoError::EncryptFailed { message: e.to_string() }
}

fn decrypt_err(e: openssl::error::ErrorStack) -> CryptoError {
    CryptoError::DecryptFailed { message: e.to_string() }
}

fn sign_err(e: openssl::error::ErrorStack) -> CryptoError {
    CryptoError::SignFailed { message: e.to_string() }
}

fn verify_err(e: openssl::error::ErrorStack) -> CryptoError {
    CryptoError::VerifyFailed { message: e.to_string() }
}

fn hash_err(e: openssl::error::ErrorStack) -> CryptoError {
    CryptoError::HashFailed { message: e.to_string() }
}

fn random_err(e: openssl::error::ErrorStack) -> CryptoError {
    CryptoError::RandomFailed { message: e.to_string() }
}

// ── AES cipher selection ──────────────────────────────────────────────────────

fn aes_cbc_cipher(key_len: usize) -> Result<Cipher, CryptoError> {
    match key_len {
        16 => Ok(Cipher::aes_128_cbc()),
        24 => Ok(Cipher::aes_192_cbc()),
        32 => Ok(Cipher::aes_256_cbc()),
        n  => Err(CryptoError::InvalidKeySize {
            message: format!("AES-CBC key must be 16, 24, or 32 bytes; got {n}"),
        }),
    }
}

fn aes_ctr_cipher(key_len: usize) -> Result<Cipher, CryptoError> {
    match key_len {
        16 => Ok(Cipher::aes_128_ctr()),
        24 => Ok(Cipher::aes_192_ctr()),
        32 => Ok(Cipher::aes_256_ctr()),
        n  => Err(CryptoError::InvalidKeySize {
            message: format!("AES-CTR key must be 16, 24, or 32 bytes; got {n}"),
        }),
    }
}

fn aes_gcm_cipher(key_len: usize) -> Result<Cipher, CryptoError> {
    match key_len {
        16 => Ok(Cipher::aes_128_gcm()),
        24 => Ok(Cipher::aes_192_gcm()),
        32 => Ok(Cipher::aes_256_gcm()),
        n  => Err(CryptoError::InvalidKeySize {
            message: format!("AES-GCM key must be 16, 24, or 32 bytes; got {n}"),
        }),
    }
}

// ── MessageDigest mapping ─────────────────────────────────────────────────────

fn message_digest(algorithm: HashAlgorithm) -> Result<MessageDigest, CryptoError> {
    match algorithm {
        HashAlgorithm::Md5      => Ok(MessageDigest::md5()),
        HashAlgorithm::Sha1     => Ok(MessageDigest::sha1()),
        HashAlgorithm::Sha256   => Ok(MessageDigest::sha256()),
        HashAlgorithm::Sha384   => Ok(MessageDigest::sha384()),
        HashAlgorithm::Sha512   => Ok(MessageDigest::sha512()),
        HashAlgorithm::Sha3_256 => Ok(MessageDigest::sha3_256()),
        HashAlgorithm::Sha3_384 => Ok(MessageDigest::sha3_384()),
        HashAlgorithm::Sha3_512 => Ok(MessageDigest::sha3_512()),
        #[allow(unreachable_patterns)]
        _ => Err(CryptoError::MechanismInvalid { name: "unknown HashAlgorithm variant" }),
    }
}

// ── DER OCTET STRING wrapper (for CKA_EC_POINT) ───────────────────────────────

/// Wrap raw bytes in a DER OCTET STRING (tag 0x04 + length + data).
/// Used to produce the CKA_EC_POINT encoding that PKCS#11 expects.
fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len();
    let mut out = Vec::with_capacity(4 + len);
    out.push(0x04); // OCTET STRING tag
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
    out.extend_from_slice(bytes);
    out
}

// ── Streaming hasher wrapper ──────────────────────────────────────────────────

struct OpenSslStreamHasher {
    inner: Hasher,
}

impl StreamHasher for OpenSslStreamHasher {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.inner.update(data).map_err(hash_err)
    }

    fn finish(mut self: Box<Self>) -> Result<Vec<u8>, CryptoError> {
        self.inner.finish().map(|d| d.to_vec()).map_err(hash_err)
    }
}

// ── OpenSslEngine ─────────────────────────────────────────────────────────────

/// OpenSSL-backed crypto engine.
///
/// A zero-size struct — all state lives in the OpenSSL library itself.
/// Thread-safety is guaranteed by OpenSSL's internal locking.
pub struct OpenSslEngine;

impl CryptoProvider for OpenSslEngine {

    // ── Key generation ────────────────────────────────────────────────────────

    fn generate_rsa_key_pair(&self, bits: u32) -> Result<RsaKeyPair, CryptoError> {
        let exponent = openssl::bn::BigNum::from_u32(65537).map_err(key_err)?;
        let rsa = Rsa::generate_with_e(bits, &exponent).map_err(key_err)?;

        // Pre-extract attribute values before moving rsa into PKey.
        let modulus         = rsa.n().to_vec();
        let public_exponent = rsa.e().to_vec();

        let pkey = PKey::from_rsa(rsa).map_err(key_err)?;
        let private_der = Zeroizing::new(pkey.private_key_to_pkcs8().map_err(key_err)?);
        let public_der  = pkey.public_key_to_der().map_err(key_err)?;

        Ok(RsaKeyPair { private_der, public_der, bits, modulus, public_exponent })
    }

    fn generate_ec_key_pair(&self, curve: EcCurve) -> Result<EcKeyPair, CryptoError> {
        let nid = match curve {
            EcCurve::P256 => Nid::X9_62_PRIME256V1,
            EcCurve::P384 => Nid::SECP384R1,
            EcCurve::P521 => Nid::SECP521R1,
            #[allow(unreachable_patterns)]
            _ => return Err(CryptoError::MechanismInvalid { name: "unsupported EC curve" }),
        };

        let ec_params_der = match curve {
            EcCurve::P256 => vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            EcCurve::P384 => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
            EcCurve::P521 => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
            #[allow(unreachable_patterns)]
            _ => return Err(CryptoError::MechanismInvalid { name: "unsupported EC curve" }),
        };

        let group   = EcGroup::from_curve_name(nid).map_err(key_err)?;
        let ec_key  = EcKey::generate(&group).map_err(key_err)?;

        // Extract CKA_EC_POINT: DER OCTET STRING wrapping the uncompressed point.
        let mut ctx = BigNumContext::new().map_err(key_err)?;
        let point_bytes = ec_key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(key_err)?;
        let ec_point_uncompressed = der_octet_string(&point_bytes);

        let pkey = PKey::from_ec_key(ec_key).map_err(key_err)?;
        let private_der = Zeroizing::new(pkey.private_key_to_pkcs8().map_err(key_err)?);
        let public_der  = pkey.public_key_to_der().map_err(key_err)?;

        Ok(EcKeyPair { private_der, public_der, curve, ec_params_der, ec_point_uncompressed })
    }

    fn generate_aes_key(&self, len: usize) -> Result<EngineKeyRef, CryptoError> {
        if !matches!(len, 16 | 24 | 32) {
            return Err(CryptoError::InvalidKeySize {
                message: format!("AES key must be 16, 24, or 32 bytes; got {len}"),
            });
        }
        let mut buf = vec![0u8; len];
        rand_bytes(&mut buf).map_err(key_err)?;
        Ok(EngineKeyRef::from_bytes(buf))
    }

    // ── Random ────────────────────────────────────────────────────────────────

    fn generate_random(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        rand_bytes(buf).map_err(random_err)
    }

    // ── AES-CBC ───────────────────────────────────────────────────────────────

    fn aes_cbc_encrypt(
        &self,
        key: &EngineKeyRef,
        iv: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = key.as_bytes();
        let cipher = aes_cbc_cipher(key.len())?;
        let mut c = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).map_err(encrypt_err)?;
        c.pad(true);
        let mut out = vec![0u8; plaintext.len() + cipher.block_size()];
        let mut n = c.update(plaintext, &mut out).map_err(encrypt_err)?;
        n += c.finalize(&mut out[n..]).map_err(encrypt_err)?;
        out.truncate(n);
        Ok(out)
    }

    fn aes_cbc_decrypt(
        &self,
        key: &EngineKeyRef,
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let key = key.as_bytes();
        let cipher = aes_cbc_cipher(key.len())?;
        let mut c = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).map_err(decrypt_err)?;
        c.pad(true);
        let mut out = vec![0u8; ciphertext.len() + cipher.block_size()];
        let mut n = c.update(ciphertext, &mut out).map_err(decrypt_err)?;
        n += c.finalize(&mut out[n..]).map_err(decrypt_err)?;
        out.truncate(n);
        Ok(Zeroizing::new(out))
    }

    // ── AES-CTR ───────────────────────────────────────────────────────────────

    fn aes_ctr_crypt(
        &self,
        key: &EngineKeyRef,
        iv: &[u8],
        input: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = key.as_bytes();
        let cipher = aes_ctr_cipher(key.len())?;
        // CTR is a stream cipher — no padding, encrypt == decrypt.
        let mut c = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).map_err(encrypt_err)?;
        c.pad(false);
        let mut out = vec![0u8; input.len() + cipher.block_size()];
        let mut n = c.update(input, &mut out).map_err(encrypt_err)?;
        n += c.finalize(&mut out[n..]).map_err(encrypt_err)?;
        out.truncate(n);
        Ok(out)
    }

    // ── AES-GCM ───────────────────────────────────────────────────────────────

    fn aes_gcm_encrypt(
        &self,
        key: &EngineKeyRef,
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let key = key.as_bytes();
        let cipher = aes_gcm_cipher(key.len())?;
        let mut tag = vec![0u8; 16];
        let ciphertext = encrypt_aead(cipher, key, Some(iv), aad, plaintext, &mut tag)
            .map_err(encrypt_err)?;
        Ok((ciphertext, tag))
    }

    fn aes_gcm_decrypt(
        &self,
        key: &EngineKeyRef,
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let key = key.as_bytes();
        let cipher = aes_gcm_cipher(key.len())?;
        decrypt_aead(cipher, key, Some(iv), aad, ciphertext, tag)
            .map(Zeroizing::new)
            .map_err(decrypt_err)
    }

    // ── RSA PKCS#1 v1.5 encryption ────────────────────────────────────────────

    fn rsa_pkcs1_encrypt(
        &self,
        key: &EngineKeyRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let pkey = PKey::<Public>::public_key_from_der(key.as_bytes()).map_err(invalid_key_err)?;
        let rsa  = pkey.rsa().map_err(invalid_key_err)?;
        let mut out = vec![0u8; rsa.size() as usize];
        let n = rsa.public_encrypt(plaintext, &mut out, Padding::PKCS1).map_err(encrypt_err)?;
        out.truncate(n);
        Ok(out)
    }

    fn rsa_pkcs1_decrypt(
        &self,
        key: &EngineKeyRef,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let pkey = PKey::<Private>::private_key_from_pkcs8(key.as_bytes()).map_err(invalid_key_err)?;
        let rsa  = pkey.rsa().map_err(invalid_key_err)?;
        let mut out = Zeroizing::new(vec![0u8; rsa.size() as usize]);
        let n = rsa.private_decrypt(ciphertext, &mut out, Padding::PKCS1).map_err(decrypt_err)?;
        out.truncate(n);
        Ok(out)
    }

    // ── RSA-OAEP encryption ───────────────────────────────────────────────────

    fn rsa_oaep_encrypt(
        &self,
        key: &EngineKeyRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let pkey = PKey::<Public>::public_key_from_der(key.as_bytes()).map_err(invalid_key_err)?;
        let rsa  = pkey.rsa().map_err(invalid_key_err)?;
        let mut out = vec![0u8; rsa.size() as usize];
        let n = rsa.public_encrypt(plaintext, &mut out, Padding::PKCS1_OAEP).map_err(encrypt_err)?;
        out.truncate(n);
        Ok(out)
    }

    fn rsa_oaep_decrypt(
        &self,
        key: &EngineKeyRef,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let pkey = PKey::<Private>::private_key_from_pkcs8(key.as_bytes()).map_err(invalid_key_err)?;
        let rsa  = pkey.rsa().map_err(invalid_key_err)?;
        let mut out = Zeroizing::new(vec![0u8; rsa.size() as usize]);
        let n = rsa.private_decrypt(ciphertext, &mut out, Padding::PKCS1_OAEP).map_err(decrypt_err)?;
        out.truncate(n);
        Ok(out)
    }

    // ── RSA PKCS#1 v1.5 signing ───────────────────────────────────────────────

    fn rsa_pkcs1_sign(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let pkey = PKey::private_key_from_pkcs8(key.as_bytes()).map_err(invalid_key_err)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).map_err(sign_err)?;
        // Default RSA padding for Signer is PKCS#1 v1.5 — no explicit set needed.
        signer.update(message).map_err(sign_err)?;
        signer.sign_to_vec().map_err(sign_err)
    }

    fn rsa_pkcs1_verify(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let pkey = PKey::public_key_from_der(key.as_bytes()).map_err(invalid_key_err)?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).map_err(verify_err)?;
        verifier.update(message).map_err(verify_err)?;
        verifier.verify(signature).map_err(verify_err)
    }

    // ── RSA-PSS signing ───────────────────────────────────────────────────────

    fn rsa_pss_sign(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let pkey = PKey::private_key_from_pkcs8(key.as_bytes()).map_err(invalid_key_err)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).map_err(sign_err)?;
        signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS).map_err(sign_err)?;
        signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH).map_err(sign_err)?;
        signer.update(message).map_err(sign_err)?;
        signer.sign_to_vec().map_err(sign_err)
    }

    fn rsa_pss_verify(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let pkey = PKey::public_key_from_der(key.as_bytes()).map_err(invalid_key_err)?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).map_err(verify_err)?;
        verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS).map_err(verify_err)?;
        verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH).map_err(verify_err)?;
        verifier.update(message).map_err(verify_err)?;
        verifier.verify(signature).map_err(verify_err)
    }

    // ── ECDSA signing ─────────────────────────────────────────────────────────

    fn ecdsa_sign(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let pkey   = PKey::<Private>::private_key_from_pkcs8(key.as_bytes()).map_err(invalid_key_err)?;
        let ec_key = pkey.ec_key().map_err(invalid_key_err)?;
        // Hash the message first (CKM_ECDSA requires a pre-hashed digest).
        let digest = hash(MessageDigest::sha256(), message).map_err(hash_err)?;
        let sig    = EcdsaSig::sign(digest.as_ref(), &ec_key).map_err(sign_err)?;
        sig.to_der().map_err(sign_err)
    }

    fn ecdsa_verify(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let pkey   = PKey::<Public>::public_key_from_der(key.as_bytes()).map_err(invalid_key_err)?;
        let ec_key = pkey.ec_key().map_err(invalid_key_err)?;
        let digest = hash(MessageDigest::sha256(), message).map_err(hash_err)?;
        let sig    = EcdsaSig::from_der(signature)
            .map_err(|e| CryptoError::VerifyFailed { message: e.to_string() })?;
        sig.verify(digest.as_ref(), &ec_key).map_err(verify_err)
    }

    /// Sign a **pre-computed** digest with ECDSA.
    ///
    /// The caller is responsible for hashing the message with the appropriate
    /// algorithm before calling this method.  `EcdsaSig::sign` takes raw
    /// digest bytes directly — no internal hashing is performed here.
    fn ecdsa_sign_prehashed(
        &self,
        key: &EngineKeyRef,
        digest: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let pkey   = PKey::<Private>::private_key_from_pkcs8(key.as_bytes()).map_err(invalid_key_err)?;
        let ec_key = pkey.ec_key().map_err(invalid_key_err)?;
        let sig    = EcdsaSig::sign(digest, &ec_key).map_err(sign_err)?;
        sig.to_der().map_err(sign_err)
    }

    fn ecdsa_verify_prehashed(
        &self,
        key: &EngineKeyRef,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let pkey   = PKey::<Public>::public_key_from_der(key.as_bytes()).map_err(invalid_key_err)?;
        let ec_key = pkey.ec_key().map_err(invalid_key_err)?;
        let sig    = EcdsaSig::from_der(signature)
            .map_err(|e| CryptoError::VerifyFailed { message: e.to_string() })?;
        sig.verify(digest, &ec_key).map_err(verify_err)
    }

    // ── Hash-parameterized RSA/ECDSA signing (SHA-384/512 etc.) ──────────────

    fn rsa_pkcs1_sign_hash(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        hash_algo: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let md = message_digest(hash_algo)?;
        let pkey = PKey::private_key_from_pkcs8(key.as_bytes()).map_err(invalid_key_err)?;
        let mut signer = Signer::new(md, &pkey).map_err(sign_err)?;
        signer.update(message).map_err(sign_err)?;
        signer.sign_to_vec().map_err(sign_err)
    }

    fn rsa_pkcs1_verify_hash(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        signature: &[u8],
        hash_algo: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let md = message_digest(hash_algo)?;
        let pkey = PKey::public_key_from_der(key.as_bytes()).map_err(invalid_key_err)?;
        let mut verifier = Verifier::new(md, &pkey).map_err(verify_err)?;
        verifier.update(message).map_err(verify_err)?;
        verifier.verify(signature).map_err(verify_err)
    }

    fn rsa_pss_sign_hash(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        hash_algo: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let md = message_digest(hash_algo)?;
        let pkey = PKey::private_key_from_pkcs8(key.as_bytes()).map_err(invalid_key_err)?;
        let mut signer = Signer::new(md, &pkey).map_err(sign_err)?;
        signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS).map_err(sign_err)?;
        signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH).map_err(sign_err)?;
        signer.update(message).map_err(sign_err)?;
        signer.sign_to_vec().map_err(sign_err)
    }

    fn rsa_pss_verify_hash(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        signature: &[u8],
        hash_algo: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let md = message_digest(hash_algo)?;
        let pkey = PKey::public_key_from_der(key.as_bytes()).map_err(invalid_key_err)?;
        let mut verifier = Verifier::new(md, &pkey).map_err(verify_err)?;
        verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS).map_err(verify_err)?;
        verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH).map_err(verify_err)?;
        verifier.update(message).map_err(verify_err)?;
        verifier.verify(signature).map_err(verify_err)
    }

    fn ecdsa_sign_hash(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        hash_algo: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let md = message_digest(hash_algo)?;
        let pkey   = PKey::<Private>::private_key_from_pkcs8(key.as_bytes()).map_err(invalid_key_err)?;
        let ec_key = pkey.ec_key().map_err(invalid_key_err)?;
        let digest = hash(md, message).map_err(hash_err)?;
        let sig    = EcdsaSig::sign(digest.as_ref(), &ec_key).map_err(sign_err)?;
        sig.to_der().map_err(sign_err)
    }

    fn ecdsa_verify_hash(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        signature: &[u8],
        hash_algo: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let md = message_digest(hash_algo)?;
        let pkey   = PKey::<Public>::public_key_from_der(key.as_bytes()).map_err(invalid_key_err)?;
        let ec_key = pkey.ec_key().map_err(invalid_key_err)?;
        let digest = hash(md, message).map_err(hash_err)?;
        let sig    = EcdsaSig::from_der(signature)
            .map_err(|e| CryptoError::VerifyFailed { message: e.to_string() })?;
        sig.verify(digest.as_ref(), &ec_key).map_err(verify_err)
    }

    // ── AES Key Wrap (RFC 3394) ─────────────────────────────────────────────

    fn aes_key_wrap(
        &self,
        kek: &EngineKeyRef,
        plaintext_key: &EngineKeyRef,
    ) -> Result<Vec<u8>, CryptoError> {
        use openssl::aes::{AesKey, wrap_key};
        let plaintext_key = plaintext_key.as_bytes();
        let aes_key = AesKey::new_encrypt(kek.as_bytes())
            .map_err(|_| CryptoError::EncryptFailed { message: "AES key wrap: invalid KEK".into() })?;
        let mut out = vec![0u8; plaintext_key.len() + 8]; // wrap adds 8-byte IV
        let n = wrap_key(&aes_key, None, &mut out, plaintext_key)
            .map_err(|_| CryptoError::EncryptFailed { message: "AES key wrap failed".into() })?;
        out.truncate(n);
        Ok(out)
    }

    fn aes_key_unwrap(
        &self,
        kek: &EngineKeyRef,
        wrapped_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        use openssl::aes::{AesKey, unwrap_key};
        let aes_key = AesKey::new_decrypt(kek.as_bytes())
            .map_err(|_| CryptoError::DecryptFailed { message: "AES key unwrap: invalid KEK".into() })?;
        // AES Key Wrap (RFC 3394) adds an 8-byte integrity check value, so the
        // plaintext is always 8 bytes shorter than the wrapped ciphertext.
        let pt_len = wrapped_key.len().checked_sub(8)
            .ok_or_else(|| CryptoError::DecryptFailed { message: "wrapped key too short".into() })?;
        let mut out = Zeroizing::new(vec![0u8; pt_len]);
        let n = unwrap_key(&aes_key, None, &mut out, wrapped_key)
            .map_err(|_| CryptoError::DecryptFailed { message: "AES key unwrap failed".into() })?;
        out.truncate(n);
        Ok(out)
    }

    fn key_value_for_digest(&self, key_ref: &EngineKeyRef) -> Result<Vec<u8>, CryptoError> {
        // For the software engine the key ref IS the raw key bytes, so return them directly.
        // This is the only permitted call to as_bytes() for semantic purposes — all other
        // callers in the PKCS#11 layer pass key refs through opaquely.
        Ok(key_ref.as_bytes().to_vec())
    }

    // ── HMAC ─────────────────────────────────────────────────────────────────

    fn hmac_sign(&self, algorithm: HashAlgorithm, key: &EngineKeyRef, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let md   = message_digest(algorithm)?;
        let pkey = PKey::hmac(key.as_bytes()).map_err(sign_err)?;
        let mut signer = Signer::new(md, &pkey).map_err(sign_err)?;
        signer.update(data).map_err(sign_err)?;
        signer.sign_to_vec().map_err(sign_err)
    }

    fn hmac_verify(&self, algorithm: HashAlgorithm, key: &EngineKeyRef, data: &[u8], mac: &[u8]) -> Result<bool, CryptoError> {
        let computed = self.hmac_sign(algorithm, key, data)?;
        if computed.len() != mac.len() { return Ok(false); }
        Ok(openssl::memcmp::eq(&computed, mac))
    }

    // ── Hashing ───────────────────────────────────────────────────────────────

    fn hash(
        &self,
        algorithm: HashAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let md = message_digest(algorithm)?;
        hash(md, data).map(|d| d.to_vec()).map_err(hash_err)
    }

    fn new_stream_hasher(
        &self,
        algorithm: HashAlgorithm,
    ) -> Result<Box<dyn StreamHasher>, CryptoError> {
        let md = message_digest(algorithm)?;
        let inner = Hasher::new(md).map_err(hash_err)?;
        Ok(Box::new(OpenSslStreamHasher { inner }))
    }

    // ── Attribute access ──────────────────────────────────────────────────────

    fn rsa_attribute(
        &self,
        key: &EngineKeyRef,
        is_private: bool,
        attr: AttributeType,
    ) -> Result<AttributeValue, CryptoError> {
        if is_private && matches!(attr, AttributeType::Value) {
            return Err(CryptoError::AttributeSensitive);
        }

        let key_der = key.as_bytes();
        let (n_bytes, e_bytes, size_bytes) = if is_private {
            let pkey = PKey::<Private>::private_key_from_pkcs8(key_der).map_err(invalid_key_err)?;
            let rsa  = pkey.rsa().map_err(invalid_key_err)?;
            (rsa.n().to_vec(), rsa.e().to_vec(), rsa.size() as u64)
        } else {
            let pkey = PKey::<Public>::public_key_from_der(key_der).map_err(invalid_key_err)?;
            let rsa  = pkey.rsa().map_err(invalid_key_err)?;
            (rsa.n().to_vec(), rsa.e().to_vec(), rsa.size() as u64)
        };

        match attr {
            AttributeType::Modulus        => Ok(AttributeValue::Bytes(n_bytes)),
            AttributeType::ModulusBits    => Ok(AttributeValue::Ulong(size_bytes * 8)),
            AttributeType::PublicExponent => Ok(AttributeValue::Bytes(e_bytes)),
            _ => Err(CryptoError::AttributeTypeInvalid),
        }
    }

    fn ec_attribute(
        &self,
        key: &EngineKeyRef,
        is_private: bool,
        attr: AttributeType,
    ) -> Result<AttributeValue, CryptoError> {
        if is_private && matches!(attr, AttributeType::Value) {
            return Err(CryptoError::AttributeSensitive);
        }

        let key_der = key.as_bytes();
        let (ec_params_der, ec_point_der) = if is_private {
            let pkey   = PKey::<Private>::private_key_from_pkcs8(key_der).map_err(invalid_key_err)?;
            let ec_key = pkey.ec_key().map_err(invalid_key_err)?;
            let params = ec_params_for_group(ec_key.group())?;
            let point  = ec_point_for_key(&ec_key)?;
            (params, point)
        } else {
            let pkey   = PKey::<Public>::public_key_from_der(key_der).map_err(invalid_key_err)?;
            let ec_key = pkey.ec_key().map_err(invalid_key_err)?;
            let params = ec_params_for_group(ec_key.group())?;
            let point  = ec_point_for_key(&ec_key)?;
            (params, point)
        };

        match attr {
            AttributeType::EcParams => Ok(AttributeValue::Bytes(ec_params_der)),
            AttributeType::EcPoint  => Ok(AttributeValue::Bytes(ec_point_der)),
            _ => Err(CryptoError::AttributeTypeInvalid),
        }
    }

    fn aes_attribute(
        &self,
        key: &EngineKeyRef,
        attr: AttributeType,
    ) -> Result<AttributeValue, CryptoError> {
        let raw = key.as_bytes();
        match attr {
            AttributeType::ValueLen => Ok(AttributeValue::Ulong(raw.len() as u64)),
            AttributeType::Value    => Ok(AttributeValue::Bytes(raw.to_vec())),
            _ => Err(CryptoError::AttributeTypeInvalid),
        }
    }

    // ── EdDSA (v3.0) ────────────────────────────────────────────────────────

    fn generate_ed_key_pair(&self, curve: EdwardsCurve) -> Result<EdKeyPair, CryptoError> {
        let pkey = match curve {
            EdwardsCurve::Ed25519 => PKey::generate_ed25519().map_err(key_err)?,
            EdwardsCurve::Ed448   => PKey::generate_ed448().map_err(key_err)?,
        };
        let private_der = Zeroizing::new(pkey.private_key_to_pkcs8().map_err(key_err)?);
        let public_der  = pkey.public_key_to_der().map_err(key_err)?;
        let raw_pub     = pkey.raw_public_key().map_err(key_err)?;

        // EdDSA OIDs for CKA_EC_PARAMS
        let ec_params_der = match curve {
            // Ed25519: 1.3.101.112 → 06 03 2b 65 70
            EdwardsCurve::Ed25519 => vec![0x06, 0x03, 0x2b, 0x65, 0x70],
            // Ed448: 1.3.101.113 → 06 03 2b 65 71
            EdwardsCurve::Ed448   => vec![0x06, 0x03, 0x2b, 0x65, 0x71],
        };

        Ok(EdKeyPair {
            private_der,
            public_der,
            curve,
            ec_params_der,
            ec_point: raw_pub,
        })
    }

    fn eddsa_sign(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let pkey = PKey::private_key_from_pkcs8(key.as_bytes()).map_err(invalid_key_err)?;
        // EdDSA uses None for digest — the sign is done over the raw message
        let mut signer = Signer::new_without_digest(&pkey).map_err(sign_err)?;
        signer.sign_oneshot_to_vec(message).map_err(sign_err)
    }

    fn eddsa_verify(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let pkey = PKey::public_key_from_der(key.as_bytes()).map_err(invalid_key_err)?;
        let mut verifier = Verifier::new_without_digest(&pkey).map_err(verify_err)?;
        verifier.verify_oneshot(signature, message).map_err(verify_err)
    }

    fn ed_attribute(
        &self,
        key: &EngineKeyRef,
        is_private: bool,
        attr: AttributeType,
    ) -> Result<AttributeValue, CryptoError> {
        if is_private && matches!(attr, AttributeType::Value) {
            return Err(CryptoError::AttributeSensitive);
        }

        let key_der = key.as_bytes();
        let (key_id, raw_pub) = if is_private {
            let pkey = PKey::<Private>::private_key_from_pkcs8(key_der).map_err(invalid_key_err)?;
            let id = pkey.id();
            let raw = pkey.raw_public_key().map_err(invalid_key_err)?;
            (id, raw)
        } else {
            let pkey = PKey::<Public>::public_key_from_der(key_der).map_err(invalid_key_err)?;
            let id = pkey.id();
            let raw = pkey.raw_public_key().map_err(invalid_key_err)?;
            (id, raw)
        };

        let ec_params_der = match key_id {
            openssl::pkey::Id::ED25519 => vec![0x06, 0x03, 0x2b, 0x65, 0x70],
            openssl::pkey::Id::ED448   => vec![0x06, 0x03, 0x2b, 0x65, 0x71],
            _ => return Err(CryptoError::AttributeTypeInvalid),
        };

        match attr {
            AttributeType::EcParams => Ok(AttributeValue::Bytes(ec_params_der)),
            AttributeType::EcPoint  => Ok(AttributeValue::Bytes(der_octet_string(&raw_pub))),
            _ => Err(CryptoError::AttributeTypeInvalid),
        }
    }

    // ── ChaCha20-Poly1305 (v3.0) ────────────────────────────────────────────

    fn generate_chacha20_key(&self) -> Result<EngineKeyRef, CryptoError> {
        let mut buf = vec![0u8; 32]; // ChaCha20 always uses 256-bit keys
        rand_bytes(&mut buf).map_err(key_err)?;
        Ok(EngineKeyRef::from_bytes(buf))
    }

    fn chacha20_poly1305_encrypt(
        &self,
        key: &EngineKeyRef,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let key = key.as_bytes();
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize {
                message: format!("ChaCha20-Poly1305 key must be 32 bytes; got {}", key.len()),
            });
        }
        if nonce.len() != 12 {
            return Err(CryptoError::MechanismParamInvalid {
                message: format!("ChaCha20-Poly1305 nonce must be 12 bytes; got {}", nonce.len()),
            });
        }
        let cipher = Cipher::chacha20_poly1305();
        let mut tag = vec![0u8; 16];
        let ciphertext = encrypt_aead(cipher, key, Some(nonce), aad, plaintext, &mut tag)
            .map_err(encrypt_err)?;
        Ok((ciphertext, tag))
    }

    fn chacha20_poly1305_decrypt(
        &self,
        key: &EngineKeyRef,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let key = key.as_bytes();
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize {
                message: format!("ChaCha20-Poly1305 key must be 32 bytes; got {}", key.len()),
            });
        }
        let cipher = Cipher::chacha20_poly1305();
        decrypt_aead(cipher, key, Some(nonce), aad, ciphertext, tag)
            .map(Zeroizing::new)
            .map_err(decrypt_err)
    }

    // ── HKDF (v3.0) ─────────────────────────────────────────────────────────

    fn hkdf_derive(
        &self,
        hash_algo: HashAlgorithm,
        ikm: &EngineKeyRef,
        salt: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let ikm = ikm.as_bytes();
        use openssl::md::Md;
        use openssl::pkey_ctx::PkeyCtx;

        let md = match hash_algo {
            HashAlgorithm::Sha256   => Md::sha256(),
            HashAlgorithm::Sha384   => Md::sha384(),
            HashAlgorithm::Sha512   => Md::sha512(),
            HashAlgorithm::Sha1     => Md::sha1(),
            _ => return Err(CryptoError::MechanismInvalid { name: "HKDF: unsupported hash" }),
        };
        let gen_err = |e: openssl::error::ErrorStack| CryptoError::GeneralError { message: e.to_string() };
        let mut ctx = PkeyCtx::new_id(openssl::pkey::Id::HKDF).map_err(gen_err)?;
        ctx.derive_init().map_err(gen_err)?;
        ctx.set_hkdf_md(md).map_err(gen_err)?;
        ctx.set_hkdf_key(ikm).map_err(gen_err)?;
        ctx.set_hkdf_salt(salt).map_err(gen_err)?;
        ctx.add_hkdf_info(info).map_err(gen_err)?;
        let mut okm = Zeroizing::new(vec![0u8; okm_len]);
        ctx.derive(Some(&mut okm)).map_err(gen_err)?;
        Ok(okm)
    }

    // ── Key persistence ──────────────────────────────────────────────────

    fn serialize_key(&self, key: &EngineKeyRef) -> Result<Vec<u8>, CryptoError> {
        Ok(key.as_bytes().to_vec())
    }

    fn deserialize_key(&self, data: &[u8]) -> Result<EngineKeyRef, CryptoError> {
        Ok(EngineKeyRef::from_bytes(data.to_vec()))
    }

    // ── Mechanism capability reporting ────────────────────────────────────────

    /// Return actual OpenSSL capabilities for a given `CKM_*` mechanism.
    ///
    /// `min_key_size` / `max_key_size` follow the PKCS#11 convention:
    ///   - RSA / EC / EdDSA: key size **in bits**
    ///   - AES / ChaCha20:   key size **in bytes**
    ///   - Hash / HKDF:      0 (no key)
    ///
    /// The `flags` field uses `CKF_*` bit values from PKCS#11.
    /// The PKCS#11 layer may clamp `min_key_size` upward (e.g. RSA ≥ 2048)
    /// per the mechanism-tier policy in `mechanisms.rs`.
    fn mechanism_info(&self, _slot: usize, mechanism: u64) -> Option<EngineMechanismInfo> {
    const ENCRYPT:           u32 = 0x0000_0100;
    const DECRYPT:           u32 = 0x0000_0200;
    const DIGEST:            u32 = 0x0000_0400;
    const SIGN:              u32 = 0x0000_0800;
    const VERIFY:            u32 = 0x0000_2000;
    const GENERATE:          u32 = 0x0000_8000;
    const GENERATE_KEY_PAIR: u32 = 0x0001_0000;
    const WRAP:              u32 = 0x0002_0000;
    const UNWRAP:            u32 = 0x0004_0000;
    const DERIVE:            u32 = 0x0008_0000;

    Some(match mechanism {
        // ── RSA ──────────────────────────────────────────────────────────
        // CKM_RSA_PKCS_KEY_PAIR_GEN (0x0000)
        0x0000_0000 => EngineMechanismInfo {
            min_key_size: 1024,
            max_key_size: 16384,
            flags: GENERATE_KEY_PAIR,
        },
        // CKM_RSA_PKCS (0x0001)
        0x0000_0001 => EngineMechanismInfo {
            min_key_size: 1024,
            max_key_size: 16384,
            flags: ENCRYPT | DECRYPT | SIGN | VERIFY,
        },
        // CKM_RSA_PKCS_OAEP (0x0009)
        0x0000_0009 => EngineMechanismInfo {
            min_key_size: 1024,
            max_key_size: 16384,
            flags: ENCRYPT | DECRYPT | WRAP | UNWRAP,
        },
        // All RSA-PSS and SHA-RSA Mechanisms
        0x0000_000D | 0x0000_0006 | 0x0000_000E
        | 0x0000_0040 | 0x0000_0041 | 0x0000_0042
        | 0x0000_0043 | 0x0000_0044 | 0x0000_0045 => EngineMechanismInfo {
            min_key_size: 1024,
            max_key_size: 16384,
            flags: SIGN | VERIFY,
        },

        // ── EC (Weierstrass) ─────────────────────────────────────────────
        0x0000_1040 => EngineMechanismInfo {
            min_key_size: 256, max_key_size: 521,
            flags: GENERATE_KEY_PAIR,
        },
        0x0000_1041..=0x0000_1045 => EngineMechanismInfo {
            min_key_size: 256, max_key_size: 521,
            flags: SIGN | VERIFY,
        },
        0x0000_1050 => EngineMechanismInfo {
            min_key_size: 256, max_key_size: 521,
            flags: DERIVE,
        },

        // ── EdDSA ────────────────────────────────────────────────────────
        0x0000_1055 => EngineMechanismInfo {
            min_key_size: 255, max_key_size: 448,
            flags: GENERATE_KEY_PAIR,
        },
        0x0000_1057 => EngineMechanismInfo {
            min_key_size: 255, max_key_size: 448,
            flags: SIGN | VERIFY,
        },

        // ── AES ────────────────────────────────────────────────────────
        0x0000_1080 => EngineMechanismInfo {
            min_key_size: 16, max_key_size: 32,
            flags: GENERATE,
        },
        0x0000_0120 | 0x0000_0131 => EngineMechanismInfo {
            min_key_size: 8, max_key_size: 24,
            flags: GENERATE,
        },
        0x0000_1082 | 0x0000_1085 | 0x0000_1086 | 0x0000_1087 => EngineMechanismInfo {
            min_key_size: 16, max_key_size: 32,
            flags: ENCRYPT | DECRYPT,
        },
        0x0000_0121 | 0x0000_0122 | 0x0000_0132 | 0x0000_0133 => EngineMechanismInfo {
            min_key_size: 8, max_key_size: 24,
            flags: ENCRYPT | DECRYPT,
        },
        0x0000_1090 => EngineMechanismInfo {
            min_key_size: 16, max_key_size: 32,
            flags: WRAP | UNWRAP,
        },

        // ── ChaCha20 ────────────────────────────────────────────────────────
        0x0000_4021 => EngineMechanismInfo {
            min_key_size: 32, max_key_size: 32,
            flags: ENCRYPT | DECRYPT,
        },
        0x0000_4022 => EngineMechanismInfo {
            min_key_size: 32, max_key_size: 32,
            flags: GENERATE,
        },

        // ── Hashing ────────────────────────────────────────────────────────
        0x0000_0210 | 0x0000_0220
        | 0x0000_0250 | 0x0000_0260 | 0x0000_0270
        | 0x0000_02B0 | 0x0000_02C0 | 0x0000_02D0 => EngineMechanismInfo {
            min_key_size: 0, max_key_size: 0,
            flags: DIGEST,
        },

        // ── HKDF ────────────────────────────────────────────────────────
        0x0000_402A => EngineMechanismInfo {
            min_key_size: 0, max_key_size: 0,
            flags: DERIVE,
        },
        0x0000_402C => EngineMechanismInfo {
            min_key_size: 0, max_key_size: 0,
            flags: GENERATE,
        },
        // CKM_GENERIC_SECRET_KEY_GEN (0x0350)
        0x0000_0350 => EngineMechanismInfo {
            min_key_size: 1,
            max_key_size: 4096,
            flags: GENERATE,
        },

        _ => return None,
    })
}
}

// ── Private EC helpers ────────────────────────────────────────────────────────

/// Return the DER-encoded OID for a named curve (CKA_EC_PARAMS).
fn ec_params_for_group(group: &openssl::ec::EcGroupRef) -> Result<Vec<u8>, CryptoError> {
    let nid = group.curve_name().ok_or(CryptoError::GeneralError {
        message: "EC group has no named curve NID".into(),
    })?;
    match nid {
        Nid::X9_62_PRIME256V1 =>
            Ok(vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        Nid::SECP384R1 =>
            Ok(vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
        Nid::SECP521R1 =>
            Ok(vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]),
        _other => Err(CryptoError::MechanismInvalid {
            name: "unsupported EC curve",
        }),
    }
}

/// Return a DER OCTET STRING wrapping the uncompressed EC public key point (CKA_EC_POINT).
fn ec_point_for_key<T: openssl::pkey::HasPublic>(
    ec_key: &EcKey<T>,
) -> Result<Vec<u8>, CryptoError> {
    let mut ctx = BigNumContext::new()
        .map_err(|e| CryptoError::GeneralError { message: e.to_string() })?;
    let bytes = ec_key
        .public_key()
        .to_bytes(ec_key.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|e| CryptoError::GeneralError { message: e.to_string() })?;
    Ok(der_octet_string(&bytes))
}
