// *******************************************************************************
// Copyright (c) 2026 Contributors to the Eclipse Foundation
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

use zeroize::Zeroizing;

use crate::attributes::{AttributeType, AttributeValue};
use crate::error::CryptoError;
use crate::types::{EcCurve, EcKeyPair, EdKeyPair, EdwardsCurve, HashAlgorithm, RsaKeyPair};

// ── EngineKeyRef ────────────────────────────────────────────────────────────

/// Opaque key reference passed between the PKCS#11 layer and the engine.
///
/// For software engines (e.g. OpenSSL) this wraps DER-encoded key bytes.
/// For HSM/TPM/TEE backends the inner bytes could be a handle or label
/// rather than extractable key material.  The PKCS#11 layer never
/// interprets the contents — it just stores, clones, and passes them back.
#[derive(Debug, Clone)]
pub struct EngineKeyRef {
    inner: Zeroizing<Vec<u8>>,
}

impl EngineKeyRef {
    /// Construct from raw bytes (DER, handle, etc.).
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self {
            inner: Zeroizing::new(b),
        }
    }

    /// View the inner bytes. Only the engine should call this.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

// ── EngineMechanismInfo ─────────────────────────────────────────────────────

/// Per-mechanism capability descriptor returned by
/// [`CryptoProvider::mechanism_info`].
///
/// Fields mirror `CK_MECHANISM_INFO`.  The PKCS#11 layer
/// applies additional policy constraints on top (e.g. clamping RSA
/// `min_key_size` to 2048).
#[derive(Debug, Clone, Copy)]
pub struct EngineMechanismInfo {
    /// Smallest key size (in bits) supported by this mechanism on this slot.
    pub min_key_size: u32,
    /// Largest key size (in bits) supported by this mechanism on this slot.
    pub max_key_size: u32,
    /// `CKF_*` capability flags (e.g. `CKF_SIGN | CKF_VERIFY`).
    pub flags: u32,
}

/// A stateful, streaming hash context for multi-part digest operations.
pub trait StreamHasher: Send {
    /// Feed the next chunk into the running hash state.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;
    /// Finalise and return the digest bytes; consumes the hasher.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, CryptoError>;
}

/// Engine trait — all crypto operations go through here.
///
/// Key material is represented by [`EngineKeyRef`], an opaque wrapper that
/// the PKCS#11 layer stores but never interprets.  The engine creates refs
/// during key generation or deserialization and consumes them in crypto ops.
///
/// ## Multi-slot model
///
/// An engine can expose one or more **slots** (default: 1).  When an engine
/// is registered via [`register_engine`](crate::registry::register_engine),
/// the registry assigns sequential **global** slot IDs (what the application
/// sees) and maps each to the engine plus an **internal** slot index
/// (0-based, what the engine sees).
///
/// ```text
///   SoftEngine.slot_count() == 1  →  global 0  ↔  internal 0
///   HsmEngine.slot_count()  == 3  →  global 1  ↔  internal 0
///                            global 2  ↔  internal 1
///                            global 3  ↔  internal 2
/// ```
///
/// Slot-aware query methods (`slot_description`, `token_model`,
/// `supported_mechanisms`) receive the **internal** slot index so the engine
/// can return per-partition information.  Stateless crypto methods (signing,
/// encryption, …) are slot-agnostic — they operate purely on key refs.
pub trait CryptoProvider: Send + Sync {
    // ── Slot / capability discovery ─────────────────────────────────────

    /// How many virtual slots this engine provides.  Default: 1.
    ///
    /// Called once during [`register_engine`](crate::registry::register_engine)
    /// to allocate global slot IDs.
    fn slot_count(&self) -> usize {
        1
    }

    /// Human-readable slot description (≤64 UTF-8 bytes, space-padded by caller).
    ///
    /// `internal_slot_id` is the engine's own 0-based slot index (not the
    /// global ID the application uses).
    fn slot_description(&self, _internal_slot_id: u64) -> &str {
        "Virtual Slot"
    }

    /// Human-readable token model string (≤16 UTF-8 bytes).
    ///
    /// `internal_slot_id` is the engine's own 0-based slot index.
    fn token_model(&self, _internal_slot_id: u64) -> &str {
        "SoftToken"
    }

    /// The set of `CKM_*` mechanism types this engine supports on the given slot.
    ///
    /// `internal_slot_id` is the engine's own 0-based slot index.
    /// Default returns an empty slice — the PKCS#11 layer falls back to the
    /// global `SUPPORTED_MECHANISMS` list when this is empty (backward compat).
    fn supported_mechanisms(&self, _internal_slot_id: u64) -> &[u64] {
        &[]
    }

    /// Return capability information for one mechanism on one slot.
    ///
    /// `slot` is the engine's own 0-based internal slot index.
    /// `mechanism` is a `CKM_*` constant (underlying type `u64`).
    ///
    /// Returns `None` when the engine has no opinion — the PKCS#11 layer
    /// falls back to its built-in hardcoded table in that case.
    ///
    /// Default: always returns `None` (backward-compatible for engines that
    /// have not yet implemented per-mechanism capability reporting).
    fn mechanism_info(&self, _slot: usize, _mechanism: u64) -> Option<EngineMechanismInfo> {
        None
    }

    /// Called in the child process immediately after `fork(2)`.
    ///
    /// Engines that hold state that must not be shared between parent and
    /// child (e.g. hardware session handles, connection pools) should reset
    /// that state here.  Software engines that are stateless can rely on
    /// the default no-op implementation.
    fn post_fork_child(&self) {}

    // ── Key generation ────────────────────────────────────────────────────

    /// Generate an RSA key pair (`bits` ≥ 2048, public exponent fixed at 65537).
    fn generate_rsa_key_pair(&self, bits: u32) -> Result<RsaKeyPair, CryptoError>;
    /// Generate an EC key pair on the given named curve.
    fn generate_ec_key_pair(&self, curve: EcCurve) -> Result<EcKeyPair, CryptoError>;
    /// Generate an AES key of `len` bytes (16, 24, or 32).
    fn generate_aes_key(&self, len: usize) -> Result<EngineKeyRef, CryptoError>;

    // ── Random ────────────────────────────────────────────────────────────

    /// Fill `buf` with CSPRNG bytes.
    fn generate_random(&self, buf: &mut [u8]) -> Result<(), CryptoError>;

    // ── AES ───────────────────────────────────────────────────────────────

    /// AES-CBC encrypt with PKCS#7 padding. `iv`: 16 bytes.
    fn aes_cbc_encrypt(&self, key: &EngineKeyRef, iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// AES-CBC decrypt, stripping PKCS#7 padding.
    fn aes_cbc_decrypt(
        &self,
        key: &EngineKeyRef,
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
    /// AES-CTR encrypt/decrypt (symmetric XOR with keystream). `iv`: 16-byte counter block.
    fn aes_ctr_crypt(&self, key: &EngineKeyRef, iv: &[u8], input: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// AES-GCM authenticated encrypt. Returns `(ciphertext, 16-byte tag)`.
    fn aes_gcm_encrypt(
        &self,
        key: &EngineKeyRef,
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;
    /// AES-GCM authenticated decrypt. `tag` must be 16 bytes.
    fn aes_gcm_decrypt(
        &self,
        key: &EngineKeyRef,
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    // ── RSA encryption ────────────────────────────────────────────────────

    /// RSA PKCS#1 v1.5 encrypt.
    fn rsa_pkcs1_encrypt(&self, key: &EngineKeyRef, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// RSA PKCS#1 v1.5 decrypt.
    fn rsa_pkcs1_decrypt(&self, key: &EngineKeyRef, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
    /// RSA-OAEP encrypt (SHA-1, MGF1-SHA-1, empty label).
    fn rsa_oaep_encrypt(&self, key: &EngineKeyRef, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// RSA-OAEP decrypt.
    fn rsa_oaep_decrypt(&self, key: &EngineKeyRef, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    // ── Signing / Verification ────────────────────────────────────────────

    /// RSA PKCS#1 v1.5 sign (SHA-256 hash computed internally).
    fn rsa_pkcs1_sign(&self, key: &EngineKeyRef, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// RSA PKCS#1 v1.5 verify. Returns `true` if signature is valid.
    fn rsa_pkcs1_verify(&self, key: &EngineKeyRef, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
    /// RSA-PSS sign (SHA-256, MGF1-SHA-256, salt = 32 bytes).
    fn rsa_pss_sign(&self, key: &EngineKeyRef, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// RSA-PSS verify.
    fn rsa_pss_verify(&self, key: &EngineKeyRef, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
    /// ECDSA sign over P-256 (SHA-256 hash computed internally). Returns DER `(r, s)`.
    fn ecdsa_sign(&self, key: &EngineKeyRef, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// ECDSA verify. `signature` must be DER-encoded `(r, s)`.
    fn ecdsa_verify(&self, key: &EngineKeyRef, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
    /// ECDSA sign over a **pre-computed** digest. The caller is responsible
    /// for hashing `message` with the appropriate algorithm before calling
    /// this method.  Returns a DER-encoded `(r, s)` signature.
    ///
    /// This is the primitive used by the ECDSA dispatch in `backend.rs`
    /// `CKM_ECDSA_SHA256/384/512` each hash the message, then call
    /// this once with the resulting digest bytes.
    ///
    /// Default: returns [`CryptoError::MechanismInvalid`] so that engines
    /// that only implement `ecdsa_sign` continue to compile without changes.
    fn ecdsa_sign_prehashed(&self, key: &EngineKeyRef, digest: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let _ = (key, digest);
        Err(CryptoError::MechanismInvalid {
            name: "ecdsa_sign_prehashed not implemented",
        })
    }
    /// ECDSA verify against a **pre-computed** digest. The caller is responsible
    /// for hashing the message before calling this method.
    ///
    /// Default: returns [`CryptoError::MechanismInvalid`].
    fn ecdsa_verify_prehashed(&self, key: &EngineKeyRef, digest: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let _ = (key, digest, signature);
        Err(CryptoError::MechanismInvalid {
            name: "ecdsa_verify_prehashed not implemented",
        })
    }

    // ── Hashing ───────────────────────────────────────────────────────────

    /// Single-part (one-shot) hash.
    fn hash(&self, algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Create a streaming hash context for multi-part digesting.
    fn new_stream_hasher(&self, algorithm: HashAlgorithm) -> Result<Box<dyn StreamHasher>, CryptoError>;

    // ── EdDSA (v3.0) ──────────────────────────────────────────────────────

    /// Generate an EdDSA key pair (Ed25519 or Ed448).
    fn generate_ed_key_pair(&self, curve: EdwardsCurve) -> Result<EdKeyPair, CryptoError>;
    /// EdDSA sign (pure mode, no prehash). Returns raw signature bytes.
    fn eddsa_sign(&self, key: &EngineKeyRef, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// EdDSA verify. Returns `true` if signature is valid.
    fn eddsa_verify(&self, key: &EngineKeyRef, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;

    // ── HMAC ─────────────────────────────────────────────────────────────

    fn hmac_sign(&self, _algorithm: HashAlgorithm, _key: &EngineKeyRef, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::MechanismInvalid {
            name: "hmac_sign not supported",
        })
    }

    fn hmac_verify(
        &self,
        _algorithm: HashAlgorithm,
        _key: &EngineKeyRef,
        _data: &[u8],
        _mac: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::MechanismInvalid {
            name: "hmac_verify not supported",
        })
    }

    // ── ChaCha20-Poly1305 (v3.0) ────────────────────────────────────────

    /// Generate a 256-bit ChaCha20 key.
    fn generate_chacha20_key(&self) -> Result<EngineKeyRef, CryptoError>;
    /// ChaCha20-Poly1305 AEAD encrypt. Returns `(ciphertext, 16-byte tag)`.
    fn chacha20_poly1305_encrypt(
        &self,
        key: &EngineKeyRef,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;
    /// ChaCha20-Poly1305 AEAD decrypt.
    fn chacha20_poly1305_decrypt(
        &self,
        key: &EngineKeyRef,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    // ── HKDF (v3.0) ─────────────────────────────────────────────────────

    /// HKDF-Extract + HKDF-Expand. Returns derived key material of `okm_len` bytes.
    fn hkdf_derive(
        &self,
        hash: HashAlgorithm,
        ikm: &EngineKeyRef,
        salt: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    // ── Hash-parameterized RSA signing (v2.40 SHA-384/512 + v3.0) ─────

    /// RSA PKCS#1 v1.5 sign with caller-chosen hash.
    fn rsa_pkcs1_sign_hash(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        hash: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let _ = (key, message, hash);
        Err(CryptoError::MechanismInvalid {
            name: "rsa_pkcs1_sign_hash not implemented",
        })
    }
    /// RSA PKCS#1 v1.5 verify with caller-chosen hash.
    fn rsa_pkcs1_verify_hash(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        signature: &[u8],
        hash: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let _ = (key, message, signature, hash);
        Err(CryptoError::MechanismInvalid {
            name: "rsa_pkcs1_verify_hash not implemented",
        })
    }
    /// RSA-PSS sign with caller-chosen hash.
    fn rsa_pss_sign_hash(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        hash: HashAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let _ = (key, message, hash);
        Err(CryptoError::MechanismInvalid {
            name: "rsa_pss_sign_hash not implemented",
        })
    }
    /// RSA-PSS verify with caller-chosen hash.
    fn rsa_pss_verify_hash(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        signature: &[u8],
        hash: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let _ = (key, message, signature, hash);
        Err(CryptoError::MechanismInvalid {
            name: "rsa_pss_verify_hash not implemented",
        })
    }
    /// ECDSA sign with caller-chosen hash.
    fn ecdsa_sign_hash(&self, key: &EngineKeyRef, message: &[u8], hash: HashAlgorithm) -> Result<Vec<u8>, CryptoError> {
        let _ = (key, message, hash);
        Err(CryptoError::MechanismInvalid {
            name: "ecdsa_sign_hash not implemented",
        })
    }
    /// ECDSA verify with caller-chosen hash.
    fn ecdsa_verify_hash(
        &self,
        key: &EngineKeyRef,
        message: &[u8],
        signature: &[u8],
        hash: HashAlgorithm,
    ) -> Result<bool, CryptoError> {
        let _ = (key, message, signature, hash);
        Err(CryptoError::MechanismInvalid {
            name: "ecdsa_verify_hash not implemented",
        })
    }

    // ── AES Key Wrap (RFC 3394) ─────────────────────────────────────────

    /// AES Key Wrap (encrypt). Returns wrapped key bytes.
    fn aes_key_wrap(&self, kek: &EngineKeyRef, plaintext_key: &EngineKeyRef) -> Result<Vec<u8>, CryptoError> {
        let _ = (kek, plaintext_key);
        Err(CryptoError::MechanismInvalid {
            name: "aes_key_wrap not implemented",
        })
    }
    /// AES Key Unwrap (decrypt). Returns unwrapped key bytes.
    fn aes_key_unwrap(&self, kek: &EngineKeyRef, wrapped_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let _ = (kek, wrapped_key);
        Err(CryptoError::MechanismInvalid {
            name: "aes_key_unwrap not implemented",
        })
    }

    /// Return the raw key value bytes to be fed into `C_DigestKey`.
    ///
    /// For software engines: returns the secret key bytes directly.
    /// For HSM/TEE engines: extract via the HSM if the key policy permits it,
    /// or return `Err` to surface `CKR_KEY_INDIGESTIBLE` to the caller.
    ///
    /// Default: returns `Err` — engines must explicitly opt in.  This is the
    /// fail-safe for opaque backends where `as_bytes()` yields a handle token,
    /// not extractable key material.
    fn key_value_for_digest(&self, key_ref: &EngineKeyRef) -> Result<Vec<u8>, CryptoError> {
        let _ = key_ref;
        Err(CryptoError::MechanismInvalid {
            name: "key_value_for_digest not supported",
        })
    }

    // ── Attribute access ──────────────────────────────────────────────────

    /// Return a crypto-derived attribute for an RSA key (modulus, bits, exponent, etc.).
    fn rsa_attribute(
        &self,
        key: &EngineKeyRef,
        is_private: bool,
        attr: AttributeType,
    ) -> Result<AttributeValue, CryptoError>;
    /// Return a crypto-derived attribute for an EC key (ec_params, ec_point, etc.).
    fn ec_attribute(
        &self,
        key: &EngineKeyRef,
        is_private: bool,
        attr: AttributeType,
    ) -> Result<AttributeValue, CryptoError>;
    /// Return a crypto-derived attribute for an AES key (value_len, value).
    fn aes_attribute(&self, key: &EngineKeyRef, attr: AttributeType) -> Result<AttributeValue, CryptoError>;
    /// Return a crypto-derived attribute for an EdDSA key (ec_params, ec_point, etc.).
    fn ed_attribute(
        &self,
        _key: &EngineKeyRef,
        _is_private: bool,
        _attr: AttributeType,
    ) -> Result<AttributeValue, CryptoError> {
        Err(CryptoError::AttributeTypeInvalid)
    }

    // ── Key persistence ──────────────────────────────────────────────────

    /// Serialize an opaque key ref to bytes for persistent storage.
    fn serialize_key(&self, key: &EngineKeyRef) -> Result<Vec<u8>, CryptoError>;
    /// Reconstruct an opaque key ref from previously serialized bytes.
    fn deserialize_key(&self, data: &[u8]) -> Result<EngineKeyRef, CryptoError>;
}
