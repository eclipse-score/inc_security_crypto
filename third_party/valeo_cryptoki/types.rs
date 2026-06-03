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

use zeroize::Zeroizing;

/// An RSA key pair with pre-parsed attribute fields.
///
/// Both DER fields use standard encodings that every crypto library understands:
///   - `private_der` — PKCS#8 `PrivateKeyInfo` (RFC 5958)
///   - `public_der`  — `SubjectPublicKeyInfo` (RFC 5480 / X.509)
///
/// The pre-parsed fields (`bits`, `modulus`, `public_exponent`) allow the
/// PKCS#11 layer to answer `C_GetAttributeValue` for common read-only attributes
/// without round-tripping through the engine's `rsa_attribute` method on every call.
///
/// # PKCS#11 attribute mapping
/// | Field              | CKA_*                    |
/// |--------------------|--------------------------|
/// | `private_der`      | CKA_VALUE (sensitive)    |
/// | `public_der`       | (SubjectPublicKeyInfo)   |
/// | `bits`             | CKA_MODULUS_BITS         |
/// | `modulus`          | CKA_MODULUS              |
/// | `public_exponent`  | CKA_PUBLIC_EXPONENT      |
#[derive(Clone)]
pub struct RsaKeyPair {
    /// PKCS#8 PrivateKeyInfo DER — corresponds to CKA_VALUE on the private-key object.
    /// Marked sensitive; the PKCS#11 layer must not expose it unless CKA_EXTRACTABLE is true.
    /// Wrapped in `Zeroizing` to ensure secure erasure on drop.
    pub private_der: Zeroizing<Vec<u8>>,
    /// SubjectPublicKeyInfo DER — the public half.
    pub public_der: Vec<u8>,
    /// Modulus bit length (e.g. 2048, 4096). Corresponds to CKA_MODULUS_BITS.
    pub bits: u32,
    /// RSA modulus `n` in big-endian bytes. Corresponds to CKA_MODULUS.
    pub modulus: Vec<u8>,
    /// RSA public exponent `e` in big-endian bytes. Corresponds to CKA_PUBLIC_EXPONENT.
    pub public_exponent: Vec<u8>,
}

/// An EC key pair with pre-parsed attribute fields.
///
/// | Field                    | CKA_*                    |
/// |--------------------------|--------------------------|
/// | `private_der`            | CKA_VALUE (sensitive)    |
/// | `public_der`             | (SubjectPublicKeyInfo)   |
/// | `curve`                  | (engine-internal)        |
/// | `ec_params_der`          | CKA_EC_PARAMS            |
/// | `ec_point_uncompressed`  | CKA_EC_POINT             |
#[derive(Clone)]
pub struct EcKeyPair {
    /// PKCS#8 PrivateKeyInfo DER. Wrapped in `Zeroizing` for secure erasure on drop.
    pub private_der: Zeroizing<Vec<u8>>,
    /// SubjectPublicKeyInfo DER.
    pub public_der: Vec<u8>,
    /// Which named curve was used.
    pub curve: EcCurve,
    /// DER-encoded OID of the curve — CKA_EC_PARAMS.
    /// For P-256: `06 08 2a 86 48 ce 3d 03 01 07`.
    pub ec_params_der: Vec<u8>,
    /// DER OCTET STRING wrapping the uncompressed point (0x04 || x || y).
    /// Corresponds to CKA_EC_POINT.
    pub ec_point_uncompressed: Vec<u8>,
}

/// Named elliptic curves supported by the abstraction layer.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcCurve {
    /// P-256 / secp256r1 / prime256v1.
    P256,
    /// P-384 / secp384r1.
    P384,
    /// P-521 / secp521r1.
    P521,
}

/// Edwards curves for EdDSA (v3.0).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdwardsCurve {
    /// Ed25519 — RFC 8032.
    Ed25519,
    /// Ed448 — RFC 8032.
    Ed448,
}

/// EdDSA key pair returned by the engine.
#[derive(Clone)]
pub struct EdKeyPair {
    /// PKCS#8 PrivateKeyInfo DER. Wrapped in `Zeroizing` for secure erasure on drop.
    pub private_der: Zeroizing<Vec<u8>>,
    /// SubjectPublicKeyInfo DER.
    pub public_der: Vec<u8>,
    /// Which Edwards curve was used.
    pub curve: EdwardsCurve,
    /// DER-encoded OID of the curve — CKA_EC_PARAMS.
    pub ec_params_der: Vec<u8>,
    /// Raw public key bytes (32 for Ed25519, 57 for Ed448).
    pub ec_point: Vec<u8>,
}

/// Hash algorithms supported by the engine.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashAlgorithm {
    /// Digest output length in bytes.
    pub fn digest_len(self) -> usize {
        match self {
            HashAlgorithm::Md5      => 16,
            HashAlgorithm::Sha1     => 20,
            HashAlgorithm::Sha256   => 32,
            HashAlgorithm::Sha384   => 48,
            HashAlgorithm::Sha512   => 64,
            HashAlgorithm::Sha3_256 => 32,
            HashAlgorithm::Sha3_384 => 48,
            HashAlgorithm::Sha3_512 => 64,
        }
    }
}
