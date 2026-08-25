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
use super::*;

pub fn sign(slot_id: CK_SLOT_ID, mechanism: CK_MECHANISM_TYPE, key: &KeyObject, data: &[u8]) -> Result<Vec<u8>> {
    debug!(context: "BACKEND", "Signing: slot={} mechanism={} key_handle={} data_len={}", slot_id, mechanism, key.handle, data.len());
    let e = eng(slot_id)?;
    match key.key_type {
        KeyType::RsaPrivate => match mechanism {
            CKM_RSA_PKCS => e.rsa_pkcs1_sign(&key.key_ref, data).map_err(Pkcs11Error::from),
            CKM_MD5_RSA_PKCS => e
                .rsa_pkcs1_sign_hash(&key.key_ref, data, crate::types::HashAlgorithm::Md5)
                .map_err(Pkcs11Error::from),
            CKM_SHA1_RSA_PKCS => e
                .rsa_pkcs1_sign_hash(&key.key_ref, data, crate::types::HashAlgorithm::Sha1)
                .map_err(Pkcs11Error::from),
            CKM_SHA256_RSA_PKCS => e.rsa_pkcs1_sign(&key.key_ref, data).map_err(Pkcs11Error::from),
            CKM_SHA384_RSA_PKCS => e
                .rsa_pkcs1_sign_hash(&key.key_ref, data, crate::types::HashAlgorithm::Sha384)
                .map_err(Pkcs11Error::from),
            CKM_SHA512_RSA_PKCS => e
                .rsa_pkcs1_sign_hash(&key.key_ref, data, crate::types::HashAlgorithm::Sha512)
                .map_err(Pkcs11Error::from),
            CKM_SHA256_RSA_PKCS_PSS => e.rsa_pss_sign(&key.key_ref, data).map_err(Pkcs11Error::from),
            CKM_SHA384_RSA_PKCS_PSS => e
                .rsa_pss_sign_hash(&key.key_ref, data, crate::types::HashAlgorithm::Sha384)
                .map_err(Pkcs11Error::from),
            CKM_SHA512_RSA_PKCS_PSS => e
                .rsa_pss_sign_hash(&key.key_ref, data, crate::types::HashAlgorithm::Sha512)
                .map_err(Pkcs11Error::from),
            _ => Err(Pkcs11Error::InvalidMechanism),
        },
        KeyType::EcPrivate => match mechanism {
            CKM_ECDSA => e.ecdsa_sign_prehashed(&key.key_ref, data).map_err(Pkcs11Error::from),
            CKM_ECDSA_SHA256 => {
                let digest = e
                    .hash(crate::types::HashAlgorithm::Sha256, data)
                    .map_err(Pkcs11Error::from)?;
                e.ecdsa_sign_prehashed(&key.key_ref, &digest).map_err(Pkcs11Error::from)
            },
            CKM_ECDSA_SHA384 => {
                let digest = e
                    .hash(crate::types::HashAlgorithm::Sha384, data)
                    .map_err(Pkcs11Error::from)?;
                e.ecdsa_sign_prehashed(&key.key_ref, &digest).map_err(Pkcs11Error::from)
            },
            CKM_ECDSA_SHA512 => {
                let digest = e
                    .hash(crate::types::HashAlgorithm::Sha512, data)
                    .map_err(Pkcs11Error::from)?;
                e.ecdsa_sign_prehashed(&key.key_ref, &digest).map_err(Pkcs11Error::from)
            },
            _ => Err(Pkcs11Error::InvalidMechanism),
        },
        KeyType::EdPrivate => match mechanism {
            CKM_EDDSA => e.eddsa_sign(&key.key_ref, data).map_err(Pkcs11Error::from),
            _ => Err(Pkcs11Error::InvalidMechanism),
        },
        KeyType::GenericSecret => match mechanism {
            CKM_SHA256_HMAC => e
                .hmac_sign(crate::types::HashAlgorithm::Sha256, &key.key_ref, data)
                .map_err(Pkcs11Error::from),
            CKM_SHA384_HMAC => e
                .hmac_sign(crate::types::HashAlgorithm::Sha384, &key.key_ref, data)
                .map_err(Pkcs11Error::from),
            CKM_SHA512_HMAC => e
                .hmac_sign(crate::types::HashAlgorithm::Sha512, &key.key_ref, data)
                .map_err(Pkcs11Error::from),
            _ => Err(Pkcs11Error::InvalidMechanism),
        },
        _ => Err(Pkcs11Error::KeyTypeInconsistent),
    }
}

pub fn verify(
    slot_id: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    key: &KeyObject,
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    debug!(context: "BACKEND", "Verifying: slot={} mechanism={} key_handle={} data_len={} sig_len={}", slot_id, mechanism, key.handle, data.len(), signature.len());
    let e = eng(slot_id)?;
    let ok = match key.key_type {
        KeyType::RsaPublic => match mechanism {
            CKM_RSA_PKCS => e
                .rsa_pkcs1_verify(&key.key_ref, data, signature)
                .map_err(Pkcs11Error::from)?,
            CKM_MD5_RSA_PKCS => e
                .rsa_pkcs1_verify_hash(&key.key_ref, data, signature, crate::types::HashAlgorithm::Md5)
                .map_err(Pkcs11Error::from)?,
            CKM_SHA1_RSA_PKCS => e
                .rsa_pkcs1_verify_hash(&key.key_ref, data, signature, crate::types::HashAlgorithm::Sha1)
                .map_err(Pkcs11Error::from)?,
            CKM_SHA256_RSA_PKCS => e
                .rsa_pkcs1_verify(&key.key_ref, data, signature)
                .map_err(Pkcs11Error::from)?,
            CKM_SHA384_RSA_PKCS => e
                .rsa_pkcs1_verify_hash(&key.key_ref, data, signature, crate::types::HashAlgorithm::Sha384)
                .map_err(Pkcs11Error::from)?,
            CKM_SHA512_RSA_PKCS => e
                .rsa_pkcs1_verify_hash(&key.key_ref, data, signature, crate::types::HashAlgorithm::Sha512)
                .map_err(Pkcs11Error::from)?,
            CKM_SHA256_RSA_PKCS_PSS => e
                .rsa_pss_verify(&key.key_ref, data, signature)
                .map_err(Pkcs11Error::from)?,
            CKM_SHA384_RSA_PKCS_PSS => e
                .rsa_pss_verify_hash(&key.key_ref, data, signature, crate::types::HashAlgorithm::Sha384)
                .map_err(Pkcs11Error::from)?,
            CKM_SHA512_RSA_PKCS_PSS => e
                .rsa_pss_verify_hash(&key.key_ref, data, signature, crate::types::HashAlgorithm::Sha512)
                .map_err(Pkcs11Error::from)?,
            _ => return Err(Pkcs11Error::InvalidMechanism),
        },
        KeyType::EcPublic => match mechanism {
            CKM_ECDSA => e
                .ecdsa_verify_prehashed(&key.key_ref, data, signature)
                .map_err(Pkcs11Error::from)?,
            CKM_ECDSA_SHA256 => {
                let digest = e
                    .hash(crate::types::HashAlgorithm::Sha256, data)
                    .map_err(Pkcs11Error::from)?;
                e.ecdsa_verify_prehashed(&key.key_ref, &digest, signature)
                    .map_err(Pkcs11Error::from)?
            },
            CKM_ECDSA_SHA384 => {
                let digest = e
                    .hash(crate::types::HashAlgorithm::Sha384, data)
                    .map_err(Pkcs11Error::from)?;
                e.ecdsa_verify_prehashed(&key.key_ref, &digest, signature)
                    .map_err(Pkcs11Error::from)?
            },
            CKM_ECDSA_SHA512 => {
                let digest = e
                    .hash(crate::types::HashAlgorithm::Sha512, data)
                    .map_err(Pkcs11Error::from)?;
                e.ecdsa_verify_prehashed(&key.key_ref, &digest, signature)
                    .map_err(Pkcs11Error::from)?
            },
            _ => return Err(Pkcs11Error::InvalidMechanism),
        },
        KeyType::EdPublic => match mechanism {
            CKM_EDDSA => e
                .eddsa_verify(&key.key_ref, data, signature)
                .map_err(Pkcs11Error::from)?,
            _ => return Err(Pkcs11Error::InvalidMechanism),
        },
        KeyType::GenericSecret => match mechanism {
            CKM_SHA256_HMAC => e
                .hmac_verify(crate::types::HashAlgorithm::Sha256, &key.key_ref, data, signature)
                .map_err(Pkcs11Error::from)?,
            CKM_SHA384_HMAC => e
                .hmac_verify(crate::types::HashAlgorithm::Sha384, &key.key_ref, data, signature)
                .map_err(Pkcs11Error::from)?,
            CKM_SHA512_HMAC => e
                .hmac_verify(crate::types::HashAlgorithm::Sha512, &key.key_ref, data, signature)
                .map_err(Pkcs11Error::from)?,
            _ => return Err(Pkcs11Error::InvalidMechanism),
        },
        _ => return Err(Pkcs11Error::KeyTypeInconsistent),
    };

    if ok {
        Ok(())
    } else {
        Err(Pkcs11Error::SignatureInvalid)
    }
}
