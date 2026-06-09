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
use super::*;

pub fn key_value_for_digest(slot_id: CK_SLOT_ID, key: &KeyObject) -> Result<Vec<u8>> {
    eng(slot_id)?.key_value_for_digest(&key.key_ref).map_err(Pkcs11Error::from)
}

pub fn digest(slot_id: CK_SLOT_ID, mechanism: CK_MECHANISM_TYPE, data: &[u8]) -> Result<Vec<u8>> {
    debug!(context: "BACKEND", "Digest: slot={} mechanism={} len={}", slot_id, mechanism, data.len());
    let e = eng(slot_id)?;
    let alg = mechanism_to_hash_algorithm(mechanism)?;
    e.hash(alg, data).map_err(Pkcs11Error::from)
}

pub fn generate_random(slot_id: CK_SLOT_ID, buf: &mut [u8]) -> Result<()> {
    debug!(context: "BACKEND", "Generate random: slot={} len={}", slot_id, buf.len());
    let e = eng(slot_id)?;
    e.generate_random(buf).map_err(Pkcs11Error::from)
}

fn mechanism_to_hash_algorithm(mechanism: CK_MECHANISM_TYPE) -> Result<crate::types::HashAlgorithm> {
    use crate::types::HashAlgorithm;
    match mechanism {
        CKM_MD5 => Ok(HashAlgorithm::Md5),
        CKM_SHA_1 => Ok(HashAlgorithm::Sha1),
        CKM_SHA256 => Ok(HashAlgorithm::Sha256),
        CKM_SHA384 => Ok(HashAlgorithm::Sha384),
        CKM_SHA512 => Ok(HashAlgorithm::Sha512),
        CKM_SHA3_256 => Ok(HashAlgorithm::Sha3_256),
        CKM_SHA3_384 => Ok(HashAlgorithm::Sha3_384),
        CKM_SHA3_512 => Ok(HashAlgorithm::Sha3_512),
        _ => Err(Pkcs11Error::InvalidMechanism),
    }
}
