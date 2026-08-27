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
use crate::types::{EcCurve, EdwardsCurve};

pub fn generate_rsa_key_pair(
    slot_id: CK_SLOT_ID,
    modulus_bits: u32,
    _pub_exponent: u32,
    pub_template: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
    priv_template: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
) -> Result<(GeneratedKey, GeneratedKey)> {
    debug!(context: "BACKEND", "Generating RSA key pair: bits={} slot={}", modulus_bits, slot_id);
    if !(1024..=16384).contains(&modulus_bits) {
        return Err(Pkcs11Error::KeySizeRange);
    }
    let e = eng(slot_id)?;
    let pair = e.generate_rsa_key_pair(modulus_bits).map_err(Pkcs11Error::from)?;

    let mut pub_attrs = pub_template;
    pub_attrs.insert(CKA_CLASS, ulong_bytes(CKO_PUBLIC_KEY));
    pub_attrs.insert(CKA_KEY_TYPE, ulong_bytes(CKK_RSA));
    pub_attrs.insert(CKA_MODULUS, pair.modulus.clone());
    pub_attrs.insert(CKA_PUBLIC_EXPONENT, pair.public_exponent.clone());
    pub_attrs.insert(CKA_MODULUS_BITS, ulong_bytes(pair.bits as CK_ULONG));

    let mut priv_attrs = priv_template;
    priv_attrs.insert(CKA_CLASS, ulong_bytes(CKO_PRIVATE_KEY));
    priv_attrs.insert(CKA_KEY_TYPE, ulong_bytes(CKK_RSA));
    priv_attrs.insert(CKA_MODULUS, pair.modulus);
    priv_attrs.insert(CKA_PUBLIC_EXPONENT, pair.public_exponent);
    priv_attrs.insert(CKA_MODULUS_BITS, ulong_bytes(pair.bits as CK_ULONG));

    Ok((
        GeneratedKey {
            key_type: KeyType::RsaPrivate,
            key_ref: EngineKeyRef::from_bytes(pair.private_der.to_vec()),
            attrs: priv_attrs,
            key_gen_mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        },
        GeneratedKey {
            key_type: KeyType::RsaPublic,
            key_ref: EngineKeyRef::from_bytes(pair.public_der),
            attrs: pub_attrs,
            key_gen_mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        },
    ))
}

pub fn generate_ec_key_pair(
    slot_id: CK_SLOT_ID,
    curve: EcCurve,
    pub_template: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
    priv_template: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
) -> Result<(GeneratedKey, GeneratedKey)> {
    debug!(context: "BACKEND", "Generating EC key pair: curve={} slot={}", format!("{:?}", curve).as_str(), slot_id);
    let e = eng(slot_id)?;
    let pair = e.generate_ec_key_pair(curve).map_err(Pkcs11Error::from)?;

    let mut pub_attrs = pub_template;
    pub_attrs.insert(CKA_CLASS, ulong_bytes(CKO_PUBLIC_KEY));
    pub_attrs.insert(CKA_KEY_TYPE, ulong_bytes(CKK_EC));
    pub_attrs.insert(CKA_EC_PARAMS, pair.ec_params_der.clone());
    pub_attrs.insert(CKA_EC_POINT, pair.ec_point_uncompressed);

    let mut priv_attrs = priv_template;
    priv_attrs.insert(CKA_CLASS, ulong_bytes(CKO_PRIVATE_KEY));
    priv_attrs.insert(CKA_KEY_TYPE, ulong_bytes(CKK_EC));
    priv_attrs.insert(CKA_EC_PARAMS, pair.ec_params_der);

    Ok((
        GeneratedKey {
            key_type: KeyType::EcPrivate,
            key_ref: EngineKeyRef::from_bytes(pair.private_der.to_vec()),
            attrs: priv_attrs,
            key_gen_mechanism: CKM_EC_KEY_PAIR_GEN,
        },
        GeneratedKey {
            key_type: KeyType::EcPublic,
            key_ref: EngineKeyRef::from_bytes(pair.public_der),
            attrs: pub_attrs,
            key_gen_mechanism: CKM_EC_KEY_PAIR_GEN,
        },
    ))
}

pub fn generate_ed_key_pair(
    slot_id: CK_SLOT_ID,
    curve: EdwardsCurve,
    pub_template: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
    priv_template: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
) -> Result<(GeneratedKey, GeneratedKey)> {
    debug!(context: "BACKEND", "Generating Edwards key pair: curve={} slot={}", format!("{:?}", curve).as_str(), slot_id);
    let e = eng(slot_id)?;
    let pair = e.generate_ed_key_pair(curve).map_err(Pkcs11Error::from)?;

    let mut pub_attrs = pub_template;
    pub_attrs.insert(CKA_CLASS, ulong_bytes(CKO_PUBLIC_KEY));
    pub_attrs.insert(CKA_KEY_TYPE, ulong_bytes(CKK_EC_EDWARDS));
    pub_attrs.insert(CKA_EC_PARAMS, pair.ec_params_der.clone());
    pub_attrs.insert(CKA_EC_POINT, pair.ec_point.clone());

    let mut priv_attrs = priv_template;
    priv_attrs.insert(CKA_CLASS, ulong_bytes(CKO_PRIVATE_KEY));
    priv_attrs.insert(CKA_KEY_TYPE, ulong_bytes(CKK_EC_EDWARDS));
    priv_attrs.insert(CKA_EC_PARAMS, pair.ec_params_der);

    Ok((
        GeneratedKey {
            key_type: KeyType::EdPrivate,
            key_ref: EngineKeyRef::from_bytes(pair.private_der.to_vec()),
            attrs: priv_attrs,
            key_gen_mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN,
        },
        GeneratedKey {
            key_type: KeyType::EdPublic,
            key_ref: EngineKeyRef::from_bytes(pair.public_der),
            attrs: pub_attrs,
            key_gen_mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN,
        },
    ))
}

pub fn generate_aes_key(
    slot_id: CK_SLOT_ID,
    key_len_bytes: usize,
    template: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
) -> Result<GeneratedKey> {
    debug!(context: "BACKEND", "Generating AES key: len={} slot={}", key_len_bytes, slot_id);
    if !matches!(key_len_bytes, 16 | 24 | 32) {
        return Err(Pkcs11Error::KeySizeRange);
    }

    let e = eng(slot_id)?;
    let key_ref = e.generate_aes_key(key_len_bytes).map_err(Pkcs11Error::from)?;

    let mut unique_id = vec![0u8; 16];
    e.generate_random(&mut unique_id).map_err(Pkcs11Error::from)?;

    let mut attrs = template;
    attrs.insert(CKA_CLASS, ulong_bytes(CKO_SECRET_KEY));
    attrs.insert(CKA_KEY_TYPE, ulong_bytes(CKK_AES));
    attrs.insert(CKA_VALUE_LEN, ulong_bytes(key_len_bytes as CK_ULONG));
    attrs.insert(CKA_UNIQUE_ID, unique_id);

    Ok(GeneratedKey {
        key_type: KeyType::AesSecret,
        key_ref,
        attrs,
        key_gen_mechanism: CKM_AES_KEY_GEN,
    })
}

pub fn generate_chacha20_key(
    slot_id: CK_SLOT_ID,
    template: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
) -> Result<GeneratedKey> {
    debug!(context: "BACKEND", "Generating ChaCha20 key: slot={}", slot_id);
    let e = eng(slot_id)?;
    let key_ref = e.generate_chacha20_key().map_err(Pkcs11Error::from)?;

    let mut attrs = template;
    attrs.insert(CKA_CLASS, ulong_bytes(CKO_SECRET_KEY));
    attrs.insert(CKA_KEY_TYPE, ulong_bytes(CKK_CHACHA20));
    attrs.insert(CKA_VALUE_LEN, ulong_bytes(32));

    Ok(GeneratedKey {
        key_type: KeyType::ChaCha20Secret,
        key_ref,
        attrs,
        key_gen_mechanism: CKM_CHACHA20_KEY_GEN,
    })
}

pub fn generate_generic_secret_key(
    slot_id: CK_SLOT_ID,
    key_len_bytes: usize,
    template: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
) -> Result<GeneratedKey> {
    debug!(context: "BACKEND", "Generating generic secret key: len={} slot={}", key_len_bytes, slot_id);
    if key_len_bytes == 0 || key_len_bytes > 4096 {
        return Err(Pkcs11Error::KeySizeRange);
    }

    let e = eng(slot_id)?;
    let mut key_bytes = vec![0u8; key_len_bytes];
    e.generate_random(&mut key_bytes).map_err(Pkcs11Error::from)?;
    let key_ref = EngineKeyRef::from_bytes(key_bytes);

    let mut unique_id = vec![0u8; 16];
    e.generate_random(&mut unique_id).map_err(Pkcs11Error::from)?;

    let mut attrs = template;
    attrs.insert(CKA_CLASS, ulong_bytes(CKO_SECRET_KEY));
    attrs.insert(CKA_KEY_TYPE, ulong_bytes(CKK_GENERIC_SECRET));
    attrs.insert(CKA_VALUE_LEN, ulong_bytes(key_len_bytes as CK_ULONG));
    attrs.insert(CKA_UNIQUE_ID, unique_id);

    Ok(GeneratedKey {
        key_type: KeyType::GenericSecret,
        key_ref,
        attrs,
        key_gen_mechanism: CKM_GENERIC_SECRET_KEY_GEN,
    })
}

pub fn generate_legacy_secret_key(
    slot_id: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    key_len_bytes: usize,
    key_type: CK_KEY_TYPE,
    template: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
) -> Result<GeneratedKey> {
    let e = eng(slot_id)?;
    let mut key_bytes = vec![0u8; key_len_bytes];
    e.generate_random(&mut key_bytes).map_err(Pkcs11Error::from)?;

    let mut attrs = template;
    attrs.insert(CKA_CLASS, ulong_bytes(CKO_SECRET_KEY));
    attrs.insert(CKA_KEY_TYPE, ulong_bytes(key_type));
    attrs.insert(CKA_VALUE_LEN, ulong_bytes(key_len_bytes as CK_ULONG));

    Ok(GeneratedKey {
        key_type: KeyType::GenericSecret,
        key_ref: EngineKeyRef::from_bytes(key_bytes),
        attrs,
        key_gen_mechanism: mechanism,
    })
}
