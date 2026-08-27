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

pub fn get_attribute(slot_id: CK_SLOT_ID, key: &KeyObject, attr_type: CK_ATTRIBUTE_TYPE) -> Result<Vec<u8>> {
    use crate::attributes::AttributeType;
    trace!(context: "BACKEND", "Get attribute: slot={} key_handle={} attr_type={}", slot_id, key.handle, attr_type);
    let e = eng(slot_id)?;
    let at = AttributeType::from_u32(attr_type as u32).ok_or(Pkcs11Error::InvalidAttributeType)?;
    let val = match key.key_type {
        KeyType::RsaPrivate => e.rsa_attribute(&key.key_ref, true, at),
        KeyType::RsaPublic => e.rsa_attribute(&key.key_ref, false, at),
        KeyType::EcPrivate => e.ec_attribute(&key.key_ref, true, at),
        KeyType::EcPublic => e.ec_attribute(&key.key_ref, false, at),
        KeyType::AesSecret => e.aes_attribute(&key.key_ref, at),
        KeyType::EdPrivate => e.ed_attribute(&key.key_ref, true, at),
        KeyType::EdPublic => e.ed_attribute(&key.key_ref, false, at),
        KeyType::ChaCha20Secret => e.aes_attribute(&key.key_ref, at),
        KeyType::GenericSecret => e.aes_attribute(&key.key_ref, at),
        KeyType::Profile => return Err(Pkcs11Error::InvalidAttributeType),
    }
    .map_err(Pkcs11Error::from)?;

    Ok(val.to_bytes())
}
