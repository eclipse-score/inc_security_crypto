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

use super::*;

pub fn encrypt_message(
    slot_id: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    key: &KeyObject,
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    debug!(context: "BACKEND", "Message encrypt: slot={} mechanism={} key_handle={} iv_len={} aad_len={} len={}", 
        slot_id, mechanism, key.handle, iv.len(), aad.len(), plaintext.len());
    let e = eng(slot_id)?;
    match mechanism {
        CKM_AES_GCM => e.aes_gcm_encrypt(&key.key_ref, iv, aad, plaintext).map_err(Pkcs11Error::from),
        CKM_CHACHA20_POLY1305 => e.chacha20_poly1305_encrypt(&key.key_ref, iv, aad, plaintext).map_err(Pkcs11Error::from),
        _ => Err(Pkcs11Error::MechanismUnsupported),
    }
}

pub fn decrypt_message(
    slot_id: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    key: &KeyObject,
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    debug!(context: "BACKEND", "Message decrypt: slot={} mechanism={} key_handle={} iv_len={} aad_len={} len={} tag_len={}", 
        slot_id, mechanism, key.handle, iv.len(), aad.len(), ciphertext.len(), tag.len());
    let e = eng(slot_id)?;
    match mechanism {
        CKM_AES_GCM => e.aes_gcm_decrypt(&key.key_ref, iv, aad, ciphertext, tag).map_err(Pkcs11Error::from),
        CKM_CHACHA20_POLY1305 => e.chacha20_poly1305_decrypt(&key.key_ref, iv, aad, ciphertext, tag).map_err(Pkcs11Error::from),
        _ => Err(Pkcs11Error::MechanismUnsupported),
    }
}
