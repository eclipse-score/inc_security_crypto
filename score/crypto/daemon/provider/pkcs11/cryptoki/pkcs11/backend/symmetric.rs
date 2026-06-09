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
use std::sync::OnceLock;

use openssl::provider::Provider;
use openssl::symm::{Cipher, Crypter, Mode};
use zeroize::Zeroizing;

use super::*;

static OPENSSL_PROVIDERS: OnceLock<Vec<Provider>> = OnceLock::new();

pub fn encrypt_symmetric(
    slot_id: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    key: &KeyObject,
    iv: &[u8],
    aad: Option<&[u8]>,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    debug!(context: "BACKEND", "Symmetric encrypt: slot={} mechanism={} key_handle={} iv_len={} aad_len={} len={}", 
        slot_id, mechanism, key.handle, iv.len(), aad.map_or(0, |a| a.len()), plaintext.len());
    let e = eng(slot_id)?;
    match mechanism {
        CKM_DES_ECB | CKM_DES_CBC | CKM_DES3_ECB | CKM_DES3_CBC | CKM_AES_ECB | CKM_AES_CBC => {
            block_cipher_crypt(mechanism, key.key_ref.as_bytes(), iv, plaintext, Mode::Encrypt, false)
        }
        CKM_AES_CBC_PAD => e.aes_cbc_encrypt(&key.key_ref, iv, plaintext).map_err(Pkcs11Error::from),
        CKM_AES_GCM => {
            let (mut ct, tag) = e.aes_gcm_encrypt(&key.key_ref, iv, aad.unwrap_or(&[]), plaintext).map_err(Pkcs11Error::from)?;
            ct.extend_from_slice(&tag);
            Ok(ct)
        }
        CKM_CHACHA20_POLY1305 => {
            let (mut ct, tag) = e.chacha20_poly1305_encrypt(&key.key_ref, iv, aad.unwrap_or(&[]), plaintext).map_err(Pkcs11Error::from)?;
            ct.extend_from_slice(&tag);
            Ok(ct)
        }
        _ => Err(Pkcs11Error::MechanismUnsupported),
    }
}

pub fn decrypt_symmetric(
    slot_id: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    key: &KeyObject,
    iv: &[u8],
    aad: Option<&[u8]>,
    ciphertext: &[u8],
    tag_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    debug!(context: "BACKEND", "Symmetric decrypt: slot={} mechanism={} key_handle={} iv_len={} aad_len={} len={} tag_len={}", 
        slot_id, mechanism, key.handle, iv.len(), aad.map_or(0, |a| a.len()), ciphertext.len(), tag_len);
    let e = eng(slot_id)?;
    match mechanism {
        CKM_DES_ECB | CKM_DES_CBC | CKM_DES3_ECB | CKM_DES3_CBC | CKM_AES_ECB | CKM_AES_CBC => {
            block_cipher_crypt(mechanism, key.key_ref.as_bytes(), iv, ciphertext, Mode::Decrypt, false).map(Zeroizing::new)
        }
        CKM_AES_CBC_PAD => e.aes_cbc_decrypt(&key.key_ref, iv, ciphertext).map_err(Pkcs11Error::from),
        CKM_AES_GCM => {
            if ciphertext.len() < tag_len {
                return Err(Pkcs11Error::EncryptedDataInvalid);
            }
            let (ct, tag) = ciphertext.split_at(ciphertext.len() - tag_len);
            e.aes_gcm_decrypt(&key.key_ref, iv, aad.unwrap_or(&[]), ct, tag).map_err(Pkcs11Error::from)
        }
        CKM_CHACHA20_POLY1305 => {
            if ciphertext.len() < tag_len {
                return Err(Pkcs11Error::EncryptedDataInvalid);
            }
            let (ct, tag) = ciphertext.split_at(ciphertext.len() - tag_len);
            e.chacha20_poly1305_decrypt(&key.key_ref, iv, aad.unwrap_or(&[]), ct, tag).map_err(Pkcs11Error::from)
        }
        _ => Err(Pkcs11Error::MechanismUnsupported),
    }
}

pub fn is_rsa_enc_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(mechanism, CKM_RSA_PKCS | CKM_RSA_PKCS_OAEP)
}

fn block_cipher_crypt(
    mechanism: CK_MECHANISM_TYPE,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
    mode: Mode,
    padding: bool,
) -> Result<Vec<u8>> {
    load_openssl_legacy_provider();
    let cipher = match mechanism {
        CKM_DES_ECB => Cipher::des_ecb(),
        CKM_DES_CBC => Cipher::des_cbc(),
        CKM_DES3_ECB => Cipher::des_ede3(),
        CKM_DES3_CBC => Cipher::des_ede3_cbc(),
        CKM_AES_ECB => aes_ecb_cipher(key.len())?,
        CKM_AES_CBC => aes_cbc_cipher(key.len())?,
        _ => return Err(Pkcs11Error::InvalidMechanism),
    };
    let iv_arg = if matches!(mechanism, CKM_DES_CBC | CKM_DES3_CBC | CKM_AES_CBC) {
        Some(iv)
    } else {
        None
    };
    let mut crypter = Crypter::new(cipher, mode, key, iv_arg).map_err(Pkcs11Error::from)?;
    crypter.pad(padding);
    let mut out = vec![0u8; input.len() + cipher.block_size()];
    let mut n = crypter.update(input, &mut out).map_err(Pkcs11Error::from)?;
    n += crypter.finalize(&mut out[n..]).map_err(Pkcs11Error::from)?;
    out.truncate(n);
    Ok(out)
}

fn load_openssl_legacy_provider() {
    let _ = OPENSSL_PROVIDERS.get_or_init(|| {
        let mut providers = Vec::new();
        if let Ok(provider) = Provider::try_load(None, "default", true) {
            providers.push(provider);
        }
        if let Ok(provider) = Provider::try_load(None, "legacy", true) {
            providers.push(provider);
        }
        providers
    });
}

fn aes_ecb_cipher(key_len: usize) -> Result<Cipher> {
    match key_len {
        16 => Ok(Cipher::aes_128_ecb()),
        24 => Ok(Cipher::aes_192_ecb()),
        32 => Ok(Cipher::aes_256_ecb()),
        _ => Err(Pkcs11Error::KeySizeRange),
    }
}

fn aes_cbc_cipher(key_len: usize) -> Result<Cipher> {
    match key_len {
        16 => Ok(Cipher::aes_128_cbc()),
        24 => Ok(Cipher::aes_192_cbc()),
        32 => Ok(Cipher::aes_256_cbc()),
        _ => Err(Pkcs11Error::KeySizeRange),
    }
}
