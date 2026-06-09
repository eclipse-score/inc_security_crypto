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
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::traits::CryptoProvider;

use super::super::object_store::{KeyObject, KeyType};
use super::super::token::{HashedPin, Token, TokenState};
use super::super::types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoredKeyType {
    RsaPrivate,
    RsaPublic,
    EcPrivate,
    EcPublic,
    AesSecret,
    EdPrivate,
    EdPublic,
    ChaCha20Secret,
    GenericSecret,
}

impl From<KeyType> for StoredKeyType {
    fn from(kt: KeyType) -> Self {
        match kt {
            KeyType::RsaPrivate => StoredKeyType::RsaPrivate,
            KeyType::RsaPublic => StoredKeyType::RsaPublic,
            KeyType::EcPrivate => StoredKeyType::EcPrivate,
            KeyType::EcPublic => StoredKeyType::EcPublic,
            KeyType::AesSecret => StoredKeyType::AesSecret,
            KeyType::EdPrivate => StoredKeyType::EdPrivate,
            KeyType::EdPublic => StoredKeyType::EdPublic,
            KeyType::ChaCha20Secret => StoredKeyType::ChaCha20Secret,
            KeyType::GenericSecret => StoredKeyType::GenericSecret,
            KeyType::Profile => unreachable!("profile objects are not persisted"),
        }
    }
}

impl From<StoredKeyType> for KeyType {
    fn from(skt: StoredKeyType) -> Self {
        match skt {
            StoredKeyType::RsaPrivate => KeyType::RsaPrivate,
            StoredKeyType::RsaPublic => KeyType::RsaPublic,
            StoredKeyType::EcPrivate => KeyType::EcPrivate,
            StoredKeyType::EcPublic => KeyType::EcPublic,
            StoredKeyType::AesSecret => KeyType::AesSecret,
            StoredKeyType::EdPrivate => KeyType::EdPrivate,
            StoredKeyType::EdPublic => KeyType::EdPublic,
            StoredKeyType::ChaCha20Secret => KeyType::ChaCha20Secret,
            StoredKeyType::GenericSecret => KeyType::GenericSecret,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObject {
    pub handle: CK_OBJECT_HANDLE,
    #[serde(default)]
    pub slot_id: CK_SLOT_ID,
    pub key_type: StoredKeyType,
    pub key_der: Vec<u8>,
    pub attributes: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
}

impl StoredObject {
    pub fn from_key_object(obj: &KeyObject, engine: &dyn CryptoProvider) -> Result<Self, String> {
        let key_bytes = engine
            .serialize_key(&obj.key_ref)
            .map_err(|e| format!("serialize_key slot {}: {e}", obj.slot_id))?;
        Ok(StoredObject {
            handle: obj.handle,
            slot_id: obj.slot_id,
            key_type: obj.key_type.into(),
            key_der: key_bytes,
            attributes: obj.attributes.clone(),
        })
    }

    pub fn into_key_object_with_engine(self, engine: &dyn CryptoProvider) -> Result<KeyObject, String> {
        let key_ref = engine
            .deserialize_key(&self.key_der)
            .map_err(|e| format!("deserialize_key slot {}: {e}", self.slot_id))?;
        Ok(KeyObject::new(self.handle, self.slot_id, self.key_type.into(), key_ref, self.attributes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredHashedPin {
    #[serde(default)]
    pub phc_string: Option<String>,
    #[serde(default)]
    pub salt: Option<Vec<u8>>,
    #[serde(default)]
    pub hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub label: Vec<u8>,
    #[serde(default = "default_state_str")]
    pub state: String,
    #[serde(default)]
    pub initialized: Option<bool>,
    #[serde(default)]
    pub so_pin: Option<Vec<u8>>,
    #[serde(default)]
    pub user_pin: Option<Vec<u8>>,
    #[serde(default)]
    pub so_pin_hash: Option<StoredHashedPin>,
    #[serde(default)]
    pub user_pin_hash: Option<StoredHashedPin>,
    #[serde(default)]
    pub so_pin_failures: u32,
    #[serde(default)]
    pub user_pin_failures: u32,
    pub login_required: bool,
    pub serial_number: Vec<u8>,
}

fn default_state_str() -> String {
    "read_write".to_string()
}

impl From<&Token> for StoredToken {
    fn from(t: &Token) -> Self {
        let state = match t.state {
            TokenState::Reset => "reset",
            TokenState::ReadWrite => "read_write",
            TokenState::ReadOnly => "read_only",
        };
        StoredToken {
            label: t.label.to_vec(),
            state: state.to_string(),
            initialized: None,
            so_pin: None,
            user_pin: None,
            so_pin_hash: t.so_pin.as_ref().map(|p| StoredHashedPin {
                phc_string: Some(p.phc_string.clone()),
                salt: None,
                hash: None,
            }),
            user_pin_hash: t.user_pin.as_ref().map(|p| StoredHashedPin {
                phc_string: Some(p.phc_string.clone()),
                salt: None,
                hash: None,
            }),
            so_pin_failures: t.so_pin_failures,
            user_pin_failures: t.user_pin_failures,
            login_required: t.login_required,
            serial_number: t.serial_number.to_vec(),
        }
    }
}

impl StoredToken {
    pub fn apply_to(&self, token: &mut Token) {
        let mut label = [b' '; 32];
        let n = self.label.len().min(32);
        label[..n].copy_from_slice(&self.label[..n]);
        token.label = label;

        token.state = match self.state.as_str() {
            "reset" => TokenState::Reset,
            "read_only" => TokenState::ReadOnly,
            _ => {
                if let Some(false) = self.initialized {
                    TokenState::Reset
                } else {
                    TokenState::ReadWrite
                }
            }
        };

        token.so_pin = match (&self.so_pin_hash, &self.so_pin) {
            (Some(h), _) if h.phc_string.is_some() => Some(HashedPin::from_phc(h.phc_string.clone().unwrap())),
            (_, Some(p)) => Some(HashedPin::new(p)),
            _ => None,
        };
        token.user_pin = match (&self.user_pin_hash, &self.user_pin) {
            (Some(h), _) if h.phc_string.is_some() => Some(HashedPin::from_phc(h.phc_string.clone().unwrap())),
            (_, Some(p)) => Some(HashedPin::new(p)),
            _ => None,
        };

        token.so_pin_failures = self.so_pin_failures;
        token.user_pin_failures = self.user_pin_failures;
        token.login_required = self.login_required;

        let mut serial = [b' '; 16];
        let n = self.serial_number.len().min(16);
        serial[..n].copy_from_slice(&self.serial_number[..n]);
        token.serial_number = serial;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredState {
    pub version: u32,
    #[serde(default)]
    pub tokens: HashMap<CK_SLOT_ID, StoredToken>,
    #[serde(default)]
    pub token: Option<StoredToken>,
    pub objects: Vec<StoredObject>,
    pub next_handle: u64,
}
