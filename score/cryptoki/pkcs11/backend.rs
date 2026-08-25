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

//! Crypto backend — all operations delegate to the registered `CryptoProvider`.
//!
//! This module has no direct OpenSSL dependency. Key material is identified by
//! `KeyType` and passed to the engine as opaque `EngineKeyRef` values.
//!
//! Every public function takes a `slot_id` parameter to look up the correct
//! engine from the multi-engine registry.

use std::collections::HashMap;

use crate::traits::EngineKeyRef;
use score_log::{debug, info, trace, warn};

use super::constants::*;
use super::error::{Pkcs11Error, Result};
use super::object_store::{KeyObject, KeyType};
use super::types::*;

mod attributes;
mod digest_random;
mod keygen;
mod message_aead;
mod rsa_wrap_derive;
mod sign_verify;
mod symmetric;

pub use attributes::*;
pub use digest_random::*;
pub use keygen::*;
pub use message_aead::*;
pub use rsa_wrap_derive::*;
pub use sign_verify::*;
pub use symmetric::*;

/// Key material and attributes produced by a keygen operation.
///
/// `backend` does not allocate handles or touch the object store.
/// The caller assigns a handle, constructs the `KeyObject`, stamps policy
/// fields, and calls `object_store::store_object()`.
pub struct GeneratedKey {
    pub key_type: KeyType,
    pub key_ref: EngineKeyRef,
    pub attrs: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
    pub key_gen_mechanism: CK_MECHANISM_TYPE,
}

fn eng(slot_id: CK_SLOT_ID) -> Result<std::sync::Arc<dyn crate::traits::CryptoProvider>> {
    trace!(context: "BACKEND", "provider lookup slot={}", slot_id);
    let (engine, _internal_slot_id) = crate::registry::engine_for_slot(slot_id).map_err(|e| {
        warn!(context: "BACKEND", "provider lookup failed slot={} ", slot_id);
        Pkcs11Error::from(e)
    })?;
    Ok(engine)
}

pub fn ulong_bytes(v: CK_ULONG) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

pub fn bytes_to_ulong(b: &[u8]) -> CK_ULONG {
    let mut arr = [0u8; 8];
    let n = b.len().min(8);
    arr[..n].copy_from_slice(&b[..n]);
    CK_ULONG::from_le_bytes(arr)
}
