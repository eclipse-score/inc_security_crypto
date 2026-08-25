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

//! # cryptoki
//!
//! PKCS#11 v3.0 software token with a multi-engine registry and pluggable
//! crypto backends.
//!
//! ## Usage
//!
//!
//! use cryptoki::{register_engine, engine_for_slot, OpenSslEngine, HashAlgorithm};
//!
//! // C_Initialize — register one or more engines.
//! // Each engine gets one or more global slot IDs assigned automatically.
//! let slots = register_engine(OpenSslEngine).unwrap(); // e.g. [0]
//!
//! // Retrieve the engine for a given global slot ID.
//! let (eng, _internal_id) = engine_for_slot(slots[0]).unwrap();
//!
//! // C_GenerateKey(CKM_AES_KEY_GEN) — generate a 128-bit AES key.
//! let key = eng.generate_aes_key(16).unwrap();
//!
//! // C_DigestInit(CKM_SHA256) + C_Digest — one-shot hash.
//! let digest = eng.hash(HashAlgorithm::Sha256, b"hello").unwrap();
//!
//!
//! ## Implementing a new engine
//!
//! Implement [`traits::CryptoProvider`] and [`traits::StreamHasher`] for your
//! crypto library, then call [`registry::register_engine`] with an instance.
//! The PKCS#11 layer never needs to change.  Each engine declares how many
//! slots it provides via [`CryptoProvider::slot_count`](traits::CryptoProvider::slot_count).

pub mod attributes;
pub mod error;
pub(crate) mod logger;
pub mod openssl_provider;
pub mod pkcs11;
pub mod registry;
pub mod traits;
pub mod types;

// ── Convenience re-exports ────────────────────────────────────────────────────

pub use attributes::{AttributeType, AttributeValue};
pub use error::CryptoError;
pub use openssl_provider::OpenSslEngine;
pub use registry::{
    engine, engine_for_slot, is_valid_slot, register_engine, reset_registry, slot_count, slot_ids, try_engine,
};
pub use traits::{CryptoProvider, EngineKeyRef, EngineMechanismInfo, StreamHasher};
pub use types::{EcCurve, EcKeyPair, EdKeyPair, EdwardsCurve, HashAlgorithm, RsaKeyPair};
