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

//! In-memory object store — engine-agnostic key descriptors + CKA_* attribute maps.
//! Global store backed by `once_cell::Lazy<parking_lot::RwLock<…>>`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use score_log::{debug, error, info, trace, warn};

use crate::traits::EngineKeyRef;

use super::constants::*;
use super::error::{Pkcs11Error, Result};
use super::types::*;

// ── Key type discriminant ─────────────────────────────────────────────────

/// Identifies what kind of key a `KeyObject` represents.
/// No crypto-library types — just a tag used for dispatch in `backend.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    RsaPrivate,
    RsaPublic,
    EcPrivate,
    EcPublic,
    AesSecret,
    GenericSecret,
    EdPrivate,      // v3.0 — Ed25519, Ed448
    EdPublic,       // v3.0 — Ed25519, Ed448
    ChaCha20Secret, // v3.0
    /// `CKO_PROFILE` — not a key; holds `CKA_PROFILE_ID` describing which
    /// PKCS#11 v3.0 profile this token claims to implement.  `key_ref` is empty.
    Profile, // v3.0
}

// ── KeyObject ─────────────────────────────────────────────────────────────

pub struct KeyObject {
    pub handle: CK_OBJECT_HANDLE,
    /// The slot this object belongs to.
    pub slot_id: CK_SLOT_ID,
    pub key_type: KeyType,
    /// Opaque key reference used by the `CryptoProvider`.
    /// For software engines this wraps DER-encoded bytes; for HSM/TPM backends
    /// it could be a handle.  The PKCS#11 layer never inspects the contents.
    pub key_ref: EngineKeyRef,
    /// All CKA_* attributes encoded as raw bytes:
    /// - `CK_ULONG` → 8-byte little-endian
    /// - `CK_BBOOL` → 1 byte (0 = false, 1 = true)
    /// - byte arrays → raw bytes
    pub attributes: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
    /// The session that created this object. Session objects (CKA_TOKEN=false)
    /// are destroyed when their creating session closes. Token objects are
    /// persisted and this field is ignored for them.
    pub creating_session: Option<CK_SESSION_HANDLE>,
    /// CKA_ALWAYS_AUTHENTICATE — user must re-authenticate before each use.
    pub always_authenticate: bool,
    /// CKA_LOCAL — true when the key was generated on the token (not imported).
    pub local: bool,
    /// CKA_ALWAYS_SENSITIVE — has been sensitive since creation (never changed).
    pub always_sensitive: bool,
    /// CKA_NEVER_EXTRACTABLE — has never been extractable since creation.
    pub never_extractable: bool,
    /// CKA_KEY_GEN_MECHANISM — mechanism used to generate the key, or
    /// `CK_UNAVAILABLE_INFORMATION` if not applicable / unknown.
    pub key_gen_mechanism: CK_MECHANISM_TYPE,
}

impl KeyObject {
    pub fn new(
        handle: CK_OBJECT_HANDLE,
        slot_id: CK_SLOT_ID,
        key_type: KeyType,
        key_ref: EngineKeyRef,
        attrs: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>>,
    ) -> Self {
        let mut attributes = attrs;
        attributes.entry(CKA_TOKEN).or_insert_with(|| vec![CK_FALSE]);
        KeyObject {
            handle,
            slot_id,
            key_type,
            key_ref,
            attributes,
            creating_session: None,
            always_authenticate: false,
            local: false,
            always_sensitive: false,
            never_extractable: false,
            key_gen_mechanism: CK_UNAVAILABLE_INFORMATION,
        }
    }

    pub fn get_attr(&self, attr_type: CK_ATTRIBUTE_TYPE) -> Result<&[u8]> {
        self.attributes
            .get(&attr_type)
            .map(|v| v.as_slice())
            .ok_or(Pkcs11Error::InvalidAttributeType)
    }

    /// Determines if this object matches the provided search template.
    ///
    /// In PKCS#11, a template is a list of attributes that an object must possess
    /// with exact matching values to be considered a "match."
    ///
    /// # Arguments
    /// * `template` - A slice of tuples containing the attribute type and the expected raw bytes.
    ///
    /// # Returns
    /// * `true` if the object contains all attributes in the template with matching values,
    ///   or if the template is empty (vacuous truth).
    /// * `false` if any attribute is missing from the object or has a different value.
    pub fn matches_template(&self, template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        // Iterate through every (Type, Value) pair in the search criteria.
        for (attr_type, expected) in template {
            // Look up the attribute in this object's internal attribute map.
            match self.attributes.get(attr_type) {
                // Success case: The attribute exists AND the bytes match exactly.
                // We use a 'Match Guard' (if v == expected) to verify the contents.
                Some(v) if v == expected => {},
                // Failure case: The attribute is either missing (None)
                // or the value did not match the guard condition.
                _ => return false,
            }
        }
        // If the loop completes without returning false, all criteria
        // in the template (if any) were satisfied by this object.
        // Note: An empty template (resulting from a NULL pTemplate)
        // matches all objects.
        true
    }
}

// ── Global store ──────────────────────────────────────────────────────────

static OBJECT_STORE: Lazy<RwLock<HashMap<CK_OBJECT_HANDLE, KeyObject>>> = Lazy::new(|| RwLock::new(HashMap::new()));

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

pub fn next_handle() -> CK_OBJECT_HANDLE {
    NEXT_HANDLE.fetch_add(1, Ordering::SeqCst)
}

/// Store an object, optionally tagging it with the creating session handle.
/// Session objects (CKA_TOKEN=false) are tagged so they can be destroyed when
/// their creating session closes.
///
/// Only token objects (`CKA_TOKEN = CK_TRUE`) trigger a disk write.
/// Session objects never touch the storage layer.
pub fn store_object(mut obj: KeyObject, session_handle: Option<CK_SESSION_HANDLE>) -> CK_OBJECT_HANDLE {
    let is_token = !is_session_object(&obj);
    if !is_token {
        obj.creating_session = session_handle;
    }
    let h = obj.handle;
    debug!(context: "STORE", "Storing object: handle={} type={} slot={} token={}",
        h, format!("{:?}", obj.key_type).as_str(), obj.slot_id, is_token);
    OBJECT_STORE.write().insert(h, obj);
    if is_token {
        trace!(context: "STORE", "stored token object handle={}", h);
        persist_if_needed();
    } else {
        trace!(context: "STORE", "stored session object handle={}", h);
    }
    h
}

/// Call `f` with a shared reference to the object; fails if handle is unknown.
pub fn with_object<F, T>(handle: CK_OBJECT_HANDLE, f: F) -> Result<T>
where
    F: FnOnce(&KeyObject) -> Result<T>,
{
    let store = OBJECT_STORE.read();
    let obj = store.get(&handle).ok_or(Pkcs11Error::InvalidObjectHandle)?;
    f(obj)
}

/// Call `f` with a shared reference to the object, enforcing slot isolation.
///
/// Returns `InvalidObjectHandle` if the object doesn't exist **or** belongs to
/// a different slot.  This prevents cross-slot object access.
pub fn with_object_for_slot<F, T>(handle: CK_OBJECT_HANDLE, slot_id: CK_SLOT_ID, f: F) -> Result<T>
where
    F: FnOnce(&KeyObject) -> Result<T>,
{
    let store = OBJECT_STORE.read();
    let obj = store.get(&handle).ok_or(Pkcs11Error::InvalidObjectHandle)?;
    if obj.slot_id != slot_id {
        return Err(Pkcs11Error::InvalidObjectHandle);
    }
    f(obj)
}

/// Call `f` with a mutable reference to the object; fails if handle is unknown.
pub fn with_object_mut<F, T>(handle: CK_OBJECT_HANDLE, f: F) -> Result<T>
where
    F: FnOnce(&mut KeyObject) -> Result<T>,
{
    let mut store = OBJECT_STORE.write();
    let obj = store.get_mut(&handle).ok_or(Pkcs11Error::InvalidObjectHandle)?;
    f(obj)
}

/// Find objects matching a template, respecting private object visibility.
///
/// Private objects (CKA_PRIVATE = CK_TRUE) are only visible when `logged_in`
/// is true.
pub fn find_objects(
    slot_id: CK_SLOT_ID,
    template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    logged_in: bool,
) -> Vec<CK_OBJECT_HANDLE> {
    OBJECT_STORE
        .read()
        .values()
        .filter(|o| o.slot_id == slot_id && o.matches_template(template) && (logged_in || !is_private_object(o)))
        .map(|o| o.handle)
        .collect()
}

/// Remove an object from the store.
///
/// Only triggers a disk write when the destroyed object was a token object
/// (`CKA_TOKEN = CK_TRUE`).  Destroying a session object never touches disk.
pub fn destroy_object(handle: CK_OBJECT_HANDLE) -> Result<()> {
    let obj = OBJECT_STORE
        .write()
        .remove(&handle)
        .ok_or(Pkcs11Error::InvalidObjectHandle)?;
    let token_object = !is_session_object(&obj);
    if token_object {
        persist_if_needed();
    }
    trace!(context: "STORE", "destroyed object handle={} token={}", handle, token_object);
    Ok(())
}

pub fn clear_objects() {
    let mut store = OBJECT_STORE.write();
    let n = store.len();
    store.clear();
    debug!(context: "STORE", "cleared all objects count={}", n);
}

/// Clear only objects belonging to a specific slot (used by C_InitToken).
pub fn clear_objects_for_slot(slot_id: CK_SLOT_ID) {
    let removed = {
        let mut store = OBJECT_STORE.write();
        let before = store.len();
        store.retain(|_, obj| obj.slot_id != slot_id);
        before.saturating_sub(store.len())
    };
    debug!(context: "STORE", "cleared objects for slot={} removed={}", slot_id, removed);
    persist_if_needed();
}

pub fn object_count() -> usize {
    OBJECT_STORE.read().len()
}

/// Ensure a `CKP_BASELINE_PROVIDER` profile object exists for `slot_id`.
///
/// Idempotent: if a profile object already exists on this slot, this is a no-op.
/// Otherwise it creates a `CKO_PROFILE` object with `CKA_PROFILE_ID =
/// CKP_BASELINE_PROVIDER`, `CKA_TOKEN = TRUE`, `CKA_PRIVATE = FALSE`, and an
/// empty `EngineKeyRef`.
///
/// Called from `C_Initialize` (per slot) and `C_InitToken`, so every initialized
/// token advertises at least one profile as required by PKCS#11 v3.0.
pub fn ensure_baseline_profile(slot_id: CK_SLOT_ID) -> CK_OBJECT_HANDLE {
    // Already present on this slot?
    {
        let store = OBJECT_STORE.read();
        for obj in store.values() {
            if obj.slot_id == slot_id && obj.key_type == KeyType::Profile {
                return obj.handle;
            }
        }
    }
    let handle = next_handle();
    let mut attrs: HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>> = HashMap::new();
    attrs.insert(CKA_CLASS, (CKO_PROFILE as CK_ULONG).to_le_bytes().to_vec());
    attrs.insert(CKA_TOKEN, vec![CK_TRUE]);
    attrs.insert(CKA_PRIVATE, vec![CK_FALSE]);
    attrs.insert(CKA_DESTROYABLE, vec![CK_FALSE]);
    attrs.insert(
        CKA_PROFILE_ID,
        (CKP_BASELINE_PROVIDER as CK_ULONG).to_le_bytes().to_vec(),
    );

    let obj = KeyObject::new(
        handle,
        slot_id,
        KeyType::Profile,
        EngineKeyRef::from_bytes(Vec::new()),
        attrs,
    );
    OBJECT_STORE.write().insert(handle, obj);
    handle
}

/// Check if an object has CKA_PRIVATE = CK_TRUE.
pub fn is_private_object(obj: &KeyObject) -> bool {
    obj.attributes
        .get(&CKA_PRIVATE)
        .map(|v| !v.is_empty() && v[0] == CK_TRUE)
        .unwrap_or(false)
}

/// Check if an object is a session object (CKA_TOKEN = CK_FALSE or absent).
pub fn is_session_object(obj: &KeyObject) -> bool {
    !obj.attributes
        .get(&CKA_TOKEN)
        .map(|v| !v.is_empty() && v[0] == CK_TRUE)
        .unwrap_or(false)
}

/// Check if CKA_TOKEN = CK_TRUE
pub fn is_token_object(obj: &KeyObject) -> bool {
    obj.attributes
        .get(&CKA_TOKEN)
        .map(|v| !v.is_empty() && v[0] == CK_TRUE)
        .unwrap_or(false)
}

/// Returns the length of the RSA modulus in bytes.
/// Used to validate signature length in C_Verify.
pub fn get_modulus_len(obj: &KeyObject) -> Result<usize> {
    obj.attributes
        .get(&CKA_MODULUS)
        .map(|v| v.len())
        .ok_or(Pkcs11Error::InvalidAttributeType)
}

/// Destroy session objects owned by a specific session.
/// Called by C_CloseSession when that session closes.
pub fn destroy_objects_for_session(session_handle: CK_SESSION_HANDLE) {
    OBJECT_STORE
        .write()
        .retain(|_, obj| obj.creating_session != Some(session_handle));
}

/// Destroy all session objects belonging to a specific slot.
/// Called by C_CloseAllSessions.
pub fn destroy_session_objects_for_slot(slot_id: CK_SLOT_ID) {
    OBJECT_STORE
        .write()
        .retain(|_, obj| !(obj.slot_id == slot_id && is_session_object(obj)));
}

/// Destroy private session objects on a slot (called by C_Logout).
pub fn destroy_private_session_objects(slot_id: CK_SLOT_ID) {
    OBJECT_STORE
        .write()
        .retain(|_, obj| !(obj.slot_id == slot_id && is_session_object(obj) && is_private_object(obj)));
}

// ── Persistence integration ──────────────────────────────────────────────

use super::storage;

/// Save all token objects (CKA_TOKEN = CK_TRUE) to disk.
/// Called automatically after store_object / destroy_object, and explicitly by C_Finalize.
pub fn persist_to_disk() {
    persist_if_needed();
}

fn persist_if_needed() {
    let store = OBJECT_STORE.read();
    let mut objects: Vec<storage::StoredObject> = Vec::new();
    for obj in store
        .values()
        .filter(|o| storage::is_token_object(o) && o.key_type != KeyType::Profile)
    {
        match crate::registry::engine_for_slot(obj.slot_id) {
            Ok((engine, _)) => match storage::StoredObject::from_key_object(obj, engine.as_ref()) {
                Ok(stored) => objects.push(stored),
                Err(_) => error!(context: "STORE", "serialize failed for object={}", obj.handle),
            },
            Err(_) => {
                warn!(context: "STORE", "no engine for slot={} skipping object={}", obj.slot_id, obj.handle)
            },
        }
    }

    // Collect token state for every registered slot.
    let mut tokens = HashMap::new();
    for slot_id in crate::registry::slot_ids() {
        let token_state = super::token::with_token(slot_id, |t| storage::StoredToken::from(t));
        tokens.insert(slot_id, token_state);
    }

    let state = storage::StoredState {
        version: 1,
        tokens,
        token: None,
        objects,
        next_handle: NEXT_HANDLE.load(Ordering::SeqCst),
    };
    if storage::save_state(&state).is_err() {
        error!(context: "STORE", "save_state failed");
    } else {
        trace!(context: "STORE", "persisted token objects count={}", state.objects.len());
    }
}

/// Load persisted objects from disk into the object store.
/// Called by `C_Initialize` to restore token objects from a previous session.
pub fn load_persisted_objects() {
    if let Some(state) = storage::load_state() {
        let count = state.objects.len();
        let mut store = OBJECT_STORE.write();
        for stored in state.objects {
            let slot_id = stored.slot_id;
            let h = stored.handle;
            match crate::registry::engine_for_slot(slot_id) {
                Ok((engine, _)) => match stored.into_key_object_with_engine(engine.as_ref()) {
                    Ok(obj) => {
                        store.insert(h, obj);
                    },
                    Err(_) => error!(context: "STORE", "deserialize failed handle={}", h),
                },
                Err(_) => {
                    warn!(context: "STORE", "no engine for slot={} skipping object={} on load", slot_id, h)
                },
            }
        }
        // Ensure the handle counter is past all loaded handles to avoid collisions.
        let max_loaded = store.keys().copied().max().unwrap_or(0);
        let counter = state.next_handle.max(max_loaded + 1);
        NEXT_HANDLE.store(counter, Ordering::SeqCst);
        info!(context: "STORE", "Loaded {} persisted objects from storage. next_handle={}", store.len(), counter);

        // Restore per-slot token state.
        if !state.tokens.is_empty() {
            for (slot_id, stored_token) in &state.tokens {
                super::token::with_token_mut(*slot_id, |t| stored_token.apply_to(t));
            }
        } else if let Some(ref legacy_token) = state.token {
            // Backward compat: legacy single-token format → apply to slot 0.
            super::token::with_token_mut(0, |t| legacy_token.apply_to(t));
        }
    }
}
