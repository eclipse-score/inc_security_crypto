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

//! Multi-engine registry — maps **global** slot IDs to crypto engine backends.
//!
//! Real PKCS#11 consumers can load multiple providers (e.g. a software token +
//! a hardware HSM).  Each provider registers via [`register_engine`], which
//! assigns one or more **global** slot IDs.  All subsequent C_* calls route
//! through [`engine_for_slot`] to the correct backend.
//!
//! ## Slot ID model
//!
//! There are two levels of slot ID:
//!
//! | Level | Assigned by | Used by |
//! |-------|------------|---------|
//! | **Global** (0, 1, 2, …) | Registry, sequentially | Application / C_* API |
//! | **Internal** (0-based per engine) | Engine itself | Engine trait methods |
//!
//! `engine_for_slot(global_id)` returns `(Arc<dyn CryptoProvider>, internal_id)`.
//!
//! ## Example
//!
//! ```text
//!   register_engine(SoftEngine)     → global [0]       (internal 0)
//!   register_engine(HsmEngine)      → global [1, 2]    (internal 0, 1)
//!
//!   C_OpenSession(slot=2)  →  session.slot_id = 2 (global)
//!   C_Sign(session)        →  engine_for_slot(2) → (HsmEngine, internal=1)
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock, OnceLock};

use crate::error::CryptoError;
use crate::traits::CryptoProvider;
use crate::pkcs11::types::CK_SLOT_ID;

// ── Virtual slot ─────────────────────────────────────────────────────────

/// Maps a global slot ID to a specific engine and its internal slot index.
struct VirtualSlot {
    engine: Arc<dyn CryptoProvider>,
    /// The engine's own slot index (0-based). For a single-slot engine this is always 0.
    internal_slot_id: CK_SLOT_ID,
}

// ── Registry ─────────────────────────────────────────────────────────────

struct Registry {
    engines: Vec<Arc<dyn CryptoProvider>>,
    slots: HashMap<CK_SLOT_ID, VirtualSlot>,
    next_slot_id: CK_SLOT_ID,
}

impl Registry {
    fn new() -> Self {
        Registry {
            engines: Vec::new(),
            slots: HashMap::new(),
            next_slot_id: 0,
        }
    }
}

static REGISTRY: OnceLock<RwLock<Registry>> = OnceLock::new();

fn get_registry() -> &'static RwLock<Registry> {
    REGISTRY.get_or_init(|| RwLock::new(Registry::new()))
}

// ── Public API ───────────────────────────────────────────────────────────

/// Register a crypto engine and assign it virtual slot(s).
///
/// Returns the global slot IDs assigned to this engine.
/// Each engine gets `engine.slot_count()` slots (default: 1).
pub fn register_engine(engine: impl CryptoProvider + 'static) -> Result<Vec<CK_SLOT_ID>, CryptoError> {
    let engine: Arc<dyn CryptoProvider> = Arc::new(engine);
    let mut reg = get_registry().write().map_err(|_| CryptoError::GeneralError { message: "registry lock poisoned".into() })?;

    let count = engine.slot_count();
    let mut assigned = Vec::with_capacity(count);

    for i in 0..count {
        let global_id = reg.next_slot_id;
        reg.slots.insert(global_id, VirtualSlot {
            engine: Arc::clone(&engine),
            internal_slot_id: i as CK_SLOT_ID,
        });
        assigned.push(global_id);
        reg.next_slot_id += 1;
    }

    reg.engines.push(engine);
    Ok(assigned)
}

/// Retrieve the engine and its internal slot ID for a given global slot ID.
///
/// The returned `CK_SLOT_ID` is the engine's own slot index (the "internal"
/// ID) which must be used when talking to the engine.  The global ID is what
/// the application sees; the internal ID is what the engine understands.
pub fn engine_for_slot(slot_id: CK_SLOT_ID) -> Result<(Arc<dyn CryptoProvider>, CK_SLOT_ID), CryptoError> {
    let reg = get_registry().read().map_err(|_| CryptoError::GeneralError { message: "registry lock poisoned".into() })?;
    reg.slots
        .get(&slot_id)
        .map(|vs| (Arc::clone(&vs.engine), vs.internal_slot_id))
        .ok_or(CryptoError::SlotIdInvalid)
}

/// Check whether a slot ID is registered.
pub fn is_valid_slot(slot_id: CK_SLOT_ID) -> bool {
    get_registry()
        .read()
        .map(|reg| reg.slots.contains_key(&slot_id))
        .unwrap_or(false)
}

/// Return all registered slot IDs, sorted.
pub fn slot_ids() -> Vec<CK_SLOT_ID> {
    let reg = get_registry().read().unwrap();
    let mut ids: Vec<CK_SLOT_ID> = reg.slots.keys().copied().collect();
    ids.sort();
    ids
}

/// Number of registered slots.
pub fn slot_count() -> usize {
    get_registry().read().map(|r| r.slots.len()).unwrap_or(0)
}

/// Convenience: retrieve the first registered engine.
///
/// Equivalent to `engine_for_slot(0)` when only one engine is registered.
/// Kept for backward compatibility with code that uses a single engine.
pub fn engine() -> Result<Arc<dyn CryptoProvider>, CryptoError> {
    let reg = get_registry().read().map_err(|_| CryptoError::GeneralError { message: "registry lock poisoned".into() })?;
    if reg.engines.is_empty() {
        return Err(CryptoError::NotInitialized);
    }
    Ok(Arc::clone(&reg.engines[0]))
}

/// Non-erroring convenience accessor — returns `None` when no engine is registered.
pub fn try_engine() -> Option<Arc<dyn CryptoProvider>> {
    let reg = get_registry().read().ok()?;
    reg.engines.first().map(Arc::clone)
}

/// Call `f` for every registered engine (used by the atfork child handler).
pub fn for_each_engine<F: Fn(&dyn CryptoProvider)>(f: F) {
    if let Ok(reg) = get_registry().read() {
        for engine in &reg.engines {
            f(engine.as_ref());
        }
    }
}

/// Reset the registry (called by C_Finalize).
///
/// Clears all engines and slot mappings so a subsequent C_Initialize
/// can re-register engines.
pub fn reset_registry() {
    if let Some(lock) = REGISTRY.get() {
        if let Ok(mut reg) = lock.write() {
            reg.engines.clear();
            reg.slots.clear();
            reg.next_slot_id = 0;
        }
    }
}
