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

//! Attribute policy enforcement — one-way ratchets, immutability, access control.
//!
//! Three entry points called from `mod.rs`:
//!
//! * [`validate_attribute_change`] — called by `C_SetAttributeValue` before
//!   each attribute is written.  Enforces:
//!   - One-way ratchets (`CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_WRAP_WITH_TRUSTED`)
//!   - Immutable-after-creation attributes (`CKA_CLASS`, `CKA_KEY_TYPE`, …)
//!
//! * [`check_attribute_access`] — called by `C_GetAttributeValue` before each
//!   attribute is returned.  Blocks `CKA_VALUE` for sensitive or non-extractable
//!   keys.
//!
//! * [`update_derived_attributes`] — called by `C_SetAttributeValue` after each
//!   attribute is written.  Keeps `always_sensitive` / `never_extractable` in
//!   sync with the key's attribute history.

use super::constants::*;
use super::error::{Pkcs11Error, Result};
use super::object_store::KeyObject;
use super::types::*;
use score_log::warn;

// ── validate_attribute_change ────────────────────────────────────────────────

/// Validate a proposed attribute write against PKCS#11 ratchet rules.
///
/// Call this **before** writing `new_val` into `obj.attributes`.
///
/// * `old_val` — current bytes for this attribute, or `None` if absent.
/// * `new_val` — proposed replacement bytes.
///
/// Returns `Err(AttributeReadOnly)` if the change violates a ratchet or an
/// immutability rule, `Ok(())` if the change is permitted.
pub fn validate_attribute_change(attr: CK_ATTRIBUTE_TYPE, old_val: Option<&[u8]>, new_val: &[u8]) -> Result<()> {
    match attr {
        // ── One-way: FALSE → TRUE only ───────────────────────────────────────
        CKA_SENSITIVE | CKA_WRAP_WITH_TRUSTED => {
            let was_true = old_val.is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE);
            let going_false = !new_val.is_empty() && new_val[0] == CK_FALSE;
            if was_true && going_false {
                warn!(context: "ATTR", "Attribute policy violation: cannot set CKA_SENSITIVE/CKA_WRAP_WITH_TRUSTED to FALSE after it was TRUE");
                return Err(Pkcs11Error::AttributeReadOnly);
            }
        },
        // ── One-way: TRUE → FALSE only ───────────────────────────────────────
        CKA_EXTRACTABLE => {
            let was_false = old_val.is_some_and(|v| v.is_empty() || v[0] == CK_FALSE);
            let going_true = !new_val.is_empty() && new_val[0] == CK_TRUE;
            if was_false && going_true {
                warn!(context: "ATTR", "Attribute policy violation: cannot set CKA_EXTRACTABLE to TRUE after it was FALSE");
                return Err(Pkcs11Error::AttributeReadOnly);
            }
        },
        // ── Immutable after creation ─────────────────────────────────────────
        CKA_CLASS | CKA_KEY_TYPE | CKA_MODULUS | CKA_EC_PARAMS | CKA_MODULUS_BITS | CKA_VALUE_LEN => {
            warn!(context: "ATTR", "Attribute policy violation: attempted to change immutable attribute type={}", attr);
            return Err(Pkcs11Error::AttributeReadOnly);
        },
        _ => {},
    }
    Ok(())
}

// ── check_attribute_access ───────────────────────────────────────────────────

/// Gate `CKA_VALUE` reads for sensitive or non-extractable keys.
///
/// Per PKCS#11:
/// - Sensitive keys (`CKA_SENSITIVE = TRUE`) must not expose `CKA_VALUE`.
/// - Non-extractable keys (`CKA_EXTRACTABLE = FALSE`) must not expose `CKA_VALUE`.
///
/// All other attribute types are returned unconditionally.
pub fn check_attribute_access(attr: CK_ATTRIBUTE_TYPE, obj: &KeyObject) -> Result<()> {
    // Check if the requested attribute is a secret payload
    let is_secret_attribute = matches!(
        attr,
        CKA_VALUE
            | CKA_PRIVATE_EXPONENT
            | CKA_PRIME_1
            | CKA_PRIME_2
            | CKA_EXPONENT_1
            | CKA_EXPONENT_2
            | CKA_COEFFICIENT
    );
    if !is_secret_attribute {
        return Ok(());
    }

    let class = obj.attributes.get(&CKA_CLASS).map(|v| {
        let mut arr = [0u8; 8];
        let n = v.len().min(8);
        arr[..n].copy_from_slice(&v[..n]);
        CK_ULONG::from_le_bytes(arr)
    });
    if matches!(class, Some(CKO_DATA | CKO_PUBLIC_KEY)) {
        return Ok(());
    }

    // Evaluate SENSITIVE (Defaults to FALSE if missing)
    let is_sensitive = obj
        .attributes
        .get(&CKA_SENSITIVE)
        .is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE);
    if is_sensitive {
        warn!(context: "ATTR", "Attribute access rejected: CKA_VALUE requested for sensitive object handle={}", obj.handle);
        return Err(Pkcs11Error::AttributeSensitive);
    }

    // Evaluate EXTRACTABLE (FAIL-CLOSED: Defaults to FALSE if missing)
    let is_extractable = obj
        .attributes
        .get(&CKA_EXTRACTABLE)
        .is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE);

    if !is_extractable {
        warn!(context: "ATTR", "Attribute access rejected: CKA_VALUE requested for non-extractable object handle={}", obj.handle);
        return Err(Pkcs11Error::AttributeSensitive);
    }
    Ok(())
}

// ── update_derived_attributes ────────────────────────────────────────────────

/// Sync `always_sensitive` and `never_extractable` after an attribute mutation.
///
/// Call this **after** writing the new value into `obj.attributes` so that
/// the struct fields reflect the key's full attribute history.
///
/// | Change                 | Derived effect                            |
/// |------------------------|-------------------------------------------|
/// | `CKA_SENSITIVE=FALSE`  | `always_sensitive = false`                |
/// | `CKA_EXTRACTABLE=TRUE` | `never_extractable = false`               |
/// | anything else          | no effect                                 |
///
/// Because the ratchets in [`validate_attribute_change`] prevent the reverse
/// transitions (`SENSITIVE TRUE→FALSE`, `EXTRACTABLE FALSE→TRUE`), these
/// updates only fire for the allowed ratchet directions.
pub fn update_derived_attributes(obj: &mut KeyObject, changed_attr: CK_ATTRIBUTE_TYPE) {
    match changed_attr {
        CKA_SENSITIVE => {
            // If CKA_SENSITIVE is now FALSE, the key was not always sensitive.
            let now_false = obj
                .attributes
                .get(&CKA_SENSITIVE)
                .is_some_and(|v| !v.is_empty() && v[0] == CK_FALSE);
            if now_false {
                obj.always_sensitive = false;
            }
        },
        CKA_EXTRACTABLE => {
            // If CKA_EXTRACTABLE is now TRUE, the key was not never-extractable.
            let now_true = obj
                .attributes
                .get(&CKA_EXTRACTABLE)
                .is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE);
            if now_true {
                obj.never_extractable = false;
            }
        },
        _ => {},
    }
}
