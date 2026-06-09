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

//! Mechanism tier policy — classifies PKCS#11 mechanisms as Standard, Legacy,
//! and gates weak legacy mechanisms behind an environment variable.
//!
//! ## Tiers
//!
//! | Tier       | Behaviour                                       |
//! |------------|-------------------------------------------------|
//! | Standard   | Always advertised and usable                    |
//! | Legacy     | Hidden and rejected unless `CRYPTOKI_LEGACY=1`  |
//! | Forbidden  | Never available (e.g. RSA keygen < 2048 bits)   |

use super::constants::*;
use super::types::CK_MECHANISM_TYPE;

/// Classification of a PKCS#11 mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MechanismTier {
    /// Available by default.
    Standard,
    /// Only available when `CRYPTOKI_LEGACY=1`.
    Legacy,
}

/// Classify a mechanism type.
///
/// Pass `None` when the key size is not known (e.g. during
/// `C_GetMechanismList`).
pub fn classify(mech: CK_MECHANISM_TYPE, key_bits: Option<u32>) -> MechanismTier {
    let _ = key_bits;
    match mech {
        // Weak / legacy hash and signature mechanisms.
        CKM_MD5 | CKM_SHA_1 | CKM_SHA1_RSA_PKCS | CKM_SHA1_RSA_PKCS_PSS => {
            MechanismTier::Legacy
        }
        _ => MechanismTier::Standard,
    }
}

/// Returns `true` when the `CRYPTOKI_LEGACY` environment variable is set
/// to `"1"`.
pub fn legacy_enabled() -> bool {
    std::env::var("CRYPTOKI_LEGACY").is_ok_and(|v| v == "1")
}

/// Returns `true` when the mechanism (with optional key size) is allowed under
/// the current policy.
///
/// - `Standard` mechanisms are always allowed.
/// - `Legacy` mechanisms are allowed only when `CRYPTOKI_LEGACY=1`.
pub fn is_mechanism_allowed(mech: CK_MECHANISM_TYPE, key_bits: Option<u32>) -> bool {
    match classify(mech, key_bits) {
        MechanismTier::Standard  => true,
        MechanismTier::Legacy    => legacy_enabled(),
    }
}
