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

//!
//! The Tests demonstrate:
//!   - Retrieving the list of all available slots with tokens.
//!   - Displaying information about those slots and tokens.
//!   - Listing supported mechanisms.
//!   - Querying the library version via C_GetInfo.

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{
    C_Initialize,
    C_GetInfo, C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo,
    C_GetMechanismList,
};
use std::ptr;
use std::sync::Once;

static INIT: Once = Once::new();

fn init() {
    INIT.call_once(|| unsafe {
        // Step 1: Initialize the PKCS#11 library
        // (equivalent: C_Initialize(NULL_PTR) in loadHSMLibrary/connectToSlot)
        let rv = C_Initialize(ptr::null_mut());
        assert!(
            rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "C_Initialize failed: {rv:#010x}",
        );
    });
}

// ── slot_and_token_info ──────────────────────────────────────

/// Demonstrates: C_GetSlotList → C_GetSlotInfo → C_GetTokenInfo →
///       C_GetMechanismList → C_GetInfo
///
/// main() sequence:
///   loadHSMLibrary() → C_Initialize() → show_all_slots() → C_Finalize()
///   show_all_slots() calls: C_GetSlotList → C_GetSlotInfo → C_GetTokenInfo
#[test]
fn slot_and_token_info() {
    init();
    unsafe {
        // Step 2: C_GetSlotList — first call with NULL buffer to get count,
        // second call to fill the slot ID array
        // (checkOperation(p11Func->C_GetSlotList(CK_TRUE, NULL_PTR, &no_of_slots)))
        let mut slot_count: CK_ULONG = 0;
        assert_eq!(
            C_GetSlotList(CK_TRUE, ptr::null_mut(), &mut slot_count),
            CKR_OK,
            "C_GetSlotList (count) failed",
        );
        assert_eq!(slot_count, 1, "expected exactly one slot");

        let mut slot_id: CK_SLOT_ID = 0;
        assert_eq!(
            C_GetSlotList(CK_TRUE, &mut slot_id, &mut slot_count),
            CKR_OK,
            "C_GetSlotList (fill) failed",
        );
        assert_eq!(slot_id, 0);

        // Step 3: C_GetSlotInfo — retrieve hardware/firmware version and flags
        // (show_slot_info() → p11Func->C_GetSlotInfo(slotId, &slotInfo))
        let mut slot_info: CK_SLOT_INFO = std::mem::zeroed();
        assert_eq!(
            C_GetSlotInfo(slot_id, &mut slot_info),
            CKR_OK,
            "C_GetSlotInfo failed",
        );
        assert_ne!(
            slot_info.flags & CKF_TOKEN_PRESENT,
            0,
            "CKF_TOKEN_PRESENT must be set",
        );

        // Step 4: C_GetTokenInfo — retrieve token label, flags, memory, pin-length limits
        // (show_token_info() → p11Func->C_GetTokenInfo(slotId, &tokenInfo))
        let mut token_info: CK_TOKEN_INFO = std::mem::zeroed();
        assert_eq!(
            C_GetTokenInfo(slot_id, &mut token_info),
            CKR_OK,
            "C_GetTokenInfo failed",
        );
        assert_ne!(
            token_info.flags & CKF_TOKEN_INITIALIZED,
            0,
            "CKF_TOKEN_INITIALIZED must be set",
        );

        // Step 5: C_GetMechanismList — first call with NULL to get count,
        // second call to retrieve the mechanism type array
        let mut mech_count: CK_ULONG = 0;
        assert_eq!(
            C_GetMechanismList(slot_id, ptr::null_mut(), &mut mech_count),
            CKR_OK,
            "C_GetMechanismList (count) failed",
        );
        assert!(mech_count >= 10, "too few mechanisms: {mech_count}");

        let mut mechs = vec![0u64; mech_count as usize];
        assert_eq!(
            C_GetMechanismList(slot_id, mechs.as_mut_ptr(), &mut mech_count),
            CKR_OK,
            "C_GetMechanismList (fill) failed",
        );
        assert!(mechs.contains(&CKM_AES_KEY_GEN),          "missing CKM_AES_KEY_GEN");
        assert!(mechs.contains(&CKM_AES_CBC_PAD),          "missing CKM_AES_CBC_PAD");
        assert!(mechs.contains(&CKM_AES_GCM),              "missing CKM_AES_GCM");
        assert!(mechs.contains(&CKM_RSA_PKCS_KEY_PAIR_GEN),"missing CKM_RSA_PKCS_KEY_PAIR_GEN");
        assert!(mechs.contains(&CKM_EC_KEY_PAIR_GEN),      "missing CKM_EC_KEY_PAIR_GEN");
        assert!(mechs.contains(&CKM_SHA256),               "missing CKM_SHA256");

        // Step 6: C_GetInfo — library version and vendor information
        let mut info: CK_INFO = std::mem::zeroed();
        assert_eq!(C_GetInfo(&mut info), CKR_OK, "C_GetInfo failed");
        assert_eq!(info.cryptokiVersion.major, 3);
        assert_eq!(info.cryptokiVersion.minor, 0);
    }
}
