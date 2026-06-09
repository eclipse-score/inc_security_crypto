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
//! Test sequence:
//!   loadHSMLibrary → connectToSlot (Initialize + OpenSession + Login)
//!   → generateRandom (C_GenerateRandom)
//!   → disconnectFromSlot (Logout + CloseSession + Finalize)

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{
    C_Initialize,
    C_OpenSession, C_CloseSession,
    C_Login, C_Logout,
    C_GenerateRandom,
};
use std::ptr;
use std::sync::Once;

const SLOT_PIN: &[u8] = b"1234";

static INIT: Once = Once::new();

fn init() {
    INIT.call_once(|| unsafe {
        let rv = C_Initialize(ptr::null_mut());
        assert!(
            rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "C_Initialize failed: {rv:#010x}",
        );
    });
}

unsafe fn connect_to_slot() -> CK_SESSION_HANDLE {
    let mut h: CK_SESSION_HANDLE = 0;
    assert_eq!(
        C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h),
        CKR_OK,
    );
    let rv = C_Login(h, CKU_USER, SLOT_PIN.as_ptr(), SLOT_PIN.len() as CK_ULONG);
    assert!(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN, "C_Login failed: {rv:#x}");
    h
}

unsafe fn disconnect_from_slot(h: CK_SESSION_HANDLE) {
    let rv = C_Logout(h);
    assert!(rv == CKR_OK || rv == CKR_USER_NOT_LOGGED_IN, "C_Logout failed: {rv:#x}");
    assert_eq!(C_CloseSession(h), CKR_OK);
}

// ═════════════════════════════════════════════════════════════════════════════
// C_GenerateRandom
// ═════════════════════════════════════════════════════════════════════════════

/// sequence:
///   loadHSMLibrary() → connectToSlot() → generateRandom() → disconnectFromSlot()
///
/// generateRandom():
///   randomData = new CK_BYTE[dataLen];
///   C_GenerateRandom(hSession, randomData, dataLen)
///
/// The generates a fixed number of random bytes and prints them in hex.
/// We verify randomness properties: non-zero output and uniqueness across calls.
#[test]
fn c_generate_random() {
    init();
    unsafe {
        // Step 1: Initialize (shared)
        // Step 2: Open session + login
        // (connectToSlot() → C_Initialize + C_OpenSession + C_Login)
        let h_session = connect_to_slot();

        // Step 3: Generate random bytes
        // (dataLen = 32; randomData = new CK_BYTE[dataLen]; C_GenerateRandom(hSession, randomData, dataLen))
        let data_len: CK_ULONG = 32;
        let mut random_data = vec![0u8; data_len as usize];
        assert_eq!(
            C_GenerateRandom(h_session, random_data.as_mut_ptr(), data_len),
            CKR_OK,
            "C_GenerateRandom failed",
        );

        // The 32-byte output must not be all zeros (with overwhelming probability)
        assert_ne!(random_data, vec![0u8; 32], "random output must not be all-zero");

        // Step 4: Generate a smaller batch (16 bytes) — verify it also succeeds
        let mut buf16 = vec![0u8; 16];
        assert_eq!(C_GenerateRandom(h_session, buf16.as_mut_ptr(), 16), CKR_OK);

        // Step 5: Two consecutive calls must produce different values (probabilistic)
        // This confirms the RNG produces fresh bytes each invocation.
        let mut buf_a = vec![0u8; 16];
        let mut buf_b = vec![0u8; 16];
        assert_eq!(C_GenerateRandom(h_session, buf_a.as_mut_ptr(), 16), CKR_OK);
        assert_eq!(C_GenerateRandom(h_session, buf_b.as_mut_ptr(), 16), CKR_OK);
        assert_ne!(buf_a, buf_b, "consecutive C_GenerateRandom calls should produce different data");

        // Step 6: Logout and close session
        // (disconnectFromSlot() → C_Logout + C_CloseSession + C_Finalize)
        disconnect_from_slot(h_session);
    }
}
