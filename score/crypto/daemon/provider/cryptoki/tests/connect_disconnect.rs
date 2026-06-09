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

//! The Test demonstrates:
//!   - Loading the PKCS#11 library.
//!   - Connecting to a token: C_Initialize → C_OpenSession → C_Login.
//!   - Disconnecting from a token: C_Logout → C_CloseSession → C_Finalize.

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{
    C_Initialize,
    C_OpenSession, C_CloseSession,
    C_Login, C_Logout,
    C_GetSessionInfo,
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

// ── connectToSlot / disconnectFromSlot ───────

/// Demonstrates the full connect/disconnect lifecycle:
///   C_Initialize → C_OpenSession → C_Login → C_Logout → C_CloseSession
///
/// connectToSlot():
///   C_Initialize(NULL_PTR)
///   C_OpenSession(slotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, ...)
///   C_Login(hSession, CKU_USER, slotPin, pinLen)
///
/// disconnectFromSlot():
///   C_Logout(hSession)
///   C_CloseSession(hSession)
///   C_Finalize(NULL_PTR)
#[test]
fn connect_disconnect() {
    init();
    unsafe {
        // Step 1: Initialize the library
        // (shared via Once — mirrors C_Initialize(NULL_PTR) in loadHSMLibrary)

        // Step 2: Open a read-write session on the slot
        // (C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession))
        let mut h_session: CK_SESSION_HANDLE = 0;
        assert_eq!(
            C_OpenSession(
                0,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                ptr::null_mut(),
                None,
                &mut h_session,
            ),
            CKR_OK,
            "C_OpenSession failed",
        );
        assert_ne!(h_session, 0, "session handle must be non-zero");

        // Step 3: Login as normal user
        // (C_Login(hSession, CKU_USER, slotPin, strlen(slotPin)))
        assert_eq!(
            C_Login(h_session, CKU_USER, SLOT_PIN.as_ptr(), SLOT_PIN.len() as CK_ULONG),
            CKR_OK,
            "C_Login failed",
        );

        // Step 4: Verify session state reflects logged-in user
        let mut info: CK_SESSION_INFO = std::mem::zeroed();
        assert_eq!(C_GetSessionInfo(h_session, &mut info), CKR_OK);
        assert_eq!(info.state, CKS_RW_USER_FUNCTIONS, "state must be CKS_RW_USER_FUNCTIONS after login");

        // Step 5: Logout
        // (C_Logout(hSession))
        assert_eq!(C_Logout(h_session), CKR_OK, "C_Logout failed");

        // Step 6: Verify session state reverts to public read-write
        assert_eq!(C_GetSessionInfo(h_session, &mut info), CKR_OK);
        assert_eq!(info.state, CKS_RW_PUBLIC_SESSION, "state must revert after logout");

        // Step 7: Close the session
        // (C_CloseSession(hSession))
        assert_eq!(C_CloseSession(h_session), CKR_OK, "C_CloseSession failed");
    }
}
