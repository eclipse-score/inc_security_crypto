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

//! Integration tests for: C_Initialize / C_Finalize lifecycle.
//!
//! These tests exercise repeated Init/Finalize cycles and verify that all
//! in-process state is cleaned up between cycles.  Because each test mutates
//! global library state (initialised / finalised), the tests MUST NOT run in
//! parallel within the same binary.  A process-wide mutex serialises them.
//!
//! Run with:
//!   cargo test --test lifecycle -- --test-threads=1
//! or just `cargo test --test lifecycle` (single-file binary always sequential).

mod common;

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{C_Initialize, C_Finalize, C_OpenSession, C_CloseSession};
use std::ffi::c_void;
use std::ptr;
use std::sync::OnceLock;

// ── Serialisation ─────────────────────────────────────────────────────────────
// All tests in this file mutate global library state; they must not overlap.
static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
fn serial_lock() -> std::sync::MutexGuard<'static, ()> {
    LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

/// Bring the library to a known-uninitialised state regardless of where it
/// currently is.  Swallows `CKR_CRYPTOKI_NOT_INITIALIZED` (already finalized).
unsafe fn ensure_finalized() {
    let rv = C_Finalize(ptr::null_mut());
    assert!(
        rv == CKR_OK || rv == CKR_CRYPTOKI_NOT_INITIALIZED,
        "ensure_finalized: unexpected rv {rv:#010x}"
    );
}

unsafe fn do_initialize() -> CK_RV {
    C_Initialize(ptr::null_mut())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// C_Initialize / C_Finalize / C_Initialize cycle succeeds cleanly.
#[test]
fn init_finalize_init_cycle() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();

        // First initialization.
        let rv = do_initialize();
        assert_eq!(rv, CKR_OK, "first C_Initialize failed: {rv:#010x}");

        // Open a session to create some state.
        let mut h: CK_SESSION_HANDLE = 0;
        let rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h);
        assert_eq!(rv, CKR_OK, "C_OpenSession after first init failed: {rv:#010x}");

        // Finalize — should close the session and clear all state.
        let rv = C_Finalize(ptr::null_mut());
        assert_eq!(rv, CKR_OK, "C_Finalize failed: {rv:#010x}");

        // Second initialization must succeed (not return ALREADY_INITIALIZED).
        let rv = do_initialize();
        assert_eq!(rv, CKR_OK, "second C_Initialize after Finalize failed: {rv:#010x}");

        // Verify the library is usable again.
        let mut h2: CK_SESSION_HANDLE = 0;
        let rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h2);
        assert_eq!(rv, CKR_OK, "C_OpenSession after re-init failed: {rv:#010x}");
        C_CloseSession(h2);

        ensure_finalized();
    }
}

/// A second C_Initialize before C_Finalize returns CKR_CRYPTOKI_ALREADY_INITIALIZED.
#[test]
fn double_init_returns_already_initialized() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();

        let rv = do_initialize();
        assert_eq!(rv, CKR_OK, "first init failed: {rv:#010x}");

        let rv = do_initialize();
        assert_eq!(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED,
                   "second init must return CKR_CRYPTOKI_ALREADY_INITIALIZED, got {rv:#010x}");

        ensure_finalized();
    }
}

/// After C_Finalize, C_OpenSession returns CKR_CRYPTOKI_NOT_INITIALIZED,
/// confirming that all session state was cleared.
#[test]
fn state_cleared_after_finalize() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();
        let rv = do_initialize();
        assert_eq!(rv, CKR_OK);

        // Open a session while initialized.
        let mut h: CK_SESSION_HANDLE = 0;
        let rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h);
        assert_eq!(rv, CKR_OK, "C_OpenSession failed: {rv:#010x}");

        // Finalize.
        let rv = C_Finalize(ptr::null_mut());
        assert_eq!(rv, CKR_OK, "C_Finalize failed: {rv:#010x}");

        // Any C_* call requiring initialization must now return NOT_INITIALIZED.
        let mut h2: CK_SESSION_HANDLE = 0;
        let rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h2);
        assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED,
                   "C_OpenSession after finalize must return CKR_CRYPTOKI_NOT_INITIALIZED, got {rv:#010x}");

        // Re-initialize and verify a fresh session can be opened (old handle gone).
        let rv = do_initialize();
        assert_eq!(rv, CKR_OK);
        let mut h3: CK_SESSION_HANDLE = 0;
        let rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h3);
        assert_eq!(rv, CKR_OK, "fresh session after re-init failed: {rv:#010x}");
        C_CloseSession(h3);

        ensure_finalized();
    }
}

/// C_Finalize with a non-NULL pReserved returns CKR_ARGUMENTS_BAD.
#[test]
fn finalize_non_null_reserved_returns_arguments_bad() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();
        let rv = do_initialize();
        assert_eq!(rv, CKR_OK);

        let dummy: u32 = 0;
        let rv = C_Finalize(&dummy as *const _ as *mut c_void);
        assert_eq!(rv, CKR_ARGUMENTS_BAD,
                   "C_Finalize(non-null) must return CKR_ARGUMENTS_BAD, got {rv:#010x}");

        // Library should still be initialized (Finalize was rejected).
        let mut h: CK_SESSION_HANDLE = 0;
        let rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h);
        assert_eq!(rv, CKR_OK,
                   "library must still be usable after rejected Finalize, got {rv:#010x}");
        C_CloseSession(h);

        ensure_finalized();
    }
}

/// C_Finalize when not initialized returns CKR_CRYPTOKI_NOT_INITIALIZED.
#[test]
fn finalize_when_not_initialized() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();

        let rv = C_Finalize(ptr::null_mut());
        assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED,
                   "C_Finalize when not initialized must return CKR_CRYPTOKI_NOT_INITIALIZED, got {rv:#010x}");
    }
}

/// Multiple Init/Finalize cycles work, not just one.
#[test]
fn three_init_finalize_cycles() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();

        for cycle in 0..3u32 {
            let rv = do_initialize();
            assert_eq!(rv, CKR_OK, "init failed on cycle {cycle}: {rv:#010x}");

            let rv = C_Finalize(ptr::null_mut());
            assert_eq!(rv, CKR_OK, "finalize failed on cycle {cycle}: {rv:#010x}");
        }
    }
}

/// C_Initialize with null args (single-threaded shorthand) is accepted.
#[test]
fn null_init_args_accepted() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();
        let rv = C_Initialize(ptr::null_mut());
        assert_eq!(rv, CKR_OK, "C_Initialize(null) must return CKR_OK, got {rv:#010x}");
        ensure_finalized();
    }
}

/// C_Initialize with CKF_OS_LOCKING_OK set (and no callbacks) is accepted.
#[test]
fn os_locking_args_accepted() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();

        let args = CK_C_INITIALIZE_ARGS {
            CreateMutex:  None,
            DestroyMutex: None,
            LockMutex:    None,
            UnlockMutex:  None,
            flags:        CKF_OS_LOCKING_OK,
            pReserved:    ptr::null_mut(),
        };
        let rv = C_Initialize(&args as *const _ as *mut _);
        assert_eq!(rv, CKR_OK, "C_Initialize with OS locking failed: {rv:#010x}");
        ensure_finalized();
    }
}

/// C_Initialize with app-supplied mutex callbacks but WITHOUT CKF_OS_LOCKING_OK
/// returns CKR_CANT_LOCK (we cannot use app mutexes).
#[test]
fn app_mutex_without_os_locking_returns_cant_lock() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();

        // Provide a dummy non-null callback for CreateMutex without CKF_OS_LOCKING_OK.
        unsafe extern "C" fn dummy_create(_: *mut *mut c_void) -> CK_RV { CKR_OK }

        let args = CK_C_INITIALIZE_ARGS {
            CreateMutex:  Some(dummy_create),
            DestroyMutex: None,
            LockMutex:    None,
            UnlockMutex:  None,
            flags:        0, // CKF_OS_LOCKING_OK intentionally absent
            pReserved:    ptr::null_mut(),
        };
        let rv = C_Initialize(&args as *const _ as *mut _);
        assert_eq!(rv, CKR_CANT_LOCK,
                   "app mutexes without OS locking must return CKR_CANT_LOCK, got {rv:#010x}");

        // Library must not have been initialized.
        let rv2 = C_Finalize(ptr::null_mut());
        assert_eq!(rv2, CKR_CRYPTOKI_NOT_INITIALIZED,
                   "library must not be initialized after CKR_CANT_LOCK, got {rv2:#010x}");
    }
}

/// C_Initialize with both app callbacks AND CKF_OS_LOCKING_OK: we prefer OS
/// locking, ignore callbacks, and return CKR_OK.
#[test]
fn app_mutex_with_os_locking_accepted() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();

        unsafe extern "C" fn dummy_create(_: *mut *mut c_void) -> CK_RV { CKR_OK }

        let args = CK_C_INITIALIZE_ARGS {
            CreateMutex:  Some(dummy_create),
            DestroyMutex: None,
            LockMutex:    None,
            UnlockMutex:  None,
            flags:        CKF_OS_LOCKING_OK, // prefer OS locking
            pReserved:    ptr::null_mut(),
        };
        let rv = C_Initialize(&args as *const _ as *mut _);
        assert_eq!(rv, CKR_OK,
                   "app callbacks + CKF_OS_LOCKING_OK must be accepted, got {rv:#010x}");
        ensure_finalized();
    }
}
