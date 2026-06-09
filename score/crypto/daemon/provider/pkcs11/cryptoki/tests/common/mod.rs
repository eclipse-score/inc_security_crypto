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

//! Shared test helpers — function-list dispatch.
//!
//! Real PKCS#11 consumers never call C_* symbols directly.  They:
//!   1. `dlopen` the shared library
//!   2. `dlsym("C_GetFunctionList")` to obtain `CK_FUNCTION_LIST*`
//!   3. Dispatch every call through the returned function pointers
//!
//! These helpers let our tests follow the same pattern.

#![allow(dead_code)]

use std::ptr;

use cryptoki::pkcs11::C_GetFunctionList;

// Re-export for convenience so test files only need `mod common;`.
pub use cryptoki::pkcs11::constants::*;
pub use cryptoki::pkcs11::types::*;

/// Obtain the v2.40-compatible function list via `C_GetFunctionList`.
///
/// In production this would be the *only* symbol obtained via `dlsym`;
/// every subsequent PKCS#11 call goes through the returned table.
pub unsafe fn fn_list() -> &'static CK_FUNCTION_LIST {
    let mut fl: *const CK_FUNCTION_LIST = ptr::null();
    let rv = C_GetFunctionList(&mut fl);
    assert_eq!(rv, CKR_OK, "C_GetFunctionList failed: {rv:#010x}");
    assert!(!fl.is_null(), "C_GetFunctionList returned null");
    &*fl
}

/// Obtain the v3.0 extended function list via `C_GetInterface`.
///
/// This is the v3.0 bootstrap path: `dlsym("C_GetInterface")` →
/// `CK_INTERFACE` → cast `pFunctionList` to `CK_FUNCTION_LIST_3_0*`.
pub unsafe fn fn_list_3_0() -> &'static CK_FUNCTION_LIST_3_0 {
    use cryptoki::pkcs11::C_GetInterface;
    let mut iface_ptr: *const CK_INTERFACE = ptr::null();
    let rv = C_GetInterface(ptr::null(), ptr::null_mut(), &mut iface_ptr, 0);
    assert_eq!(rv, CKR_OK, "C_GetInterface failed: {rv:#010x}");
    assert!(!iface_ptr.is_null());
    let iface = &*iface_ptr;
    assert!(!iface.pFunctionList.is_null());
    &*(iface.pFunctionList as *const CK_FUNCTION_LIST_3_0)
}

/// Call a PKCS#11 function through a function-list pointer.
///
/// Usage: `p11!(fl, C_Initialize, ptr::null_mut())`
///
/// Mirrors the C pattern: `fn_list->C_Initialize(NULL)`
#[macro_export]
macro_rules! p11 {
    ($fl:expr, $func:ident $(, $arg:expr)* $(,)?) => {
        ($fl.$func.unwrap())($($arg),*)
    }
}

/// Initialize the library through the function list and open a logged-in R/W session.
/// Returns `(function_list, session_handle)`.
pub unsafe fn init_and_open_session(fl: &CK_FUNCTION_LIST) -> CK_SESSION_HANDLE {
    let rv = (fl.C_Initialize.unwrap())(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
        "C_Initialize failed: {rv:#010x}");

    let mut h: CK_SESSION_HANDLE = 0;
    let rv = p11!(fl, C_OpenSession, 0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                  ptr::null_mut(), None, &mut h);
    assert_eq!(rv, CKR_OK, "C_OpenSession failed: {rv:#010x}");
    h
}

/// Open a R/W session (assumes library is already initialized).
pub unsafe fn open_session(fl: &CK_FUNCTION_LIST) -> CK_SESSION_HANDLE {
    let mut h: CK_SESSION_HANDLE = 0;
    let rv = p11!(fl, C_OpenSession, 0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                  ptr::null_mut(), None, &mut h);
    assert_eq!(rv, CKR_OK, "C_OpenSession failed: {rv:#010x}");
    h
}

/// Open a session and log in as CKU_USER with the default PIN.
pub unsafe fn open_logged_in_session(fl: &CK_FUNCTION_LIST) -> CK_SESSION_HANDLE {
    let h = open_session(fl);
    let pin = b"1234";
    let rv = p11!(fl, C_Login, h, CKU_USER, pin.as_ptr(), pin.len() as CK_ULONG);
    assert!(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN,
        "C_Login failed: {rv:#010x}");
    h
}
