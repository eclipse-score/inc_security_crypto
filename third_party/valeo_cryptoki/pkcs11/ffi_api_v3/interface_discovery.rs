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
use super::*;

// ── C_GetInterfaceList / C_GetInterface (v3.0 interface discovery) ────────

#[no_mangle]
pub unsafe extern "C" fn C_GetInterfaceList(
    p_interfaces_list: *mut CK_INTERFACE,
    pul_count:         *mut CK_ULONG,
) -> CK_RV {
    if pul_count.is_null() { return CKR_ARGUMENTS_BAD; }
    if p_interfaces_list.is_null() {
        *pul_count = 1;
        return CKR_OK;
    }
    if *pul_count < 1 {
        *pul_count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    *p_interfaces_list = CK_INTERFACE {
        pInterfaceName: PKCS11_INTERFACE_NAME.as_ptr(),
        pFunctionList:  &FUNCTION_LIST_3_0 as *const _ as *const c_void,
        flags:          CKF_INTERFACE_FORK_SAFE,
    };
    *pul_count = 1;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetInterface(
    p_interface_name: *const CK_UTF8CHAR,
    p_version:        *mut CK_VERSION,
    pp_interface:     *mut *const CK_INTERFACE,
    flags:            CK_FLAGS,
) -> CK_RV {
    if pp_interface.is_null() { return CKR_ARGUMENTS_BAD; }

    // If name is NULL, return the default (latest) interface
    if !p_interface_name.is_null() {
        // Verify the name matches "PKCS 11"
        let name = std::ffi::CStr::from_ptr(p_interface_name as *const libc::c_char);
        if name.to_bytes() != b"PKCS 11" {
            return CKR_ARGUMENTS_BAD;
        }
    }

    // If version is specified, check compatibility
    if !p_version.is_null() {
        let ver = &*p_version;
        if ver.major > 3 || (ver.major == 3 && ver.minor > 0) {
            return CKR_ARGUMENTS_BAD;
        }
    }

    *pp_interface = &INTERFACE_3_0;
    CKR_OK
}
