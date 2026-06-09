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

//! PKCS#11 v3.0 C-compatible type definitions.
#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::c_void;

// ── Primitive type aliases ─────────────────────────────────────────────────

pub type CK_BYTE           = u8;
pub type CK_CHAR           = u8;
pub type CK_UTF8CHAR       = u8;
pub type CK_BBOOL          = CK_BYTE;
/// LP64 (Linux x86-64): `unsigned long` = 8 bytes.
pub type CK_ULONG          = u64;
pub type CK_LONG           = i64;
pub type CK_FLAGS          = CK_ULONG;
pub type CK_SLOT_ID        = CK_ULONG;
pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE  = CK_ULONG;
pub type CK_OBJECT_CLASS   = CK_ULONG;
pub type CK_KEY_TYPE       = CK_ULONG;
pub type CK_ATTRIBUTE_TYPE = CK_ULONG;
pub type CK_MECHANISM_TYPE = CK_ULONG;
pub type CK_RV             = CK_ULONG;
pub type CK_NOTIFICATION   = CK_ULONG;
pub type CK_USER_TYPE      = CK_ULONG;
pub type CK_STATE          = CK_ULONG;

pub const CK_TRUE:  CK_BBOOL = 1;
pub const CK_FALSE: CK_BBOOL = 0;
/// Sentinel for CK_ATTRIBUTE.ulValueLen when an error occurred on that attribute.
pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG = CK_ULONG::MAX;
pub const CK_EFFECTIVELY_INFINITE:    CK_ULONG = 0;
pub const CK_INVALID_HANDLE:          CK_ULONG = 0;

// ── Structs ────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}

#[repr(C)]
pub struct CK_INFO {
    pub cryptokiVersion:    CK_VERSION,
    pub manufacturerID:     [CK_UTF8CHAR; 32],
    pub flags:              CK_FLAGS,
    pub libraryDescription: [CK_UTF8CHAR; 32],
    pub libraryVersion:     CK_VERSION,
}

#[repr(C)]
pub struct CK_SLOT_INFO {
    pub slotDescription: [CK_UTF8CHAR; 64],
    pub manufacturerID:  [CK_UTF8CHAR; 32],
    pub flags:           CK_FLAGS,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
}

#[repr(C)]
pub struct CK_TOKEN_INFO {
    pub label:               [CK_UTF8CHAR; 32],
    pub manufacturerID:      [CK_UTF8CHAR; 32],
    pub model:               [CK_UTF8CHAR; 16],
    pub serialNumber:        [CK_CHAR; 16],
    pub flags:               CK_FLAGS,
    pub ulMaxSessionCount:   CK_ULONG,
    pub ulSessionCount:      CK_ULONG,
    pub ulMaxRwSessionCount: CK_ULONG,
    pub ulRwSessionCount:    CK_ULONG,
    pub ulMaxPinLen:         CK_ULONG,
    pub ulMinPinLen:         CK_ULONG,
    pub ulTotalPublicMemory: CK_ULONG,
    pub ulFreePublicMemory:  CK_ULONG,
    pub ulTotalPrivateMemory: CK_ULONG,
    pub ulFreePrivateMemory: CK_ULONG,
    pub hardwareVersion:     CK_VERSION,
    pub firmwareVersion:     CK_VERSION,
    pub utcTime:             [CK_CHAR; 16],
}

#[repr(C)]
pub struct CK_SESSION_INFO {
    pub slotID:        CK_SLOT_ID,
    pub state:         CK_STATE,
    pub flags:         CK_FLAGS,
    pub ulDeviceError: CK_ULONG,
}

#[repr(C)]
pub struct CK_MECHANISM {
    pub mechanism:      CK_MECHANISM_TYPE,
    pub pParameter:     *const c_void,
    pub ulParameterLen: CK_ULONG,
}

#[repr(C)]
pub struct CK_MECHANISM_INFO {
    pub ulMinKeySize: CK_ULONG,
    pub ulMaxKeySize: CK_ULONG,
    pub flags:        CK_FLAGS,
}

#[repr(C)]
pub struct CK_ATTRIBUTE {
    pub r#type:     CK_ATTRIBUTE_TYPE,
    pub pValue:     *mut c_void,
    pub ulValueLen: CK_ULONG,
}

// ── Mechanism parameter structs ────────────────────────────────────────────

/// `CK_AES_CTR_PARAMS` — for `CKM_AES_CTR`.
#[repr(C)]
pub struct CK_AES_CTR_PARAMS {
    pub ulCounterBits: CK_ULONG,
    pub cb:            [CK_BYTE; 16],
}

/// `CK_GCM_PARAMS` — for `CKM_AES_GCM`.
#[repr(C)]
pub struct CK_GCM_PARAMS {
    pub pIv:      *const CK_BYTE,
    pub ulIvLen:  CK_ULONG,
    pub ulIvBits: CK_ULONG,
    pub pAAD:     *const CK_BYTE,
    pub ulAADLen: CK_ULONG,
    pub ulTagBits: CK_ULONG,
}

/// `CK_GCM_MESSAGE_PARAMS` — per-message params for `C_EncryptMessage` / `C_DecryptMessage`
/// with `CKM_AES_GCM`.  `pIv` and `pTag` are caller-owned mutable buffers.
#[repr(C)]
pub struct CK_GCM_MESSAGE_PARAMS {
    pub pIv:           *mut CK_BYTE,   // IV buffer (input on encrypt, written on decrypt)
    pub ulIvLen:       CK_ULONG,       // IV length in bytes (12 for standard GCM)
    pub ulIvFixedBits: CK_ULONG,       // bits of IV that are fixed (ignored, we take full IV)
    pub ivGenerator:   CK_ULONG,       // CK_GCM_GENERATOR_FUNCTION — ignored (caller supplies IV)
    pub pTag:          *mut CK_BYTE,   // tag buffer: written by encrypt, read by decrypt
    pub ulTagBits:     CK_ULONG,       // tag length in bits (128 = 16 bytes for AES-GCM)
}

/// `CK_CHACHA20_POLY1305_MESSAGE_PARAMS` — per-message params for `C_EncryptMessage` /
/// `C_DecryptMessage` with `CKM_CHACHA20_POLY1305`.  Same field layout as
/// `CK_GCM_MESSAGE_PARAMS`.
#[repr(C)]
pub struct CK_CHACHA20_POLY1305_MESSAGE_PARAMS {
    pub pNonce:           *mut CK_BYTE,
    pub ulNonceLen:       CK_ULONG,
    pub ulNonceFixedBits: CK_ULONG,
    pub nonceGenerator:   CK_ULONG,
    pub pTag:             *mut CK_BYTE,
    pub ulTagBits:        CK_ULONG,
}

/// `CK_ECDH1_DERIVE_PARAMS` — for `CKM_ECDH1_DERIVE`.
#[repr(C)]
pub struct CK_ECDH1_DERIVE_PARAMS {
    /// KDF to apply to shared secret (CKD_NULL = raw secret).
    pub kdf:             CK_ULONG,
    pub ulSharedDataLen: CK_ULONG,
    pub pSharedData:     *const CK_BYTE,
    /// Other party's public key: raw uncompressed point (04||x||y).
    pub ulPublicDataLen: CK_ULONG,
    pub pPublicData:     *const CK_BYTE,
}

// ── Callback / init args ───────────────────────────────────────────────────

pub type CK_NOTIFY = Option<unsafe extern "C" fn(
    hSession:     CK_SESSION_HANDLE,
    event:        CK_NOTIFICATION,
    pApplication: *mut c_void,
) -> CK_RV>;

pub type CK_CREATEMUTEX  = Option<unsafe extern "C" fn(*mut *mut c_void) -> CK_RV>;
pub type CK_DESTROYMUTEX = Option<unsafe extern "C" fn(*mut c_void)      -> CK_RV>;
pub type CK_LOCKMUTEX    = Option<unsafe extern "C" fn(*mut c_void)      -> CK_RV>;
pub type CK_UNLOCKMUTEX  = Option<unsafe extern "C" fn(*mut c_void)      -> CK_RV>;

#[repr(C)]
pub struct CK_C_INITIALIZE_ARGS {
    pub CreateMutex:  CK_CREATEMUTEX,
    pub DestroyMutex: CK_DESTROYMUTEX,
    pub LockMutex:    CK_LOCKMUTEX,
    pub UnlockMutex:  CK_UNLOCKMUTEX,
    pub flags:        CK_FLAGS,
    pub pReserved:    *mut c_void,
}

// ── CK_FUNCTION_LIST ───────────────────────────────────────────────────────

/// PKCS#11 v2.40 function list — 68 function-pointer slots.
#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,
    pub C_Initialize:           Option<unsafe extern "C" fn(*mut CK_C_INITIALIZE_ARGS) -> CK_RV>,
    pub C_Finalize:             Option<unsafe extern "C" fn(*mut c_void) -> CK_RV>,
    pub C_GetInfo:              Option<unsafe extern "C" fn(*mut CK_INFO) -> CK_RV>,
    pub C_GetFunctionList:      Option<unsafe extern "C" fn(*mut *const CK_FUNCTION_LIST) -> CK_RV>,
    pub C_GetSlotList:          Option<unsafe extern "C" fn(CK_BBOOL, *mut CK_SLOT_ID, *mut CK_ULONG) -> CK_RV>,
    pub C_GetSlotInfo:          Option<unsafe extern "C" fn(CK_SLOT_ID, *mut CK_SLOT_INFO) -> CK_RV>,
    pub C_GetTokenInfo:         Option<unsafe extern "C" fn(CK_SLOT_ID, *mut CK_TOKEN_INFO) -> CK_RV>,
    pub C_GetMechanismList:     Option<unsafe extern "C" fn(CK_SLOT_ID, *mut CK_MECHANISM_TYPE, *mut CK_ULONG) -> CK_RV>,
    pub C_GetMechanismInfo:     Option<unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, *mut CK_MECHANISM_INFO) -> CK_RV>,
    pub C_InitToken:            Option<unsafe extern "C" fn(CK_SLOT_ID, *const CK_UTF8CHAR, CK_ULONG, *const CK_UTF8CHAR) -> CK_RV>,
    pub C_InitPIN:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_UTF8CHAR, CK_ULONG) -> CK_RV>,
    pub C_SetPIN:               Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_UTF8CHAR, CK_ULONG, *const CK_UTF8CHAR, CK_ULONG) -> CK_RV>,
    pub C_OpenSession:          Option<unsafe extern "C" fn(CK_SLOT_ID, CK_FLAGS, *mut c_void, CK_NOTIFY, *mut CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CloseSession:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CloseAllSessions:     Option<unsafe extern "C" fn(CK_SLOT_ID) -> CK_RV>,
    pub C_GetSessionInfo:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_SESSION_INFO) -> CK_RV>,
    pub C_GetOperationState:    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_SetOperationState:    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Login:                Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, *const CK_UTF8CHAR, CK_ULONG) -> CK_RV>,
    pub C_Logout:               Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CreateObject:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_CopyObject:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_DestroyObject:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_GetObjectSize:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ULONG) -> CK_RV>,
    pub C_GetAttributeValue:    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV>,
    pub C_SetAttributeValue:    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV>,
    pub C_FindObjectsInit:      Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_ATTRIBUTE, CK_ULONG) -> CK_RV>,
    pub C_FindObjects:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_OBJECT_HANDLE, CK_ULONG, *mut CK_ULONG) -> CK_RV>,
    pub C_FindObjectsFinal:     Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_EncryptInit:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Encrypt:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_EncryptUpdate:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_EncryptFinal:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DecryptInit:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Decrypt:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DecryptUpdate:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DecryptFinal:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DigestInit:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM) -> CK_RV>,
    pub C_Digest:               Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DigestUpdate:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_DigestKey:            Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_DigestFinal:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_SignInit:             Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Sign:                 Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_SignUpdate:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_SignFinal:            Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_SignRecoverInit:      Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_SignRecover:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_VerifyInit:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Verify:               Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_VerifyUpdate:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_VerifyFinal:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_VerifyRecoverInit:    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_VerifyRecover:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DigestEncryptUpdate:  Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DecryptDigestUpdate:  Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_SignEncryptUpdate:    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DecryptVerifyUpdate:  Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_GenerateKey:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_GenerateKeyPair:      Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, *const CK_ATTRIBUTE, CK_ULONG, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_WrapKey:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_UnwrapKey:            Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE, *const CK_BYTE, CK_ULONG, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_DeriveKey:            Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_SeedRandom:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_GenerateRandom:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_GetFunctionStatus:    Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CancelFunction:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_WaitForSlotEvent:     Option<unsafe extern "C" fn(CK_FLAGS, *mut CK_SLOT_ID, *mut c_void) -> CK_RV>,
}

// SAFETY: all fields are function pointers (inherently Sync) or CK_VERSION (Copy).
unsafe impl Sync for CK_FUNCTION_LIST {}

// ── PKCS#11 v3.0 additions ───────────────────────────────────────────────

/// `CK_INTERFACE` — v3.0 interface discovery struct.
#[repr(C)]
pub struct CK_INTERFACE {
    pub pInterfaceName: *const CK_CHAR,
    pub pFunctionList:  *const c_void,
    pub flags:          CK_FLAGS,
}

// SAFETY: all fields are raw pointers to immutable statics or CK_FLAGS (Copy).
unsafe impl Sync for CK_INTERFACE {}
unsafe impl Send for CK_INTERFACE {}

/// `CK_FUNCTION_LIST_3_0` — extended function list with v3.0 functions.
/// Extends v2.40 with message-based APIs, C_SessionCancel, C_LoginUser, etc.
#[repr(C)]
pub struct CK_FUNCTION_LIST_3_0 {
    pub version: CK_VERSION,

    // ── v2.40 functions (same order as CK_FUNCTION_LIST) ─────────────────
    pub C_Initialize:          Option<unsafe extern "C" fn(*mut CK_C_INITIALIZE_ARGS) -> CK_RV>,
    pub C_Finalize:            Option<unsafe extern "C" fn(*mut c_void) -> CK_RV>,
    pub C_GetInfo:             Option<unsafe extern "C" fn(*mut CK_INFO) -> CK_RV>,
    pub C_GetFunctionList:     Option<unsafe extern "C" fn(*mut *const CK_FUNCTION_LIST) -> CK_RV>,
    pub C_GetSlotList:         Option<unsafe extern "C" fn(CK_BBOOL, *mut CK_SLOT_ID, *mut CK_ULONG) -> CK_RV>,
    pub C_GetSlotInfo:         Option<unsafe extern "C" fn(CK_SLOT_ID, *mut CK_SLOT_INFO) -> CK_RV>,
    pub C_GetTokenInfo:        Option<unsafe extern "C" fn(CK_SLOT_ID, *mut CK_TOKEN_INFO) -> CK_RV>,
    pub C_GetMechanismList:    Option<unsafe extern "C" fn(CK_SLOT_ID, *mut CK_MECHANISM_TYPE, *mut CK_ULONG) -> CK_RV>,
    pub C_GetMechanismInfo:    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, *mut CK_MECHANISM_INFO) -> CK_RV>,
    pub C_InitToken:           Option<unsafe extern "C" fn(CK_SLOT_ID, *const CK_UTF8CHAR, CK_ULONG, *const CK_UTF8CHAR) -> CK_RV>,
    pub C_InitPIN:             Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_UTF8CHAR, CK_ULONG) -> CK_RV>,
    pub C_SetPIN:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_UTF8CHAR, CK_ULONG, *const CK_UTF8CHAR, CK_ULONG) -> CK_RV>,
    pub C_OpenSession:         Option<unsafe extern "C" fn(CK_SLOT_ID, CK_FLAGS, *mut c_void, CK_NOTIFY, *mut CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CloseSession:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CloseAllSessions:    Option<unsafe extern "C" fn(CK_SLOT_ID) -> CK_RV>,
    pub C_GetSessionInfo:      Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_SESSION_INFO) -> CK_RV>,
    pub C_GetOperationState:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_SetOperationState:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Login:               Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, *const CK_UTF8CHAR, CK_ULONG) -> CK_RV>,
    pub C_Logout:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CreateObject:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_CopyObject:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_DestroyObject:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_GetObjectSize:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ULONG) -> CK_RV>,
    pub C_GetAttributeValue:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV>,
    pub C_SetAttributeValue:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV>,
    pub C_FindObjectsInit:     Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_ATTRIBUTE, CK_ULONG) -> CK_RV>,
    pub C_FindObjects:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_OBJECT_HANDLE, CK_ULONG, *mut CK_ULONG) -> CK_RV>,
    pub C_FindObjectsFinal:    Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_EncryptInit:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Encrypt:             Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_EncryptUpdate:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_EncryptFinal:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DecryptInit:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Decrypt:             Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DecryptUpdate:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DecryptFinal:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DigestInit:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM) -> CK_RV>,
    pub C_Digest:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DigestUpdate:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_DigestKey:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_DigestFinal:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_SignInit:            Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Sign:                Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_SignUpdate:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_SignFinal:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_SignRecoverInit:     Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_SignRecover:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_VerifyInit:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Verify:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_VerifyUpdate:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_VerifyFinal:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_VerifyRecoverInit:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_VerifyRecover:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DigestEncryptUpdate: Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DecryptDigestUpdate: Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_SignEncryptUpdate:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DecryptVerifyUpdate: Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_GenerateKey:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_GenerateKeyPair:     Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, *const CK_ATTRIBUTE, CK_ULONG, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_WrapKey:             Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_UnwrapKey:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE, *const CK_BYTE, CK_ULONG, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_DeriveKey:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_SeedRandom:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_GenerateRandom:      Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_GetFunctionStatus:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CancelFunction:      Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_WaitForSlotEvent:    Option<unsafe extern "C" fn(CK_FLAGS, *mut CK_SLOT_ID, *mut c_void) -> CK_RV>,

    // ── v3.0 new functions ───────────────────────────────────────────────
    pub C_GetInterfaceList:    Option<unsafe extern "C" fn(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV>,
    pub C_GetInterface:        Option<unsafe extern "C" fn(*const CK_UTF8CHAR, *mut CK_VERSION, *mut *const CK_INTERFACE, CK_FLAGS) -> CK_RV>,
    pub C_LoginUser:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, *const CK_UTF8CHAR, CK_ULONG, *const CK_UTF8CHAR, CK_ULONG) -> CK_RV>,
    pub C_SessionCancel:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_FLAGS) -> CK_RV>,

    // Message-based encryption
    pub C_MessageEncryptInit:  Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_EncryptMessage:      Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG, *const CK_BYTE, CK_ULONG, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_EncryptMessageBegin: Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_EncryptMessageNext:  Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG, CK_FLAGS) -> CK_RV>,
    pub C_MessageEncryptFinal: Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,

    // Message-based decryption
    pub C_MessageDecryptInit:  Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_DecryptMessage:      Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG, *const CK_BYTE, CK_ULONG, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_DecryptMessageBegin: Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_DecryptMessageNext:  Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG, CK_FLAGS) -> CK_RV>,
    pub C_MessageDecryptFinal: Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,

    // Message-based signing
    pub C_MessageSignInit:     Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_SignMessage:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_SignMessageBegin:    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG) -> CK_RV>,
    pub C_SignMessageNext:     Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV>,
    pub C_MessageSignFinal:    Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,

    // Message-based verification
    pub C_MessageVerifyInit:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_VerifyMessage:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG, *const CK_BYTE, CK_ULONG, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_VerifyMessageBegin:  Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG) -> CK_RV>,
    pub C_VerifyMessageNext:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *const c_void, CK_ULONG, *const CK_BYTE, CK_ULONG, *const CK_BYTE, CK_ULONG) -> CK_RV>,
    pub C_MessageVerifyFinal:  Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
}

// SAFETY: all fields are function pointers or CK_VERSION.
unsafe impl Sync for CK_FUNCTION_LIST_3_0 {}

/// Profile ID type (v3.0).
pub type CK_PROFILE_ID = CK_ULONG;

/// `CK_HKDF_PARAMS` — for `CKM_HKDF_DERIVE` (v3.0).
#[repr(C)]
pub struct CK_HKDF_PARAMS {
    pub bExtract:     CK_BBOOL,
    pub bExpand:      CK_BBOOL,
    pub prfHashMechanism: CK_MECHANISM_TYPE,
    pub ulSaltType:   CK_ULONG,
    pub pSalt:        *const CK_BYTE,
    pub ulSaltLen:    CK_ULONG,
    pub hSaltKey:     CK_OBJECT_HANDLE,
    pub pInfo:        *const CK_BYTE,
    pub ulInfoLen:    CK_ULONG,
}
