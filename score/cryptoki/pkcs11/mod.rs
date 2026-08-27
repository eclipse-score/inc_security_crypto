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

//! PKCS#11 v3.0 FFI layer — all C_* functions inline.
//!
//! Architecture:
//!   C caller → mod.rs (FFI, ck_try!) → session.rs → token.rs → object_store.rs → backend.rs
#![allow(non_snake_case, dead_code, unused_variables)]
// C FFI exports: safety contracts are defined by the PKCS#11 specification,
// not by inline Rust doc comments.
#![allow(clippy::missing_safety_doc)]

pub mod attribute_policy;
pub mod backend;
pub mod constants;
pub mod error;
pub mod mechanisms;
pub mod object_store;
pub mod session;
pub mod storage;
pub mod token;
pub mod types;

use score_log::{debug, info, trace, warn};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Once, OnceLock, RwLock};

use constants::*;
use error::Pkcs11Error;
use object_store::with_object;
use session::{CipherContext, DigestContext, FindContext, LoginState, MessageCipherContext, SignContext};
use types::*;

// ── GlobalState ───────────────────────────────────────────────────────────

/// Lightweight lifecycle coordinator.  All actual stores (sessions, objects,
/// tokens, registry) live in their own module-level statics; `GlobalState`
/// coordinates initialization order and drives the shutdown sequence.
struct GlobalState;

impl GlobalState {
    fn shutdown(&mut self) {
        // 1. Drop active sessions (operation contexts, login state).
        session::clear_sessions();
        // 2. Persist token objects while the engine/registry is still live.
        object_store::persist_to_disk();
        // 3. Zeroize and drop all in-memory key material.
        object_store::clear_objects();
        // 4. Clear token metadata (PINs, flags).
        token::clear_tokens();
        // 5. Drop engine Arc refs — engine destructors run here.
        crate::registry::reset_registry();
    }

    /// Reseed the process RNG after fork so parent and child do not share state.
    ///
    /// OpenSSL 1.1+ reseeds automatically when the PID changes, but an explicit
    /// call to `rand_bytes` guarantees the reseed happens immediately in the child.
    fn reseed_rng() {
        let mut buf = [0u8; 32];
        let _ = openssl::rand::rand_bytes(&mut buf);
    }
}

/// The initialized state of the library.
///
/// `OnceLock` initialises the `RwLock` exactly once for the lifetime of the
/// process.  The `Option<GlobalState>` inside toggles between `None` (not
/// initialised) and `Some` (initialised), enabling repeated Init/Finalize cycles.
static GLOBAL: OnceLock<RwLock<Option<GlobalState>>> = OnceLock::new();

fn global() -> &'static RwLock<Option<GlobalState>> {
    GLOBAL.get_or_init(|| RwLock::new(None))
}

/// Registered via `pthread_atfork(None, None, Some(child_after_fork))` exactly
/// once.  Called in the child process immediately after `fork(2)`.
///
/// The child inherits open file descriptors (and any associated `flock` locks)
/// from the parent.  We release those locks, reseed the RNG to avoid parent/child
/// RNG correlation, and let each engine perform its own post-fork cleanup.
///
/// We use `try_write()` rather than `write()`: if another thread held the global
/// lock at the moment of `fork`, `write()` would deadlock in the child (that
/// thread no longer exists).  `try_write()` fails gracefully in that case.
extern "C" fn child_after_fork() {
    if let Some(global) = GLOBAL.get() {
        if let Ok(guard) = global.try_write() {
            if guard.is_some() {
                storage::release_locks();
                GlobalState::reseed_rng();
                crate::registry::for_each_engine(|e| e.post_fork_child());
            }
        }
    }
}

/// Ensures `pthread_atfork` is registered at most once per process.
static ATFORK_REGISTERED: Once = Once::new();

// ── Macro ─────────────────────────────────────────────────────────────────

macro_rules! ck_try {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return e.to_ckr(),
        }
    };
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn check_init() -> error::Result<()> {
    if global().read().is_ok_and(|g| g.is_some()) {
        Ok(())
    } else {
        Err(Pkcs11Error::NotInitialised)
    }
}

/// Extract the slot_id from a session handle.
fn session_slot(h_session: CK_SESSION_HANDLE) -> error::Result<CK_SLOT_ID> {
    session::with_session(h_session, |s| Ok(s.slot_id))
}

/// Return `Err(SessionReadOnly)` if the session is not a read-write session.
fn require_rw_session(h_session: CK_SESSION_HANDLE) -> error::Result<()> {
    session::with_session(h_session, |s| s.require_rw())
}

/// Return `true` if `attr_type` is present in `obj.attributes` and its first byte
/// equals `CK_TRUE`.  Any other value (absent, empty, or `CK_FALSE`) returns `false`.
fn bool_attr_true(obj: &object_store::KeyObject, attr_type: CK_ATTRIBUTE_TYPE) -> bool {
    obj.attributes
        .get(&attr_type)
        .is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE)
}

fn is_private_component_attr(attr_type: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(
        attr_type,
        CKA_PRIVATE_EXPONENT | CKA_PRIME_1 | CKA_PRIME_2 | CKA_EXPONENT_1 | CKA_EXPONENT_2 | CKA_COEFFICIENT
    )
}

fn fill_padded(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    for b in &mut dst[n..] {
        *b = b' ';
    }
}

/// Copy `data` into a caller-provided PKCS#11 output buffer, handling the
/// three-phase protocol: size query (null pointer), buffer-too-small, or copy.
unsafe fn write_to_output(p_out: *mut CK_BYTE, pul_len: *mut CK_ULONG, data: &[u8]) -> CK_RV {
    if p_out.is_null() {
        *pul_len = data.len() as CK_ULONG;
        return CKR_OK;
    }
    if (*pul_len as usize) < data.len() {
        *pul_len = data.len() as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(data.as_ptr(), p_out, data.len());
    *pul_len = data.len() as CK_ULONG;
    CKR_OK
}

mod ffi_api_core;
mod ffi_api_crypto;
mod ffi_api_v3;

pub use ffi_api_core::*;
pub use ffi_api_crypto::*;
pub use ffi_api_v3::*;

// ── Static CK_INTERFACE (v3.0) ──────────────────────────────────────────

static INTERFACE_3_0: CK_INTERFACE = CK_INTERFACE {
    pInterfaceName: PKCS11_INTERFACE_NAME.as_ptr() as *const libc::c_char as *mut _,
    pFunctionList: &FUNCTION_LIST_3_0 as *const CK_FUNCTION_LIST_3_0 as *const c_void,
    flags: CKF_INTERFACE_FORK_SAFE,
};

// ── Static FUNCTION_LIST_3_0 (v3.0 extended) ─────────────────────────────

pub static FUNCTION_LIST_3_0: CK_FUNCTION_LIST_3_0 = CK_FUNCTION_LIST_3_0 {
    version: CK_VERSION { major: 3, minor: 0 },

    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),

    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),

    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),

    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),

    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),

    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),

    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),

    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),

    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),

    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),

    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),

    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),

    // v3.0 new functions
    C_GetInterfaceList: Some(C_GetInterfaceList),
    C_GetInterface: Some(C_GetInterface),
    C_LoginUser: Some(C_LoginUser),
    C_SessionCancel: Some(C_SessionCancel),

    C_MessageEncryptInit: Some(C_MessageEncryptInit),
    C_EncryptMessage: Some(C_EncryptMessage),
    C_EncryptMessageBegin: Some(C_EncryptMessageBegin),
    C_EncryptMessageNext: Some(C_EncryptMessageNext),
    C_MessageEncryptFinal: Some(C_MessageEncryptFinal),

    C_MessageDecryptInit: Some(C_MessageDecryptInit),
    C_DecryptMessage: Some(C_DecryptMessage),
    C_DecryptMessageBegin: Some(C_DecryptMessageBegin),
    C_DecryptMessageNext: Some(C_DecryptMessageNext),
    C_MessageDecryptFinal: Some(C_MessageDecryptFinal),

    C_MessageSignInit: Some(C_MessageSignInit),
    C_SignMessage: Some(C_SignMessage),
    C_SignMessageBegin: Some(C_SignMessageBegin),
    C_SignMessageNext: Some(C_SignMessageNext),
    C_MessageSignFinal: Some(C_MessageSignFinal),

    C_MessageVerifyInit: Some(C_MessageVerifyInit),
    C_VerifyMessage: Some(C_VerifyMessage),
    C_VerifyMessageBegin: Some(C_VerifyMessageBegin),
    C_VerifyMessageNext: Some(C_VerifyMessageNext),
    C_MessageVerifyFinal: Some(C_MessageVerifyFinal),
};

// ── Static FUNCTION_LIST (v2.40 compat) + top-level #[no_mangle] export ──

pub static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 3, minor: 0 },

    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),

    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),

    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),

    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),

    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),

    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),

    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),

    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),

    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),

    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),

    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),

    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};
