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

// ── C_Initialize / C_Finalize ─────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_Initialize(p_init_args: *mut CK_C_INITIALIZE_ARGS) -> CK_RV {
    // one-time logging initialization. MUST be the first line
    // to ensure subsequent info!/warn! macros are not dropped.
    crate::logger::init();

    info!(context: "CONFIG", "C_Initialize called");

    // Parse and validate the threading model.
    //
    // | CKF_OS_LOCKING_OK | Mutex callbacks | Action                           |
    // |-------------------|-----------------|----------------------------------|
    // | No                | NULL            | Single-threaded; accept.         |
    // | Yes               | NULL            | OS locking (parking_lot); accept.|
    // | No                | Non-NULL        | App mutexes only; CKR_CANT_LOCK. |
    // | Yes               | Non-NULL        | Prefer OS locking; ignore cbs.   |
    if !p_init_args.is_null() {
        let args = &*p_init_args;
        if !args.pReserved.is_null() {
            warn!(context: "FFI", "C_Initialize rejected: pReserved must be NULL");
            return CKR_ARGUMENTS_BAD;
        }
        let has_callbacks = args.CreateMutex.is_some()
            || args.DestroyMutex.is_some()
            || args.LockMutex.is_some()
            || args.UnlockMutex.is_some();
        let os_locking_ok = args.flags & CKF_OS_LOCKING_OK != 0;
        if has_callbacks && !os_locking_ok {
            // App-supplied mutexes without OS locking — we cannot use them (v1).
            warn!(context: "CONFIG", "C_Initialize rejected: mutex callbacks without CKF_OS_LOCKING_OK");
            return CKR_CANT_LOCK;
        }
        // All other cases: we use parking_lot (OS-level locking) regardless.
    }

    // Guard against double-initialization.
    let mut guard = global().write().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        warn!(context: "CONFIG", "C_Initialize called while already initialized");
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    // Register the OpenSSL engine and ensure a token exists for each slot.
    let slot_ids = match crate::registry::register_engine(crate::openssl_provider::OpenSslEngine) {
        Ok(ids) => ids,
        Err(_) => crate::registry::slot_ids(), // already registered on re-init
    };
    for &sid in &slot_ids {
        token::ensure_token(sid);
    }

    // Restore persisted token objects from disk.
    object_store::load_persisted_objects();

    // Ensure every slot advertises at least one profile.
    // Profile objects are not persisted, so they must be re-created on each init.
    for &sid in &slot_ids {
        object_store::ensure_baseline_profile(sid);
    }

    *guard = Some(GlobalState);
    info!(context: "CONFIG", "PKCS#11 initialized for {} slot(s)", slot_ids.len());

    // Register the post-fork child handler exactly once for the process lifetime.
    // Must happen after `*guard = Some(...)` so the child handler sees an
    // initialized library if fork occurs immediately after.
    ATFORK_REGISTERED.call_once(|| {
        unsafe { libc::pthread_atfork(None, None, Some(child_after_fork)); }
    });

    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_Finalize(p_reserved: *mut c_void) -> CK_RV {
    info!(context: "CONFIG", "C_Finalize called");
    // PKCS#11 pReserved must be NULL.
    if !p_reserved.is_null() {
        warn!(context: "FFI", "C_Finalize rejected: pReserved must be NULL");
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = global().write().unwrap_or_else(|e| e.into_inner());
    let state = match guard.as_mut() {
        Some(s) => s,
        None    => { warn!(context: "CONFIG", "C_Finalize called while not initialized"); return CKR_CRYPTOKI_NOT_INITIALIZED; },
    };
    state.shutdown();
    *guard = None;
    info!(context: "CONFIG", "PKCS#11 finalized");
    CKR_OK
}

// ── C_GetInfo ─────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_GetInfo(p_info: *mut CK_INFO) -> CK_RV {
    ck_try!(check_init());
    if p_info.is_null() { return CKR_ARGUMENTS_BAD; }
    let info = &mut *p_info;
    info.cryptokiVersion    = CK_VERSION { major: 3, minor: 0 };
    fill_padded(&mut info.manufacturerID,     b"Cryptoki");
    info.flags              = 0;
    fill_padded(&mut info.libraryDescription, b"Cryptoki v3.0");
    info.libraryVersion     = CK_VERSION { major: 1, minor: 0 };
    CKR_OK
}

// ── C_GetFunctionList ─────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(
    ppFunctionList: *mut *const CK_FUNCTION_LIST,
) -> CK_RV {
    if ppFunctionList.is_null() { return CKR_ARGUMENTS_BAD; }
    *ppFunctionList = &FUNCTION_LIST;
    CKR_OK
}

// ── Slot / Token ──────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_GetSlotList(
    _token_present: CK_BBOOL,
    p_slot_list:    *mut CK_SLOT_ID,
    pul_count:      *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CONFIG", "C_GetSlotList called");
    if pul_count.is_null() { return CKR_ARGUMENTS_BAD; }
    let ids = crate::registry::slot_ids();
    let n = ids.len() as CK_ULONG;
    if p_slot_list.is_null() {
        *pul_count = n;
        return CKR_OK;
    }
    if *pul_count < n {
        *pul_count = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (i, &sid) in ids.iter().enumerate() {
        *p_slot_list.add(i) = sid;
    }
    *pul_count = n;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetSlotInfo(slot_id: CK_SLOT_ID, p_info: *mut CK_SLOT_INFO) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CONFIG", "C_GetSlotInfo called slot={}", slot_id);
    let (engine, internal_id) = match crate::registry::engine_for_slot(slot_id) {
        Ok(pair) => pair,
        Err(_)   => return CKR_SLOT_ID_INVALID,
    };
    if p_info.is_null() { return CKR_ARGUMENTS_BAD; }
    let info = &mut *p_info;
    fill_padded(&mut info.slotDescription, engine.slot_description(internal_id).as_bytes());
    fill_padded(&mut info.manufacturerID,  b"Cryptoki");
    info.flags           = CKF_TOKEN_PRESENT;
    info.hardwareVersion = CK_VERSION { major: 1, minor: 0 };
    info.firmwareVersion = CK_VERSION { major: 1, minor: 0 };
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetTokenInfo(slot_id: CK_SLOT_ID, p_info: *mut CK_TOKEN_INFO) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CONFIG", "C_GetTokenInfo called slot={}", slot_id);
    let (engine, internal_id) = match crate::registry::engine_for_slot(slot_id) {
        Ok(pair) => pair,
        Err(_)   => return CKR_SLOT_ID_INVALID,
    };
    if p_info.is_null() { return CKR_ARGUMENTS_BAD; }
    let info = &mut *p_info;
    token::with_token(slot_id, |tok| {
        info.label = tok.label;
        fill_padded(&mut info.manufacturerID, b"Cryptoki");
        fill_padded(&mut info.model,          engine.token_model(internal_id).as_bytes());
        info.serialNumber         = tok.serial_number;
        info.flags                = tok.token_flags();
        info.ulMaxSessionCount    = CK_EFFECTIVELY_INFINITE;
        info.ulSessionCount       = session::session_count_for_slot(slot_id) as CK_ULONG;
        info.ulMaxRwSessionCount  = CK_EFFECTIVELY_INFINITE;
        info.ulRwSessionCount     = session::rw_session_count_for_slot(slot_id) as CK_ULONG;
        info.ulMaxPinLen          = tok.max_pin_len as CK_ULONG;
        info.ulMinPinLen          = tok.min_pin_len as CK_ULONG;
        info.ulTotalPublicMemory  = CK_ULONG::MAX;
        info.ulFreePublicMemory   = CK_ULONG::MAX;
        info.ulTotalPrivateMemory = CK_ULONG::MAX;
        info.ulFreePrivateMemory  = CK_ULONG::MAX;
        info.hardwareVersion      = CK_VERSION { major: 1, minor: 0 };
        info.firmwareVersion      = CK_VERSION { major: 1, minor: 0 };
        fill_padded(&mut info.utcTime,        b"0000000000000000");
    });
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetMechanismList(
    slot_id:    CK_SLOT_ID,
    p_list:     *mut CK_MECHANISM_TYPE,
    pul_count:  *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CONFIG", "C_GetMechanismList called slot={}", slot_id);
    let (engine, internal_id) = match crate::registry::engine_for_slot(slot_id) {
        Ok(pair) => pair,
        Err(_)   => return CKR_SLOT_ID_INVALID,
    };
    if pul_count.is_null() { return CKR_ARGUMENTS_BAD; }
    // Ask the engine first; fall back to global list for backward compat.
    let engine_mechs = engine.supported_mechanisms(internal_id);
    let base: &[CK_MECHANISM_TYPE] = if engine_mechs.is_empty() { SUPPORTED_MECHANISMS } else { engine_mechs };
    // Filter out Legacy (unless CRYPTOKI_LEGACY=1) and Forbidden mechanisms.
    let mechs: Vec<CK_MECHANISM_TYPE> = base.iter()
        .copied()
        .filter(|&m| mechanisms::is_mechanism_allowed(m, None))
        .collect();
    if p_list.is_null() {
        *pul_count = mechs.len() as CK_ULONG;
        return CKR_OK;
    }
    if (*pul_count as usize) < mechs.len() {
        *pul_count = mechs.len() as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (i, m) in mechs.iter().enumerate() {
        *p_list.add(i) = *m;
    }
    *pul_count = mechs.len() as CK_ULONG;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slot_id:   CK_SLOT_ID,
    mech_type: CK_MECHANISM_TYPE,
    p_info:    *mut CK_MECHANISM_INFO,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CONFIG", "C_GetMechanismInfo called slot={} mech={}", slot_id, mech_type);
    let (engine, internal_id) = match crate::registry::engine_for_slot(slot_id) {
        Ok(pair) => pair,
        Err(_)   => return CKR_SLOT_ID_INVALID,
    };
    if p_info.is_null() { return CKR_ARGUMENTS_BAD; }
    let engine_mechs = engine.supported_mechanisms(internal_id);
    let mechs: &[CK_MECHANISM_TYPE] = if engine_mechs.is_empty() { SUPPORTED_MECHANISMS } else { engine_mechs };
    if !mechs.contains(&mech_type) { return CKR_MECHANISM_INVALID; }
    // Reject legacy/forbidden mechanisms unless the env var opts in.
    if !mechanisms::is_mechanism_allowed(mech_type, None) { return CKR_MECHANISM_INVALID; }
    let info = &mut *p_info;

    // Try engine-sourced info first; fall back to hardcoded table for engines
    // that do not implement mechanism_info().
    if let Some(eng_info) = engine.mechanism_info(internal_id as usize, mech_type) {
        info.ulMinKeySize = eng_info.min_key_size as CK_ULONG;
        info.ulMaxKeySize = eng_info.max_key_size as CK_ULONG;
        info.flags        = eng_info.flags        as CK_FLAGS;
    } else {
        // Fallback hardcoded table — used when the engine returns None.
        get_mechanism_info_fallback(mech_type, info);
    }
    CKR_OK
}

/// True for mechanisms whose key operand is an RSA key, so that the RSA
/// minimum-key-size policy (≥ 2048 bits) is applied to engine-reported
/// values.
fn is_rsa_key_mechanism(mech: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mech,
        CKM_RSA_PKCS_KEY_PAIR_GEN
        | CKM_RSA_PKCS
        | CKM_RSA_PKCS_OAEP
        | CKM_SHA1_RSA_PKCS
        | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA256_RSA_PKCS
        | CKM_SHA384_RSA_PKCS
        | CKM_SHA512_RSA_PKCS
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA512_RSA_PKCS_PSS
    )
}

/// Hardcoded mechanism info table — fallback for engines that do not implement
/// `CryptoProvider::mechanism_info()`.
fn get_mechanism_info_fallback(mech_type: CK_MECHANISM_TYPE, info: &mut CK_MECHANISM_INFO) {
    match mech_type {
        CKM_RSA_PKCS_KEY_PAIR_GEN => {
            info.ulMinKeySize = 1024;
            info.ulMaxKeySize = 16384;
            info.flags = CKF_GENERATE_KEY_PAIR;
        }
        CKM_RSA_PKCS => {
            info.ulMinKeySize = 1024;
            info.ulMaxKeySize = 16384;
            info.flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;
        }
        CKM_RSA_PKCS_OAEP => {
            info.ulMinKeySize = 1024;
            info.ulMaxKeySize = 16384;
            info.flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;
        }
        CKM_SHA1_RSA_PKCS | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS
        | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS => {
            info.ulMinKeySize = 1024;
            info.ulMaxKeySize = 16384;
            info.flags = CKF_SIGN | CKF_VERIFY;
        }
        CKM_EC_KEY_PAIR_GEN => {
            info.ulMinKeySize = 256; info.ulMaxKeySize = 521;
            info.flags = CKF_GENERATE_KEY_PAIR;
        }
        CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512 => {
            info.ulMinKeySize = 256; info.ulMaxKeySize = 521;
            info.flags = CKF_SIGN | CKF_VERIFY;
        }
        CKM_ECDH1_DERIVE => {
            info.ulMinKeySize = 256; info.ulMaxKeySize = 521;
            info.flags = CKF_DERIVE;
        }
        CKM_EC_EDWARDS_KEY_PAIR_GEN => {
            info.ulMinKeySize = 255; info.ulMaxKeySize = 448;
            info.flags = CKF_GENERATE_KEY_PAIR;
        }
        CKM_EDDSA => {
            info.ulMinKeySize = 255; info.ulMaxKeySize = 448;
            info.flags = CKF_SIGN | CKF_VERIFY;
        }
        CKM_AES_KEY_GEN | CKM_DES_KEY_GEN | CKM_DES3_KEY_GEN => {
            info.ulMinKeySize = 16; info.ulMaxKeySize = 32;
            info.flags = CKF_GENERATE;
        }
        CKM_AES_ECB | CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_DES_ECB | CKM_DES_CBC | CKM_DES3_ECB | CKM_DES3_CBC => {
            info.ulMinKeySize = 16; info.ulMaxKeySize = 32;
            info.flags = CKF_ENCRYPT | CKF_DECRYPT;
        }
        CKM_AES_CTR | CKM_AES_GCM => {
            info.ulMinKeySize = 16; info.ulMaxKeySize = 32;
            info.flags = CKF_ENCRYPT | CKF_DECRYPT;
        }
        CKM_AES_KEY_WRAP => {
            info.ulMinKeySize = 16; info.ulMaxKeySize = 32;
            info.flags = CKF_WRAP | CKF_UNWRAP;
        }
        CKM_CHACHA20_KEY_GEN => {
            info.ulMinKeySize = 32; info.ulMaxKeySize = 32;
            info.flags = CKF_GENERATE;
        }
        CKM_CHACHA20_POLY1305 => {
            info.ulMinKeySize = 32; info.ulMaxKeySize = 32;
            info.flags = CKF_ENCRYPT | CKF_DECRYPT;
        }
        CKM_MD5 | CKM_SHA_1 | CKM_SHA256 | CKM_SHA384 | CKM_SHA512
        | CKM_SHA3_256 | CKM_SHA3_384 | CKM_SHA3_512 => {
            info.ulMinKeySize = 0; info.ulMaxKeySize = 0;
            info.flags = CKF_DIGEST;
        }
        CKM_HKDF_DERIVE => {
            info.ulMinKeySize = 0; info.ulMaxKeySize = 0;
            info.flags = CKF_DERIVE;
        }
        CKM_HKDF_KEY_GEN => {
            info.ulMinKeySize = 0; info.ulMaxKeySize = 0;
            info.flags = CKF_GENERATE;
        }
        _ => {
            info.ulMinKeySize = 0; info.ulMaxKeySize = 0;
            info.flags = 0;
        }
    }
}

// ── C_InitToken ──────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_InitToken(
    slot_id:     CK_SLOT_ID,
    p_pin:       *const CK_UTF8CHAR,
    ul_pin_len:  CK_ULONG,
    p_label:     *const CK_UTF8CHAR,
) -> CK_RV {
    ck_try!(check_init());
    info!(context: "CONFIG", "C_InitToken called slot={}", slot_id);
    if !crate::registry::is_valid_slot(slot_id) { return CKR_SLOT_ID_INVALID; }
    if p_pin.is_null() || p_label.is_null() { return CKR_ARGUMENTS_BAD; }
    if session::has_open_sessions(slot_id) {
        warn!(context: "CONFIG", "C_InitToken rejected: open sessions exist on slot={}", slot_id);
        return CKR_SESSION_EXISTS;
    }
    let pin = std::slice::from_raw_parts(p_pin, ul_pin_len as usize);
    let label: [CK_UTF8CHAR; 32] = {
        let mut buf = [b' '; 32];
        let src = std::slice::from_raw_parts(p_label, 32);
        buf.copy_from_slice(src);
        buf
    };

    // Verify SO PIN (if already init) and update SO PIN in RAM
    ck_try!(token::with_token_mut(slot_id, |tok| tok.init_token(pin, &label)));

    // Wipe objects in RAM
    object_store::clear_objects_for_slot(slot_id);
    object_store::ensure_baseline_profile(slot_id);

    object_store::persist_to_disk();
    info!(context: "CONFIG", "C_InitToken completed for slot={}", slot_id);
    CKR_OK
}
