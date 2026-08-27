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
use super::*;
use score_log::{debug, info, trace, warn};

// ── C_InitPIN / C_SetPIN ─────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_InitPIN(
    h_session: CK_SESSION_HANDLE,
    p_pin: *const CK_UTF8CHAR,
    ul_pin_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    info!(context: "AUTH", "C_InitPIN called session={}", h_session);
    ck_try!(require_rw_session(h_session));
    // Caller must be SO logged in.
    let slot_id = ck_try!(session::with_session(h_session, |s| {
        if s.login_state != session::LoginState::SoLoggedIn {
            warn!(context: "AUTH", "C_InitPIN rejected: not SO logged in");
            return Err(Pkcs11Error::UserNotLoggedIn);
        }
        Ok(s.slot_id)
    }));
    let pin = if p_pin.is_null() || ul_pin_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(p_pin, ul_pin_len as usize)
    };
    ck_try!(token::with_token_mut(slot_id, |tok| tok.init_pin(pin)));
    object_store::persist_to_disk();
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_SetPIN(
    h_session: CK_SESSION_HANDLE,
    p_old_pin: *const CK_UTF8CHAR,
    ul_old_pin_len: CK_ULONG,
    p_new_pin: *const CK_UTF8CHAR,
    ul_new_pin_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    info!(context: "AUTH", "C_SetPIN called session={}", h_session);
    ck_try!(require_rw_session(h_session));
    let old_pin = if p_old_pin.is_null() {
        &[] as &[u8]
    } else {
        std::slice::from_raw_parts(p_old_pin, ul_old_pin_len as usize)
    };
    let new_pin = if p_new_pin.is_null() {
        &[] as &[u8]
    } else {
        std::slice::from_raw_parts(p_new_pin, ul_new_pin_len as usize)
    };
    let (user_type, slot_id) = ck_try!(session::with_session(h_session, |s| {
        match s.login_state {
            session::LoginState::SoLoggedIn => Ok((CKU_SO, s.slot_id)),
            session::LoginState::UserLoggedIn => Ok((CKU_USER, s.slot_id)),
            // If not logged in, C_SetPIN defaults to changing the User PIN
            session::LoginState::NotLoggedIn => Ok((CKU_USER, s.slot_id)),
        }
    }));
    // Verify old PIN with failure counting, then set the new PIN.
    ck_try!(token::with_token_mut(slot_id, |tok| {
        if let Err(err) = tok.verify_pin(user_type, old_pin) {
            warn!(context: "AUTH", "C_SetPIN old PIN verification failed");
            if user_type != CKU_USER || tok.verify_pin(user_type, new_pin).is_err() {
                return Err(err);
            }
        }
        tok.set_pin(user_type, new_pin)
    }));
    object_store::persist_to_disk();

    ck_try!(session::with_session_mut(h_session, |s| {
        s.context_specific_authed = false;
        Ok(())
    }));

    CKR_OK
}

// ── Session management ────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_OpenSession(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _p_application: *mut c_void,
    _notify: CK_NOTIFY,
    ph_session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "SESSION", "C_OpenSession called slot={} flags={}", slot_id, flags);
    if !crate::registry::is_valid_slot(slot_id) {
        return CKR_SLOT_ID_INVALID;
    }
    if ph_session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *ph_session = ck_try!(session::open_session(slot_id, flags));
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_CloseSession(h_session: CK_SESSION_HANDLE) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "SESSION", "C_CloseSession called session={}", h_session);
    ck_try!(session::close_session(h_session));
    // Destroy session objects owned by the closing session.
    object_store::destroy_objects_for_session(h_session);
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_CloseAllSessions(slot_id: CK_SLOT_ID) -> CK_RV {
    ck_try!(check_init());
    info!(context: "SESSION", "C_CloseAllSessions called slot={}", slot_id);
    if !crate::registry::is_valid_slot(slot_id) {
        return CKR_SLOT_ID_INVALID;
    }
    session::close_all_sessions(slot_id);
    // All sessions gone — destroy all session objects on this slot.
    object_store::destroy_session_objects_for_slot(slot_id);
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetSessionInfo(h_session: CK_SESSION_HANDLE, p_info: *mut CK_SESSION_INFO) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "SESSION", "C_GetSessionInfo called session={}", h_session);
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *p_info = ck_try!(session::get_session_info(h_session));
    CKR_OK
}

// ── Login / Logout ────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_Login(
    h_session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: *const CK_UTF8CHAR,
    ul_pin_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    info!(context: "AUTH", "C_Login called session={} user_type={}", h_session, user_type);

    // FFI validation to prevent silent logic bugs
    if p_pin.is_null() && ul_pin_len != 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let pin: &[u8] = if p_pin.is_null() || ul_pin_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(p_pin, ul_pin_len as usize)
    };
    let slot_id = ck_try!(session::with_session(h_session, |s| Ok(s.slot_id)));

    // CKU_CONTEXT_SPECIFIC: per-operation re-authentication for CKA_ALWAYS_AUTHENTICATE keys.
    if user_type == CKU_CONTEXT_SPECIFIC {
        // Must already be logged in as user.
        let current = session::login_state_for_slot(slot_id);
        if current != LoginState::UserLoggedIn {
            return CKR_USER_NOT_LOGGED_IN;
        }

        // Verify PIN without touching lockout counters — context-specific auth
        // is per-operation re-auth; wrong attempts must not lock the user login.
        ck_try!(token::with_token(slot_id, |tok| tok.verify_user_pin_no_lockout(pin)));
        ck_try!(session::with_session_mut(h_session, |s| {
            // Check if any operation requiring a private/secret key is actually active
            let is_op_active = s.sign_ctx.is_some()
                || s.msg_sign_ctx.is_some()
                || s.decrypt_ctx.is_some()
                || s.msg_decrypt_ctx.is_some()
                || s.encrypt_ctx.is_some()
                || s.msg_encrypt_ctx.is_some();

            if !is_op_active {
                return Err(Pkcs11Error::OperationNotInitialised);
            }
            s.context_specific_authed = true;
            Ok(())
        }));
        return CKR_OK;
    }

    // Validate user type early.
    let new_state = match user_type {
        CKU_USER => LoginState::UserLoggedIn,
        CKU_SO => LoginState::SoLoggedIn,
        _ => return CKR_USER_TYPE_INVALID,
    };

    // Check if already logged in on this token (any session).
    let current = session::login_state_for_slot(slot_id);
    if current != LoginState::NotLoggedIn {
        // Distinguish same-user vs different-user (PKCS#11).
        if (current == LoginState::UserLoggedIn && user_type == CKU_USER)
            || (current == LoginState::SoLoggedIn && user_type == CKU_SO)
        {
            return CKR_USER_ALREADY_LOGGED_IN;
        }
        return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
    }

    // SO login requires no RO sessions exist on this token.
    if user_type == CKU_SO && session::has_ro_sessions_on_slot(slot_id) {
        return CKR_SESSION_READ_ONLY_EXISTS;
    }

    // User login requires user PIN to have been initialized.
    if user_type == CKU_USER {
        let pin_init = token::with_token(slot_id, |tok| tok.user_pin.is_some());
        if !pin_init {
            return CKR_USER_PIN_NOT_INITIALIZED;
        }
    }

    // Verify PIN against the token (mutable for failure counter tracking).
    ck_try!(token::with_token_mut(slot_id, |tok| tok.verify_pin(user_type, pin)));

    ck_try!(session::with_session_mut(h_session, |s| {
        s.context_specific_authed = false;
        Ok(())
    }));

    // Propagate login state to ALL sessions on this token.
    session::login_all_sessions_on_slot(slot_id, new_state);
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_Logout(h_session: CK_SESSION_HANDLE) -> CK_RV {
    ck_try!(check_init());
    info!(context: "AUTH", "C_Logout called session={}", h_session);
    let slot_id = ck_try!(session::with_session(h_session, |s| Ok(s.slot_id)));

    // Check that we are actually logged in on this token.
    let current = session::login_state_for_slot(slot_id);
    if current == LoginState::NotLoggedIn {
        return CKR_USER_NOT_LOGGED_IN;
    }

    // Release active find-object contexts on every session for this slot,
    // since object visibility changes after logout. Crypto operations are left
    // intact — they will fail naturally if they depend on login state.
    session::release_find_contexts_on_slot(slot_id);

    // Destroy private session objects on this slot.
    object_store::destroy_private_session_objects(slot_id);

    // Reset login state for ALL sessions on this token.
    session::login_all_sessions_on_slot(slot_id, LoginState::NotLoggedIn);
    CKR_OK
}
