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

// ── v3.0 new functions ────────────────────────────────────────────────────

/// C_SessionCancel — cancel active cryptographic operations on a session.
#[no_mangle]
pub unsafe extern "C" fn C_SessionCancel(
    h_session: CK_SESSION_HANDLE,
    flags:     CK_FLAGS,
) -> CK_RV {
    ck_try!(check_init());
    ck_try!(session::with_session_mut(h_session, |s| {
        // Cancel all active operations
        s.sign_ctx    = None;
        s.verify_ctx  = None;
        s.encrypt_ctx = None;
        s.decrypt_ctx = None;
        s.digest_ctx  = None;
        s.find_ctx    = None;
        Ok(())
    }));
    CKR_OK
}

/// C_LoginUser — extended login with username parameter (v3.0).
#[no_mangle]
pub unsafe extern "C" fn C_LoginUser(
    h_session:       CK_SESSION_HANDLE,
    user_type:       CK_USER_TYPE,
    p_pin:           *const CK_UTF8CHAR,
    ul_pin_len:      CK_ULONG,
    p_username:      *const CK_UTF8CHAR,
    ul_username_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    // For CKU_CONTEXT_SPECIFIC, we just verify the PIN.
    // For CKU_USER / CKU_SO, delegate to the normal login path.
    let pin: &[u8] = if p_pin.is_null() || ul_pin_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(p_pin, ul_pin_len as usize)
    };

    let slot_id = ck_try!(session_slot(h_session));
    if user_type == CKU_CONTEXT_SPECIFIC {
        // Context-specific login requires the user to already be logged in.
        let current = session::login_state_for_slot(slot_id);
        if current != LoginState::UserLoggedIn {
            return CKR_USER_NOT_LOGGED_IN;
        }
        // Verify PIN without lockout counters; on success, arm the one-shot flag.
        ck_try!(token::with_token(slot_id, |tok| tok.verify_user_pin_no_lockout(pin)));
        ck_try!(session::with_session_mut(h_session, |s| {
            s.context_specific_authed = true;
            Ok(())
        }));
        return CKR_OK;
    }

    // Validate user type early.
    let new_state = match user_type {
        CKU_USER => LoginState::UserLoggedIn,
        CKU_SO   => LoginState::SoLoggedIn,
        _        => return CKR_USER_TYPE_INVALID,
    };

    // Check if already logged in on this token (any session).
    let current = session::login_state_for_slot(slot_id);
    if current != LoginState::NotLoggedIn {
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

    // Propagate login state to ALL sessions on this token.
    session::login_all_sessions_on_slot(slot_id, new_state);
    CKR_OK
}
