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
use score_log::{debug, info, trace, warn};

// ── Message-based Sign API (v3.0) ────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_MessageSignInit(
    _h_session:   CK_SESSION_HANDLE,
    _p_mechanism: *const CK_MECHANISM,
    _h_key:       CK_OBJECT_HANDLE,
) -> CK_RV {
    // No mechanism currently supports per-message signing semantics.
    CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub unsafe extern "C" fn C_SignMessage(
    h_session:    CK_SESSION_HANDLE,
    p_parameter:  *const c_void,
    ul_param_len: CK_ULONG,
    p_data:       *const CK_BYTE,
    ul_data_len:  CK_ULONG,
    p_signature:  *mut CK_BYTE,
    pul_sig_len:  *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "CRYPTO", "C_SignMessage called session={} len={}", h_session, ul_data_len);
    if p_data.is_null() || pul_sig_len.is_null() { return CKR_ARGUMENTS_BAD; }
    let data = std::slice::from_raw_parts(p_data, ul_data_len as usize);
    let (ctx, slot_id) = ck_try!(session::with_session(h_session, |s| {
        Ok((s.msg_sign_ctx.as_ref().cloned().ok_or(Pkcs11Error::OperationNotInitialised)?, s.slot_id))
    }));
    let sig = ck_try!(with_object(ctx.key_handle, |obj| {
        backend::sign(slot_id, ctx.mechanism, obj, data)
    }));
    write_to_output(p_signature, pul_sig_len, &sig)
}

#[no_mangle]
pub unsafe extern "C" fn C_SignMessageBegin(
    h_session:    CK_SESSION_HANDLE,
    p_parameter:  *const c_void,
    ul_param_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    ck_try!(session::with_session(h_session, |s| {
        s.msg_sign_ctx.as_ref().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_SignMessageNext(
    h_session:    CK_SESSION_HANDLE,
    p_parameter:  *const c_void,
    ul_param_len: CK_ULONG,
    p_data:       *const CK_BYTE,
    ul_data_len:  CK_ULONG,
    p_signature:  *mut CK_BYTE,
    pul_sig_len:  *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub unsafe extern "C" fn C_MessageSignFinal(
    h_session: CK_SESSION_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    ck_try!(session::with_session_mut(h_session, |s| {
        s.msg_sign_ctx = None;
        Ok(())
    }));
    CKR_OK
}

// ── Message-based Verify API (v3.0) ──────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_MessageVerifyInit(
    _h_session:   CK_SESSION_HANDLE,
    _p_mechanism: *const CK_MECHANISM,
    _h_key:       CK_OBJECT_HANDLE,
) -> CK_RV {
    // No mechanism currently supports per-message verify semantics.
    CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub unsafe extern "C" fn C_VerifyMessage(
    h_session:    CK_SESSION_HANDLE,
    p_parameter:  *const c_void,
    ul_param_len: CK_ULONG,
    p_data:       *const CK_BYTE,
    ul_data_len:  CK_ULONG,
    p_signature:  *const CK_BYTE,
    ul_sig_len:   CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "CRYPTO", "C_VerifyMessage called session={} len={}", h_session, ul_data_len);
    if p_data.is_null() || p_signature.is_null() { return CKR_ARGUMENTS_BAD; }
    let data = std::slice::from_raw_parts(p_data, ul_data_len as usize);
    let sig  = std::slice::from_raw_parts(p_signature, ul_sig_len as usize);
    let (ctx, slot_id) = ck_try!(session::with_session(h_session, |s| {
        Ok((s.msg_verify_ctx.as_ref().cloned().ok_or(Pkcs11Error::OperationNotInitialised)?, s.slot_id))
    }));
    ck_try!(with_object(ctx.key_handle, |obj| {
        backend::verify(slot_id, ctx.mechanism, obj, data, sig)
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_VerifyMessageBegin(
    h_session:    CK_SESSION_HANDLE,
    p_parameter:  *const c_void,
    ul_param_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    ck_try!(session::with_session(h_session, |s| {
        s.msg_verify_ctx.as_ref().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_VerifyMessageNext(
    h_session:    CK_SESSION_HANDLE,
    p_parameter:  *const c_void,
    ul_param_len: CK_ULONG,
    p_data:       *const CK_BYTE,
    ul_data_len:  CK_ULONG,
    p_signature:  *const CK_BYTE,
    ul_sig_len:   CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub unsafe extern "C" fn C_MessageVerifyFinal(
    h_session: CK_SESSION_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    ck_try!(session::with_session_mut(h_session, |s| {
        s.msg_verify_ctx = None;
        Ok(())
    }));
    CKR_OK
}
