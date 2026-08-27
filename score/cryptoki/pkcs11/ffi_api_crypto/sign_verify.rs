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

// ── Sign ──────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_SignInit(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CRYPTO", "C_SignInit called session={} key={}", h_session, h_key);
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech_type = (*p_mechanism).mechanism;

    match mech_type {
        // Standard and Legacy RSA
        CKM_RSA_PKCS | CKM_SHA1_RSA_PKCS | CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS => {
            // These are standard PKCS#1 v1.5 signing mechanisms
        },

        // RSA-PSS
        CKM_RSA_PKCS_PSS
        | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA512_RSA_PKCS_PSS => {
            // Probabilistic Signature Scheme
        },

        // Elliptic Curve
        CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_EDDSA => {
            // EC and EdDSA signatures
        },

        // HMAC
        CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC => {
            // Hash-based Message Authentication Code
        },

        _ => {
            warn!(context: "MECH", "C_SignInit rejected mechanism={}", mech_type);
            return CKR_MECHANISM_INVALID;
        },
    }

    ck_try!(session::with_session_mut(h_session, |s| {
        if s.sign_ctx.is_some() {
            return Err(Pkcs11Error::OperationActive);
        }
        // Wipe any old ghost tickets.
        s.context_specific_authed = false;
        s.sign_ctx = Some(SignContext {
            mechanism: mech_type,
            key_handle: h_key,
            data: Vec::new(),
        });
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_Sign(
    h_session: CK_SESSION_HANDLE,
    p_data: *const CK_BYTE,
    ul_data_len: CK_ULONG,
    p_signature: *mut CK_BYTE,
    pul_sig_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "CRYPTO", "C_Sign called session={} len={}", h_session, ul_data_len);
    if p_data.is_null() || pul_sig_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let is_length_req = p_signature.is_null();
    let data = std::slice::from_raw_parts(p_data, ul_data_len as usize);

    let (ctx, slot_id) = ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.sign_ctx.take().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok((ctx, s.slot_id)) // take() gives ownership, no need to clone
    }));

    // Gate on CKA_ALWAYS_AUTHENTICATE before the engine call.
    ck_try!(with_object(ctx.key_handle, |obj| {
        session::with_session_mut(h_session, |s| s.require_context_auth(obj))
    }));
    let sig = ck_try!(with_object(ctx.key_handle, |obj| {
        backend::sign(slot_id, ctx.mechanism, obj, data)
    }));
    // RESTORE OR CONSUME
    ck_try!(session::with_session_mut(h_session, |s| {
        if is_length_req {
            s.sign_ctx = Some(ctx); // THE FIX: Put it back for the real call!
        } else {
            s.context_specific_authed = false; // Burn the ticket
        }
        Ok(())
    }));

    write_to_output(p_signature, pul_sig_len, &sig)
}

#[no_mangle]
pub unsafe extern "C" fn C_SignUpdate(
    h_session: CK_SESSION_HANDLE,
    p_part: *const CK_BYTE,
    ul_part_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    if p_part.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let part = std::slice::from_raw_parts(p_part, ul_part_len as usize);
    ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.sign_ctx.as_mut().ok_or(Pkcs11Error::OperationNotInitialised)?;
        ctx.data.extend_from_slice(part);
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_SignFinal(
    h_session: CK_SESSION_HANDLE,
    p_signature: *mut CK_BYTE,
    pul_sig_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "MECH", "C_SignFinal session={}", h_session);
    if pul_sig_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let is_length_req = p_signature.is_null();

    let (ctx, slot_id) = ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.sign_ctx.take().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok((ctx, s.slot_id))
    }));

    // Check CKA_ALWAYS_AUTHENTICATE
    ck_try!(with_object(ctx.key_handle, |obj| {
        session::with_session_mut(h_session, |s| s.require_context_auth(obj))
    }));

    let sig = ck_try!(with_object(ctx.key_handle, |obj| {
        backend::sign(slot_id, ctx.mechanism, obj, &ctx.data)
    }));

    // RESTORE OR CONSUME
    ck_try!(session::with_session_mut(h_session, |s| {
        if is_length_req {
            s.sign_ctx = Some(ctx); // THE FIX: Put it back for the real call!
        } else {
            s.context_specific_authed = false; // Burn the ticket
        }
        Ok(())
    }));
    write_to_output(p_signature, pul_sig_len, &sig)
}

// ── Verify ────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_VerifyInit(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CRYPTO", "C_VerifyInit called session={} key={}", h_session, h_key);
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech_type = (*p_mechanism).mechanism;
    match mech_type {
        // Standard and Legacy RSA
        CKM_RSA_PKCS | CKM_SHA1_RSA_PKCS | CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS => {
            // These are standard PKCS#1 v1.5 signing mechanisms
        },

        // RSA-PSS
        CKM_RSA_PKCS_PSS
        | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA512_RSA_PKCS_PSS => {
            // Probabilistic Signature Scheme
        },

        // Elliptic Curve
        CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_EDDSA => {
            // EC and EdDSA signatures
        },

        // HMAC
        CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC => {
            // Hash-based Message Authentication Code
        },

        _ => {
            warn!(context: "MECH", "C_VerifyInit rejected mechanism={}", mech_type);
            return CKR_MECHANISM_INVALID;
        },
    }
    ck_try!(session::with_session_mut(h_session, |s| {
        if s.verify_ctx.is_some() {
            return Err(Pkcs11Error::OperationActive);
        }
        s.verify_ctx = Some(SignContext {
            mechanism: mech_type,
            key_handle: h_key,
            data: Vec::new(),
        });
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_Verify(
    h_session: CK_SESSION_HANDLE,
    p_data: *const CK_BYTE,
    ul_data_len: CK_ULONG,
    p_signature: *const CK_BYTE,
    ul_sig_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "CRYPTO", "C_Verify called session={} len={} sig_len={}", h_session, ul_data_len, ul_sig_len);
    if p_data.is_null() || p_signature.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let key_handle = ck_try!(session::with_session(h_session, |s| {
        s.verify_ctx
            .as_ref()
            .map(|ctx| ctx.key_handle)
            .ok_or(Pkcs11Error::OperationNotInitialised)
    }));

    let is_rsa = ck_try!(object_store::with_object(key_handle, |obj| {
        Ok(obj.key_type == object_store::KeyType::RsaPublic || obj.key_type == object_store::KeyType::RsaPrivate)
    }));

    if is_rsa {
        let modulus_size = ck_try!(object_store::with_object(key_handle, |obj| {
            object_store::get_modulus_len(obj)
        }));
        if ul_sig_len != modulus_size as CK_ULONG {
            return CKR_SIGNATURE_LEN_RANGE;
        }
    }
    let data = std::slice::from_raw_parts(p_data, ul_data_len as usize);
    let sig = std::slice::from_raw_parts(p_signature, ul_sig_len as usize);
    let (ctx, slot_id) = ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.verify_ctx.take().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok((ctx, s.slot_id))
    }));
    ck_try!(with_object(ctx.key_handle, |obj| {
        backend::verify(slot_id, ctx.mechanism, obj, data, sig)
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_VerifyUpdate(
    h_session: CK_SESSION_HANDLE,
    p_part: *const CK_BYTE,
    ul_part_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    if p_part.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let part = std::slice::from_raw_parts(p_part, ul_part_len as usize);
    ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.verify_ctx.as_mut().ok_or(Pkcs11Error::OperationNotInitialised)?;
        ctx.data.extend_from_slice(part);
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_VerifyFinal(
    h_session: CK_SESSION_HANDLE,
    p_signature: *const CK_BYTE,
    ul_sig_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    if p_signature.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let key_handle = ck_try!(session::with_session(h_session, |s| {
        s.verify_ctx
            .as_ref()
            .map(|ctx| ctx.key_handle)
            .ok_or(Pkcs11Error::OperationNotInitialised)
    }));

    let is_rsa = ck_try!(object_store::with_object(key_handle, |obj| {
        Ok(obj.key_type == object_store::KeyType::RsaPublic || obj.key_type == object_store::KeyType::RsaPrivate)
    }));

    if is_rsa {
        let modulus_size = ck_try!(object_store::with_object(key_handle, |obj| {
            object_store::get_modulus_len(obj)
        }));
        if ul_sig_len != modulus_size as CK_ULONG {
            return CKR_SIGNATURE_LEN_RANGE;
        }
    }

    let sig = std::slice::from_raw_parts(p_signature, ul_sig_len as usize);
    let (ctx, slot_id) = ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.verify_ctx.take().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok((ctx, s.slot_id))
    }));
    ck_try!(with_object(ctx.key_handle, |obj| {
        backend::verify(slot_id, ctx.mechanism, obj, &ctx.data, sig)
    }));
    CKR_OK
}
