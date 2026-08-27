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
use score_log::{debug, trace};

// ── Encrypt ───────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_EncryptInit(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CRYPTO", "C_EncryptInit called session={} key={}", h_session, h_key);
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = &*p_mechanism;
    let (iv, aad, tag_len) = extract_cipher_params(mech);
    ck_try!(session::with_session_mut(h_session, |s| {
        if s.encrypt_ctx.is_some() {
            return Err(Pkcs11Error::OperationActive);
        }
        s.encrypt_ctx = Some(CipherContext {
            mechanism: mech.mechanism,
            key_handle: h_key,
            iv: Some(iv),
            aad,
            tag_len,
            accumulated: Vec::new(),
        });
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_Encrypt(
    h_session: CK_SESSION_HANDLE,
    p_data: *const CK_BYTE,
    ul_data_len: CK_ULONG,
    p_encrypted: *mut CK_BYTE,
    pul_encrypted_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "CRYPTO", "C_Encrypt called session={} len={}", h_session, ul_data_len);
    if p_data.is_null() || pul_encrypted_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let data = std::slice::from_raw_parts(p_data, ul_data_len as usize);
    let (ctx, slot_id) = ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.encrypt_ctx.take().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok((ctx, s.slot_id))
    }));
    let ct = if backend::is_rsa_enc_mechanism(ctx.mechanism) {
        ck_try!(with_object(ctx.key_handle, |obj| {
            backend::rsa_encrypt(slot_id, ctx.mechanism, obj, data)
        }))
    } else {
        let iv = ctx.iv.as_deref().unwrap_or(&[]);
        let aad = ctx.aad.as_deref();
        ck_try!(with_object(ctx.key_handle, |obj| {
            backend::encrypt_symmetric(slot_id, ctx.mechanism, obj, iv, aad, data)
        }))
    };
    write_to_output(p_encrypted, pul_encrypted_len, &ct)
}

#[no_mangle]
pub unsafe extern "C" fn C_EncryptUpdate(
    h_session: CK_SESSION_HANDLE,
    p_part: *const CK_BYTE,
    ul_part_len: CK_ULONG,
    _p_encrypted_part: *mut CK_BYTE,
    pul_encrypted_part_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    if p_part.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let part = std::slice::from_raw_parts(p_part, ul_part_len as usize);
    ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.encrypt_ctx.as_mut().ok_or(Pkcs11Error::OperationNotInitialised)?;
        ctx.accumulated.extend_from_slice(part);
        Ok(())
    }));
    if !pul_encrypted_part_len.is_null() {
        *pul_encrypted_part_len = 0;
    }
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_EncryptFinal(
    h_session: CK_SESSION_HANDLE,
    p_last_part: *mut CK_BYTE,
    pul_last_part_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    if pul_last_part_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let (ctx, slot_id) = ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.encrypt_ctx.take().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok((ctx, s.slot_id))
    }));
    let iv = ctx.iv.as_deref().unwrap_or(&[]);
    let aad = ctx.aad.as_deref();
    let ct = ck_try!(with_object(ctx.key_handle, |obj| {
        backend::encrypt_symmetric(slot_id, ctx.mechanism, obj, iv, aad, &ctx.accumulated)
    }));
    write_to_output(p_last_part, pul_last_part_len, &ct)
}

// ── Decrypt ───────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_DecryptInit(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CRYPTO", "C_DecryptInit called session={} key={}", h_session, h_key);
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = &*p_mechanism;
    let (iv, aad, tag_len) = extract_cipher_params(mech);
    ck_try!(session::with_session_mut(h_session, |s| {
        if s.decrypt_ctx.is_some() {
            return Err(Pkcs11Error::OperationActive);
        }
        // Wipe any old ghost tickets.
        s.context_specific_authed = false;
        s.decrypt_ctx = Some(CipherContext {
            mechanism: mech.mechanism,
            key_handle: h_key,
            iv: Some(iv),
            aad,
            tag_len,
            accumulated: Vec::new(),
        });
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_Decrypt(
    h_session: CK_SESSION_HANDLE,
    p_encrypted: *const CK_BYTE,
    ul_enc_len: CK_ULONG,
    p_data: *mut CK_BYTE,
    pul_data_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "CRYPTO", "C_Decrypt called session={} len={}", h_session, ul_enc_len);
    if p_encrypted.is_null() || pul_data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let is_length_req = p_data.is_null();
    let ct = std::slice::from_raw_parts(p_encrypted, ul_enc_len as usize);

    let (ctx, slot_id) = ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.decrypt_ctx.take().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok((ctx, s.slot_id))
    }));

    // Gate on CKA_ALWAYS_AUTHENTICATE before the engine call.
    ck_try!(with_object(ctx.key_handle, |obj| {
        session::with_session_mut(h_session, |s| s.require_context_auth(obj))
    }));

    let pt = if backend::is_rsa_enc_mechanism(ctx.mechanism) {
        ck_try!(with_object(ctx.key_handle, |obj| {
            backend::rsa_decrypt(slot_id, ctx.mechanism, obj, ct)
        }))
    } else {
        let iv = ctx.iv.as_deref().unwrap_or(&[]);
        let aad = ctx.aad.as_deref();
        ck_try!(with_object(ctx.key_handle, |obj| {
            backend::decrypt_symmetric(slot_id, ctx.mechanism, obj, iv, aad, ct, ctx.tag_len)
        }))
    };

    // Restore the context OR consume the ticket.
    ck_try!(session::with_session_mut(h_session, |s| {
        if is_length_req {
            s.decrypt_ctx = Some(ctx); // It was a length request, put it back!
        } else {
            s.context_specific_authed = false; // Real call done, burn the ticket.
        }
        Ok(())
    }));
    write_to_output(p_data, pul_data_len, &pt)
}

#[no_mangle]
pub unsafe extern "C" fn C_DecryptUpdate(
    h_session: CK_SESSION_HANDLE,
    p_encrypted_part: *const CK_BYTE,
    ul_enc_part_len: CK_ULONG,
    _p_part: *mut CK_BYTE,
    pul_part_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    if p_encrypted_part.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let part = std::slice::from_raw_parts(p_encrypted_part, ul_enc_part_len as usize);
    ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.decrypt_ctx.as_mut().ok_or(Pkcs11Error::OperationNotInitialised)?;
        ctx.accumulated.extend_from_slice(part);
        Ok(())
    }));
    if !pul_part_len.is_null() {
        *pul_part_len = 0;
    }
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_DecryptFinal(
    h_session: CK_SESSION_HANDLE,
    p_last_part: *mut CK_BYTE,
    pul_last_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    if pul_last_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let is_length_req = p_last_part.is_null();

    let (ctx, slot_id) = ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.decrypt_ctx.take().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok((ctx, s.slot_id))
    }));

    // Check CKA_ALWAYS_AUTHENTICATE
    ck_try!(with_object(ctx.key_handle, |obj| {
        session::with_session_mut(h_session, |s| s.require_context_auth(obj))
    }));

    let iv = ctx.iv.as_deref().unwrap_or(&[]);
    let aad = ctx.aad.as_deref();
    let pt = ck_try!(with_object(ctx.key_handle, |obj| {
        backend::decrypt_symmetric(slot_id, ctx.mechanism, obj, iv, aad, &ctx.accumulated, ctx.tag_len)
    }));

    // put the context back if it's a length request!
    ck_try!(session::with_session_mut(h_session, |s| {
        if is_length_req {
            s.decrypt_ctx = Some(ctx);
        } else {
            s.context_specific_authed = false;
        }
        Ok(())
    }));

    write_to_output(p_last_part, pul_last_len, &pt)
}
