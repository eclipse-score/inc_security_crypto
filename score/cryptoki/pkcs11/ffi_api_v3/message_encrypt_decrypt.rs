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

// ── Message-based Encrypt API (v3.0) ──────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_MessageEncryptInit(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CRYPTO", "C_MessageEncryptInit called session={} key={}", h_session, h_key);
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech_type = (*p_mechanism).mechanism;
    // Only AES-GCM and ChaCha20-Poly1305 support per-message IV semantics.
    if mech_type != CKM_AES_GCM && mech_type != CKM_CHACHA20_POLY1305 {
        return CKR_MECHANISM_INVALID;
    }
    ck_try!(session::with_session_mut(h_session, |s| {
        if s.msg_encrypt_ctx.is_some() {
            return Err(Pkcs11Error::OperationActive);
        }
        s.msg_encrypt_ctx = Some(MessageCipherContext {
            mechanism: mech_type,
            key_handle: h_key,
        });
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_EncryptMessage(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *const c_void, // *const CK_GCM_MESSAGE_PARAMS or CK_CHACHA20_POLY1305_MESSAGE_PARAMS (tag written back via interior pointer)
    ul_param_len: CK_ULONG,
    p_aad: *const CK_BYTE,
    ul_aad_len: CK_ULONG,
    p_plaintext: *const CK_BYTE,
    ul_plain_len: CK_ULONG,
    p_ciphertext: *mut CK_BYTE,
    pul_cipher_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "CRYPTO", "C_EncryptMessage called session={} len={}", h_session, ul_plain_len);
    if p_plaintext.is_null() || pul_cipher_len.is_null() || p_parameter.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let plaintext = std::slice::from_raw_parts(p_plaintext, ul_plain_len as usize);
    let aad = if !p_aad.is_null() && ul_aad_len > 0 {
        std::slice::from_raw_parts(p_aad, ul_aad_len as usize)
    } else {
        &[]
    };

    let (ctx, slot_id) = ck_try!(session::with_session(h_session, |s| {
        Ok((
            s.msg_encrypt_ctx
                .as_ref()
                .cloned()
                .ok_or(Pkcs11Error::OperationNotInitialised)?,
            s.slot_id,
        ))
    }));

    // Extract IV and tag buffer from the per-message params struct.
    // CK_GCM_MESSAGE_PARAMS and CK_CHACHA20_POLY1305_MESSAGE_PARAMS share the same layout.
    // Cast: params is the caller's mutable struct passed through a const void pointer.
    let params = p_parameter as *const CK_GCM_MESSAGE_PARAMS;
    if (*params).pIv.is_null() || (*params).pTag.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let iv = std::slice::from_raw_parts((*params).pIv, (*params).ulIvLen as usize);
    let tag_len = ((*params).ulTagBits as usize).div_ceil(8);

    let (ct, tag) = ck_try!(with_object(ctx.key_handle, |obj| {
        backend::encrypt_message(slot_id, ctx.mechanism, obj, iv, aad, plaintext)
    }));

    // Write tag back to caller's pTag buffer (pTag is *mut CK_BYTE inside the struct).
    if tag.len() != tag_len {
        return CKR_GENERAL_ERROR;
    }
    std::ptr::copy_nonoverlapping(tag.as_ptr(), (*params).pTag, tag_len);

    write_to_output(p_ciphertext, pul_cipher_len, &ct)
}

#[no_mangle]
pub unsafe extern "C" fn C_EncryptMessageBegin(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *const c_void,
    ul_param_len: CK_ULONG,
    p_aad: *const CK_BYTE,
    ul_aad_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    // For single-part AEAD messages, Begin is a no-op that just validates state
    ck_try!(session::with_session(h_session, |s| {
        s.msg_encrypt_ctx.as_ref().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_EncryptMessageNext(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *const c_void,
    ul_param_len: CK_ULONG,
    p_plaintext: *const CK_BYTE,
    ul_plain_len: CK_ULONG,
    p_ciphertext: *mut CK_BYTE,
    pul_cipher_len: *mut CK_ULONG,
    flags: CK_FLAGS,
) -> CK_RV {
    // Streaming not supported for AEAD — use C_EncryptMessage for one-shot
    CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub unsafe extern "C" fn C_MessageEncryptFinal(h_session: CK_SESSION_HANDLE) -> CK_RV {
    ck_try!(check_init());
    ck_try!(session::with_session_mut(h_session, |s| {
        s.msg_encrypt_ctx = None;
        Ok(())
    }));
    CKR_OK
}

// ── Message-based Decrypt API (v3.0) ──────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_MessageDecryptInit(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CRYPTO", "C_MessageDecryptInit called session={} key={}", h_session, h_key);
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech_type = (*p_mechanism).mechanism;
    // Only AES-GCM and ChaCha20-Poly1305 support per-message IV semantics.
    if mech_type != CKM_AES_GCM && mech_type != CKM_CHACHA20_POLY1305 {
        return CKR_MECHANISM_INVALID;
    }
    ck_try!(session::with_session_mut(h_session, |s| {
        if s.msg_decrypt_ctx.is_some() {
            return Err(Pkcs11Error::OperationActive);
        }
        s.msg_decrypt_ctx = Some(MessageCipherContext {
            mechanism: mech_type,
            key_handle: h_key,
        });
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_DecryptMessage(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *const c_void, // *const CK_GCM_MESSAGE_PARAMS or CK_CHACHA20_POLY1305_MESSAGE_PARAMS
    ul_param_len: CK_ULONG,
    p_aad: *const CK_BYTE,
    ul_aad_len: CK_ULONG,
    p_ciphertext: *const CK_BYTE,
    ul_cipher_len: CK_ULONG,
    p_plaintext: *mut CK_BYTE,
    pul_plain_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "CRYPTO", "C_DecryptMessage called session={} len={}", h_session, ul_cipher_len);
    if p_ciphertext.is_null() || pul_plain_len.is_null() || p_parameter.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let ciphertext = std::slice::from_raw_parts(p_ciphertext, ul_cipher_len as usize);
    let aad = if !p_aad.is_null() && ul_aad_len > 0 {
        std::slice::from_raw_parts(p_aad, ul_aad_len as usize)
    } else {
        &[]
    };

    let (ctx, slot_id) = ck_try!(session::with_session(h_session, |s| {
        Ok((
            s.msg_decrypt_ctx
                .as_ref()
                .cloned()
                .ok_or(Pkcs11Error::OperationNotInitialised)?,
            s.slot_id,
        ))
    }));

    // Extract IV and tag from the per-message params struct.
    // CK_GCM_MESSAGE_PARAMS and CK_CHACHA20_POLY1305_MESSAGE_PARAMS share the same layout.
    let params = p_parameter as *const CK_GCM_MESSAGE_PARAMS;
    if (*params).pIv.is_null() || (*params).pTag.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let iv = std::slice::from_raw_parts((*params).pIv, (*params).ulIvLen as usize);
    let tag_len = ((*params).ulTagBits as usize).div_ceil(8);
    let tag = std::slice::from_raw_parts((*params).pTag, tag_len);

    let pt = ck_try!(with_object(ctx.key_handle, |obj| {
        backend::decrypt_message(slot_id, ctx.mechanism, obj, iv, aad, ciphertext, tag)
    }));
    write_to_output(p_plaintext, pul_plain_len, &pt)
}

#[no_mangle]
pub unsafe extern "C" fn C_DecryptMessageBegin(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *const c_void,
    ul_param_len: CK_ULONG,
    p_aad: *const CK_BYTE,
    ul_aad_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    ck_try!(session::with_session(h_session, |s| {
        s.msg_decrypt_ctx.as_ref().ok_or(Pkcs11Error::OperationNotInitialised)?;
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_DecryptMessageNext(
    h_session: CK_SESSION_HANDLE,
    p_parameter: *const c_void,
    ul_param_len: CK_ULONG,
    p_ciphertext: *const CK_BYTE,
    ul_cipher_len: CK_ULONG,
    p_plaintext: *mut CK_BYTE,
    pul_plain_len: *mut CK_ULONG,
    flags: CK_FLAGS,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub unsafe extern "C" fn C_MessageDecryptFinal(h_session: CK_SESSION_HANDLE) -> CK_RV {
    ck_try!(check_init());
    ck_try!(session::with_session_mut(h_session, |s| {
        s.msg_decrypt_ctx = None;
        Ok(())
    }));
    CKR_OK
}
