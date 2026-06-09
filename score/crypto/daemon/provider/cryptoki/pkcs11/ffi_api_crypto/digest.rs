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
use score_log::{debug, trace};

// ── Digest ────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_DigestInit(
    h_session:   CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CRYPTO", "C_DigestInit called session={}", h_session);
    if p_mechanism.is_null() { return CKR_ARGUMENTS_BAD; }
    let mech_type = (*p_mechanism).mechanism;
    match mech_type {
        CKM_MD5 | CKM_SHA_1 | CKM_SHA256 | CKM_SHA384 | CKM_SHA512 |
        CKM_SHA3_256 | CKM_SHA3_384 | CKM_SHA3_512 => {
             /* valid */
        },
        _ => return CKR_MECHANISM_INVALID,
    }
    ck_try!(session::with_session_mut(h_session, |s| {
        if s.digest_ctx.is_some() { return Err(Pkcs11Error::OperationActive); }
        s.digest_ctx = Some(DigestContext {
            mechanism: mech_type,
            data: Vec::new(),
            is_single_part: false,
            is_multi_part: false,
        });
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_Digest(
    h_session:      CK_SESSION_HANDLE,
    p_data:         *const CK_BYTE,
    ul_data_len:    CK_ULONG,
    p_digest:       *mut CK_BYTE,
    pul_digest_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "CRYPTO", "C_Digest called session={} len={}", h_session, ul_data_len);
    if pul_digest_len.is_null() {
        let _ = session::with_session_mut(h_session, |s| {
            s.digest_ctx.take();
            Ok(())
        });
        return CKR_ARGUMENTS_BAD;
    }
    if p_data.is_null() && ul_data_len > 0 { return CKR_ARGUMENTS_BAD; }

    // 1. Peek at context without destroying it
    let (mech, slot_id) = ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.digest_ctx.as_mut().ok_or(Pkcs11Error::OperationNotInitialised)?;
        if ctx.is_multi_part {
            s.digest_ctx.take();
            return Err(Pkcs11Error::OperationActive);
        }
        ctx.is_single_part = true;
        Ok((ctx.mechanism, s.slot_id))
    }));

    let data = if ul_data_len > 0 { std::slice::from_raw_parts(p_data, ul_data_len as usize) } else { &[] };
    let hash = ck_try!(backend::digest(slot_id, mech, data));
    let rv = write_to_output(p_digest, pul_digest_len, &hash);

    // 2. ONLY consume context if the operation succeeded AND the buffer was written to
    if rv == CKR_OK && !p_digest.is_null() {
        let _ = session::with_session_mut(h_session, |s| {
            s.digest_ctx.take();
            Ok(())
        });
    }
    rv
}

#[no_mangle]
pub unsafe extern "C" fn C_DigestUpdate(
    h_session:   CK_SESSION_HANDLE,
    p_part:      *const CK_BYTE,
    ul_part_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "CRYPTO", "C_DigestUpdate called session={} len={}", h_session, ul_part_len);
    if p_part.is_null() && ul_part_len > 0 { return CKR_ARGUMENTS_BAD; }

    ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.digest_ctx.as_mut().ok_or(Pkcs11Error::OperationNotInitialised)?;
        if ctx.is_single_part { return Err(Pkcs11Error::OperationActive); }
        ctx.is_multi_part = true;

        if ul_part_len > 0 {
            let part = std::slice::from_raw_parts(p_part, ul_part_len as usize);
            ctx.data.extend_from_slice(part);
        }
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_DigestFinal(
    h_session:      CK_SESSION_HANDLE,
    p_digest:       *mut CK_BYTE,
    pul_digest_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "CRYPTO", "C_DigestFinal called session={}", h_session);
    if pul_digest_len.is_null() {
        let _ = session::with_session_mut(h_session, |s| {
            s.digest_ctx.take();
            Ok(())
        });
        return CKR_ARGUMENTS_BAD;
    }

    // 1. Peek at context without destroying it
    let (mech, data, slot_id) = ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.digest_ctx.as_mut().ok_or(Pkcs11Error::OperationNotInitialised)?;
        if ctx.is_single_part {
            s.digest_ctx.take();
            return Err(Pkcs11Error::OperationActive);
        }
        ctx.is_multi_part = true;
        Ok((ctx.mechanism, ctx.data.clone(), s.slot_id))
    }));

    let hash = ck_try!(backend::digest(slot_id, mech, &data));
    let rv = write_to_output(p_digest, pul_digest_len, &hash);

    // 2. ONLY consume context if the operation succeeded AND the buffer was written to
    if rv == CKR_OK && !p_digest.is_null() {
        let _ = session::with_session_mut(h_session, |s| {
            s.digest_ctx.take();
            Ok(())
        });
    }
    rv
}
