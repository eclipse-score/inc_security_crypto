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

// ── Remaining v2.40 functions ─────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_CopyObject(
    h_session:    CK_SESSION_HANDLE,
    h_object:     CK_OBJECT_HANDLE,
    p_template:   *const CK_ATTRIBUTE,
    ul_count:     CK_ULONG,
    ph_new_object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());

    if ph_new_object.is_null() { return CKR_ARGUMENTS_BAD; }
    if ul_count > 0 && p_template.is_null() { return CKR_ARGUMENTS_BAD; }
    let overrides = collect_template(p_template, ul_count);
    let slot_id = ck_try!(session_slot(h_session));

    // Read the source object and grab everything we need, including its CKA_TOKEN state.
    let (new_handle, new_key_type, new_key_ref, mut new_attrs, src_always_sensitive, src_never_extractable, src_is_token) =
        ck_try!(object_store::with_object_for_slot(h_object, slot_id, |obj| {
            Ok((
                object_store::next_handle(),
                obj.key_type,
                obj.key_ref.clone(),
                obj.attributes.clone(),
                obj.always_sensitive,
                obj.never_extractable,
                bool_attr_true(obj, CKA_TOKEN) // Check if source is a token object
            ))
        }));

    // If the template specifies CKA_TOKEN, use that. Otherwise, inherit from source.
    let is_target_token = overrides
        .get(&CKA_TOKEN)
        .map(|v| !v.is_empty() && v[0] == CK_TRUE)
        .unwrap_or(src_is_token);

    // Only enforce Read/Write session if we are actually writing to the token.
    if is_target_token {
        ck_try!(require_rw_session(h_session));
    }

    // Apply template overrides with attribute policy enforcement.
    let mut override_keys: Vec<CK_ATTRIBUTE_TYPE> = Vec::new();
    for (k, v) in overrides {
        let old_val = new_attrs.get(&k).map(|b| b.as_slice());
        ck_try!(attribute_policy::validate_attribute_change(k, old_val, &v));
        new_attrs.insert(k, v);
        override_keys.push(k);
    }
    let mut new_obj = object_store::KeyObject::new(new_handle, slot_id, new_key_type, new_key_ref, new_attrs);

    // Sync derived fields for any attribute the template overrode.
    for changed in override_keys {
        attribute_policy::update_derived_attributes(&mut new_obj, changed);
    }

    // By setting these AFTER update_derived_attributes, we guarantee that
    // the policy engine cannot accidentally upgrade them to TRUE if the user
    // passed CKA_EXTRACTABLE=FALSE or CKA_SENSITIVE=TRUE in the copy template.
    new_obj.always_sensitive  = src_always_sensitive;
    new_obj.never_extractable = src_never_extractable;

    // Copies are NEVER considered locally generated.
    new_obj.local = false;

    object_store::store_object(new_obj, Some(h_session));
    *ph_new_object = new_handle;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetObjectSize(
    h_session: CK_SESSION_HANDLE,
    h_object:  CK_OBJECT_HANDLE,
    pul_size:  *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    if pul_size.is_null() { return CKR_ARGUMENTS_BAD; }
    let slot_id = ck_try!(session_slot(h_session));
    let size = ck_try!(object_store::with_object_for_slot(h_object, slot_id, |obj| {
        // Approximate size: key DER + attribute storage overhead
        let attr_size: usize = obj.attributes.values().map(|v| v.len() + 16).sum();
        Ok(obj.key_ref.as_bytes().len() + attr_size)
    }));
    *pul_size = size as CK_ULONG;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetOperationState(
    h_session:         CK_SESSION_HANDLE,
    p_operation_state: *mut CK_BYTE,
    pul_state_len:     *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    ck_try!(session::with_session(h_session, |_| Ok(())));
    CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub unsafe extern "C" fn C_SetOperationState(
    h_session:         CK_SESSION_HANDLE,
    p_operation_state: *const CK_BYTE,
    ul_state_len:      CK_ULONG,
    h_encryption_key:  CK_OBJECT_HANDLE,
    h_authentication_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    ck_try!(session::with_session(h_session, |_| Ok(())));
    CKR_FUNCTION_NOT_SUPPORTED
}

#[no_mangle]
pub unsafe extern "C" fn C_DigestKey(
    h_session: CK_SESSION_HANDLE,
    h_key:     CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    let slot_id = ck_try!(session_slot(h_session));

    // Intercept the error. Do NOT use ck_try! here.
    let key_bytes_res = with_object(h_key, |obj| {
        backend::key_value_for_digest(slot_id, obj)
    });

    // Translate a missing object to KEY_HANDLE_INVALID
    let key_bytes = match key_bytes_res {
        Ok(bytes) => bytes,
        Err(Pkcs11Error::KeyHandleInvalid | Pkcs11Error::InvalidObjectHandle) => {
            return CKR_KEY_HANDLE_INVALID;
        }
        Err(_) => return CKR_KEY_INDIGESTIBLE, // Reject digesting AES/Secret keys
    };

    let mut ctx = ck_try!(session::with_session_mut(h_session, |s| {
        s.digest_ctx.take().ok_or(Pkcs11Error::OperationNotInitialised)
    }));

    let result = || -> CK_RV {
        if ctx.is_single_part { return CKR_OPERATION_ACTIVE; }
        ctx.is_multi_part = true;

        ctx.data.extend_from_slice(&key_bytes);
        CKR_OK
    }();

    if result == CKR_OK {
        let _ = session::with_session_mut(h_session, |s| {
            s.digest_ctx = Some(ctx);
            Ok(())
        });
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn C_SignRecoverInit(
    _h_session:   CK_SESSION_HANDLE,
    _p_mechanism: *const CK_MECHANISM,
    _h_key:       CK_OBJECT_HANDLE,
) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }

#[no_mangle]
pub unsafe extern "C" fn C_SignRecover(
    _h_session:   CK_SESSION_HANDLE,
    _p_data:      *const CK_BYTE,
    _ul_data_len: CK_ULONG,
    _p_signature: *mut CK_BYTE,
    _pul_sig_len: *mut CK_ULONG,
) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }

#[no_mangle]
pub unsafe extern "C" fn C_VerifyRecoverInit(
    _h_session:   CK_SESSION_HANDLE,
    _p_mechanism: *const CK_MECHANISM,
    _h_key:       CK_OBJECT_HANDLE,
) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }

#[no_mangle]
pub unsafe extern "C" fn C_VerifyRecover(
    _h_session:   CK_SESSION_HANDLE,
    _p_signature: *const CK_BYTE,
    _ul_sig_len:  CK_ULONG,
    _p_data:      *mut CK_BYTE,
    _pul_data_len: *mut CK_ULONG,
) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }

#[no_mangle]
pub unsafe extern "C" fn C_DigestEncryptUpdate(
    _h_session:           CK_SESSION_HANDLE,
    _p_part:              *const CK_BYTE,
    _ul_part_len:         CK_ULONG,
    _p_encrypted_part:    *mut CK_BYTE,
    _pul_encrypted_part_len: *mut CK_ULONG,
) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }

#[no_mangle]
pub unsafe extern "C" fn C_DecryptDigestUpdate(
    _h_session:           CK_SESSION_HANDLE,
    _p_encrypted_part:    *const CK_BYTE,
    _ul_encrypted_part_len: CK_ULONG,
    _p_part:              *mut CK_BYTE,
    _pul_part_len:        *mut CK_ULONG,
) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }

#[no_mangle]
pub unsafe extern "C" fn C_SignEncryptUpdate(
    _h_session:           CK_SESSION_HANDLE,
    _p_part:              *const CK_BYTE,
    _ul_part_len:         CK_ULONG,
    _p_encrypted_part:    *mut CK_BYTE,
    _pul_encrypted_part_len: *mut CK_ULONG,
) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }

#[no_mangle]
pub unsafe extern "C" fn C_DecryptVerifyUpdate(
    _h_session:           CK_SESSION_HANDLE,
    _p_encrypted_part:    *const CK_BYTE,
    _ul_encrypted_part_len: CK_ULONG,
    _p_part:              *mut CK_BYTE,
    _pul_part_len:        *mut CK_ULONG,
) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }

#[no_mangle]
pub unsafe extern "C" fn C_SeedRandom(
    _h_session: CK_SESSION_HANDLE,
    _p_seed:    *const CK_BYTE,
    _ul_seed_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    ck_try!(session::with_session(_h_session, |_| Ok(())));
    if _p_seed.is_null() && _ul_seed_len > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    // Per PKCS#11: libraries that don't support manual seeding must
    // return CKR_RANDOM_SEED_NOT_SUPPORTED (not CKR_OK).
    CKR_RANDOM_SEED_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn C_GetFunctionStatus(
    _h_session: CK_SESSION_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_PARALLEL
}

#[no_mangle]
pub extern "C" fn C_CancelFunction(
    _h_session: CK_SESSION_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_PARALLEL
}

#[no_mangle]
pub unsafe extern "C" fn C_WaitForSlotEvent(
    _flags:     CK_FLAGS,
    _p_slot:    *mut CK_SLOT_ID,
    _p_reserved: *mut c_void,
) -> CK_RV {
    ck_try!(check_init());
    // Software tokens have no hardware events to wait for.
    CKR_FUNCTION_NOT_SUPPORTED
}
