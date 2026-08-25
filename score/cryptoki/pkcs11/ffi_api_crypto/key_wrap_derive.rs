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

// ── C_WrapKey ─────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_WrapKey(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
    h_wrapping_key: CK_OBJECT_HANDLE,
    h_key: CK_OBJECT_HANDLE,
    p_wrapped_key: *mut CK_BYTE,
    pul_wrapped_len: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CRYPTO", "C_WrapKey called session={} wrapping_key={} target_key={}", h_session, h_wrapping_key, h_key);
    if p_mechanism.is_null() || pul_wrapped_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let slot_id = ck_try!(session_slot(h_session));

    let is_length_req = p_wrapped_key.is_null();
    let mech = &*p_mechanism;
    if matches!(mech.mechanism, CKM_DES_ECB | CKM_DES_CBC | CKM_DES3_ECB | CKM_DES3_CBC) {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    // Access control checks.
    // Each check uses a separate with_object call so the object-store read lock
    // is released between acquisitions.  Nesting with_object calls would deadlock
    // under parking_lot's writer-preferring RwLock when another thread is waiting
    // to store a new object (write lock).

    // 1. Wrapping key must have CKA_WRAP == TRUE.
    let wrap_ok =
        match object_store::with_object_for_slot(h_wrapping_key, slot_id, |obj| Ok(bool_attr_true(obj, CKA_WRAP))) {
            Ok(v) => v,
            Err(Pkcs11Error::InvalidObjectHandle) => return CKR_WRAPPING_KEY_HANDLE_INVALID,
            Err(e) => return e.to_ckr(),
        };
    if !wrap_ok {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    // 2. Target key must have CKA_EXTRACTABLE == TRUE.
    let extractable =
        match object_store::with_object_for_slot(h_key, slot_id, |obj| Ok(bool_attr_true(obj, CKA_EXTRACTABLE))) {
            Ok(v) => v,
            Err(Pkcs11Error::InvalidObjectHandle) => return CKR_KEY_HANDLE_INVALID,
            Err(e) => return e.to_ckr(),
        };
    if !extractable {
        return CKR_KEY_UNEXTRACTABLE;
    }

    // 3. If target has CKA_WRAP_WITH_TRUSTED == TRUE, wrapping key must have CKA_TRUSTED == TRUE.
    let wrap_with_trusted = ck_try!(object_store::with_object_for_slot(h_key, slot_id, |obj| Ok(
        bool_attr_true(obj, CKA_WRAP_WITH_TRUSTED)
    )));
    if wrap_with_trusted {
        let trusted = ck_try!(object_store::with_object_for_slot(h_wrapping_key, slot_id, |obj| Ok(
            bool_attr_true(obj, CKA_TRUSTED)
        )));
        if !trusted {
            return CKR_KEY_NOT_WRAPPABLE;
        }
    }

    let wrapped_bytes = match mech.mechanism {
        CKM_AES_KEY_WRAP => {
            // Clone key refs out of the store before the engine call so we do not
            // hold a read lock during the (potentially slow) crypto operation and
            // avoid any nested-lock scenario.
            let wrap_ref = ck_try!(object_store::with_object_for_slot(h_wrapping_key, slot_id, |obj| Ok(
                obj.key_ref.clone()
            )));
            let target_ref = ck_try!(object_store::with_object_for_slot(h_key, slot_id, |obj| Ok(obj
                .key_ref
                .clone())));
            ck_try!(backend::aes_wrap_key_refs(slot_id, &wrap_ref, &target_ref))
        },
        _ => return CKR_MECHANISM_INVALID,
    };

    if !is_length_req {
        ck_try!(session::with_session_mut(h_session, |s| {
            s.context_specific_authed = false;
            Ok(())
        }));
    }

    write_to_output(p_wrapped_key, pul_wrapped_len, &wrapped_bytes)
}

// ── C_UnwrapKey ───────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_UnwrapKey(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
    h_unwrapping_key: CK_OBJECT_HANDLE,
    p_wrapped_key: *const CK_BYTE,
    ul_wrapped_len: CK_ULONG,
    p_template: *const CK_ATTRIBUTE,
    ul_count: CK_ULONG,
    ph_key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CRYPTO", "C_UnwrapKey called session={} unwrapping_key={} len={}", h_session, h_unwrapping_key, ul_wrapped_len);
    if p_mechanism.is_null() || p_wrapped_key.is_null() || ph_key.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = &*p_mechanism;
    let wrapped = std::slice::from_raw_parts(p_wrapped_key, ul_wrapped_len as usize);
    if ul_count > 0 && p_template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let attrs = collect_template(p_template, ul_count);

    let slot_id = ck_try!(session_slot(h_session));
    let is_token = attrs.get(&CKA_TOKEN).is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE);
    if is_token {
        ck_try!(require_rw_session(h_session));
    }

    // Check authorization AND access rights
    let auth_rv = object_store::with_object_for_slot(h_unwrapping_key, slot_id, |obj| {
        if !bool_attr_true(obj, CKA_UNWRAP) {
            return Err(Pkcs11Error::KeyFunctionNotPermitted);
        }
        session::with_session_mut(h_session, |s| s.require_context_auth(obj))
    });
    match auth_rv {
        Ok(()) => {},
        Err(Pkcs11Error::InvalidObjectHandle) => return CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        Err(e) => return e.to_ckr(),
    }

    // The Math & Key Creation
    match mech.mechanism {
        CKM_AES_KEY_WRAP => {
            let key_bytes = ck_try!(object_store::with_object_for_slot(
                h_unwrapping_key,
                slot_id,
                |unwrap_obj| { backend::aes_unwrap_key(slot_id, unwrap_obj, wrapped) }
            ));

            let key_len = key_bytes.len();
            if !matches!(key_len, 16 | 24 | 32) {
                return CKR_KEY_SIZE_RANGE;
            }

            let handle = object_store::next_handle();
            let mut obj_attrs = attrs;
            obj_attrs
                .entry(CKA_CLASS)
                .or_insert_with(|| backend::ulong_bytes(CKO_SECRET_KEY));
            obj_attrs
                .entry(CKA_KEY_TYPE)
                .or_insert_with(|| backend::ulong_bytes(CKK_AES));
            obj_attrs.insert(CKA_VALUE_LEN, backend::ulong_bytes(key_len as CK_ULONG));
            let mut obj = object_store::KeyObject::new(
                handle,
                slot_id,
                object_store::KeyType::AesSecret,
                crate::traits::EngineKeyRef::from_bytes(key_bytes.to_vec()),
                obj_attrs,
            );
            // Unwrapped keys are NOT locally generated (§4.2, §4.5).
            obj.local = false;
            obj.key_gen_mechanism = mech.mechanism;
            object_store::store_object(obj, Some(h_session));
            *ph_key = handle;
        },
        _ => return CKR_MECHANISM_INVALID,
    }

    // BURN THE TICKET
    ck_try!(session::with_session_mut(h_session, |s| {
        s.context_specific_authed = false;
        Ok(())
    }));
    CKR_OK
}

// ── C_DeriveKey ───────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_DeriveKey(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
    h_base_key: CK_OBJECT_HANDLE,
    p_template: *const CK_ATTRIBUTE,
    ul_count: CK_ULONG,
    ph_key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "CRYPTO", "C_DeriveKey called session={} base_key={}", h_session, h_base_key);
    if p_mechanism.is_null() || ph_key.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = &*p_mechanism;
    let attrs = collect_template(p_template, ul_count);

    // Evaluate Token Status for Session R/W requirements
    let is_token = attrs.get(&CKA_TOKEN).is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE);
    if is_token {
        ck_try!(require_rw_session(h_session));
    }

    let slot_id = ck_try!(session_slot(h_session));

    // Gate on auth, check CKA_DERIVE, AND extract base key audit flags
    let (base_always_sensitive, base_never_extractable) = ck_try!(with_object(h_base_key, |obj| {
        if !bool_attr_true(obj, CKA_DERIVE) {
            return Err(Pkcs11Error::KeyFunctionNotPermitted);
        }
        session::with_session_mut(h_session, |s| s.require_context_auth(obj))?;
        Ok((obj.always_sensitive, obj.never_extractable))
    }));

    match mech.mechanism {
        CKM_HKDF_DERIVE => {
            if mech.pParameter.is_null() {
                return CKR_MECHANISM_PARAM_INVALID;
            }
            let p = &*(mech.pParameter as *const CK_HKDF_PARAMS);

            let hash = match p.prfHashMechanism {
                CKM_SHA256 => crate::types::HashAlgorithm::Sha256,
                CKM_SHA384 => crate::types::HashAlgorithm::Sha384,
                CKM_SHA512 => crate::types::HashAlgorithm::Sha512,
                CKM_SHA_1 => crate::types::HashAlgorithm::Sha1,
                _ => return CKR_MECHANISM_PARAM_INVALID,
            };

            let salt = if !p.pSalt.is_null() && p.ulSaltLen > 0 {
                std::slice::from_raw_parts(p.pSalt, p.ulSaltLen as usize)
            } else {
                &[]
            };
            let info = if !p.pInfo.is_null() && p.ulInfoLen > 0 {
                std::slice::from_raw_parts(p.pInfo, p.ulInfoLen as usize)
            } else {
                &[]
            };

            let okm_len = attrs
                .get(&CKA_VALUE_LEN)
                .map(|b| backend::bytes_to_ulong(b) as usize)
                .unwrap_or(32);

            let derived_bytes = ck_try!(with_object(h_base_key, |base_obj| {
                backend::hkdf_derive(slot_id, base_obj, hash, salt, info, okm_len)
            }));

            // Generate CKA_UNIQUE_ID for the derived key
            let mut unique_id = vec![0u8; 16];
            ck_try!(backend::generate_random(slot_id, &mut unique_id));

            let handle = object_store::next_handle();
            let mut obj_attrs = attrs;
            obj_attrs
                .entry(CKA_CLASS)
                .or_insert_with(|| backend::ulong_bytes(CKO_SECRET_KEY));
            obj_attrs
                .entry(CKA_KEY_TYPE)
                .or_insert_with(|| backend::ulong_bytes(CKK_HKDF));
            obj_attrs.insert(CKA_VALUE_LEN, backend::ulong_bytes(okm_len as CK_ULONG));
            obj_attrs.insert(CKA_UNIQUE_ID, unique_id); // Inject Unique ID

            let mut obj = object_store::KeyObject::new(
                handle,
                slot_id,
                object_store::KeyType::AesSecret,
                crate::traits::EngineKeyRef::from_bytes(derived_bytes.to_vec()),
                obj_attrs,
            );

            // Derived keys are NEVER local
            obj.local = false;
            obj.key_gen_mechanism = mech.mechanism;
            // Inherit historical audit flags from the base key
            obj.always_sensitive = base_always_sensitive;
            obj.never_extractable = base_never_extractable;
            object_store::store_object(obj, Some(h_session));
            *ph_key = handle;
        },
        _ => return CKR_MECHANISM_INVALID,
    }

    // BURN THE TICKET UNCONDITIONALLY
    ck_try!(session::with_session_mut(h_session, |s| {
        s.context_specific_authed = false;
        Ok(())
    }));

    CKR_OK
}
