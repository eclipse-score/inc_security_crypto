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

// ── Key generation ────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_GenerateKeyPair(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
    p_pub_template: *const CK_ATTRIBUTE,
    ul_pub_count: CK_ULONG,
    p_priv_template: *const CK_ATTRIBUTE,
    ul_priv_count: CK_ULONG,
    ph_pub_key: *mut CK_OBJECT_HANDLE,
    ph_priv_key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "MECH", "C_GenerateKeyPair session={}", h_session);
    if p_mechanism.is_null() || ph_pub_key.is_null() || ph_priv_key.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if (ul_pub_count > 0 && p_pub_template.is_null()) || (ul_priv_count > 0 && p_priv_template.is_null()) {
        return CKR_ARGUMENTS_BAD;
    }
    let slot_id = ck_try!(session_slot(h_session));
    let mech = &*p_mechanism;
    let pub_attrs = ffi_api_crypto::collect_template(p_pub_template, ul_pub_count);
    let mut priv_attrs = ffi_api_crypto::collect_template(p_priv_template, ul_priv_count);

    let pub_is_token = pub_attrs
        .get(&CKA_TOKEN)
        .is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE);
    let priv_is_token = priv_attrs
        .get(&CKA_TOKEN)
        .is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE);
    if pub_is_token || priv_is_token {
        ck_try!(require_rw_session(h_session));
    }

    // Inject security defaults for the private key.
    priv_attrs.entry(CKA_SENSITIVE).or_insert_with(|| vec![CK_TRUE]);
    priv_attrs.entry(CKA_EXTRACTABLE).or_insert_with(|| vec![CK_FALSE]);
    let priv_always_sensitive = priv_attrs
        .get(&CKA_SENSITIVE)
        .map_or(true, |v| !v.is_empty() && v[0] == CK_TRUE);
    let priv_never_extractable = priv_attrs
        .get(&CKA_EXTRACTABLE)
        .map_or(true, |v| v.is_empty() || v[0] == CK_FALSE);
    // CKA_ALWAYS_AUTHENTICATE is a struct field, not stored in the HashMap.
    let priv_always_authenticate = priv_attrs
        .remove(&CKA_ALWAYS_AUTHENTICATE)
        .is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE);

    // Helper: stamp a GeneratedKey into the object store, returning its handle.
    let store_pair =
        |gen: backend::GeneratedKey, always_sensitive: bool, never_extractable: bool, always_authenticate: bool| {
            let h = object_store::next_handle();
            let mut obj = object_store::KeyObject::new(h, slot_id, gen.key_type, gen.key_ref, gen.attrs);
            obj.local = true;
            obj.key_gen_mechanism = gen.key_gen_mechanism;
            obj.always_sensitive = always_sensitive;
            obj.never_extractable = never_extractable;
            obj.always_authenticate = always_authenticate;
            object_store::store_object(obj, Some(h_session));
            h
        };
    let store_pub = |gen: backend::GeneratedKey| {
        let h = object_store::next_handle();
        let mut obj = object_store::KeyObject::new(h, slot_id, gen.key_type, gen.key_ref, gen.attrs);
        obj.local = true;
        obj.key_gen_mechanism = gen.key_gen_mechanism;
        object_store::store_object(obj, Some(h_session));
        h
    };

    match mech.mechanism {
        CKM_RSA_PKCS_KEY_PAIR_GEN => {
            let bits = pub_attrs
                .get(&CKA_MODULUS_BITS)
                .map(|b| backend::bytes_to_ulong(b) as u32)
                .unwrap_or(2048);
            if bits < 1024 {
                return CKR_KEY_SIZE_RANGE;
            }
            let (priv_gen, pub_gen) = ck_try!(backend::generate_rsa_key_pair(
                slot_id, bits, 65537, pub_attrs, priv_attrs,
            ));
            *ph_pub_key = store_pub(pub_gen);
            *ph_priv_key = store_pair(
                priv_gen,
                priv_always_sensitive,
                priv_never_extractable,
                priv_always_authenticate,
            );
        },
        CKM_EC_KEY_PAIR_GEN => {
            let curve = ec_curve_from_params(pub_attrs.get(&CKA_EC_PARAMS).map(|v| v.as_slice()));
            let (priv_gen, pub_gen) = ck_try!(backend::generate_ec_key_pair(slot_id, curve, pub_attrs, priv_attrs,));
            *ph_pub_key = store_pub(pub_gen);
            *ph_priv_key = store_pair(
                priv_gen,
                priv_always_sensitive,
                priv_never_extractable,
                priv_always_authenticate,
            );
        },
        CKM_EC_EDWARDS_KEY_PAIR_GEN => {
            // Default to Ed25519; could inspect CKA_EC_PARAMS to choose Ed448
            let curve = crate::types::EdwardsCurve::Ed25519;
            let (priv_gen, pub_gen) = ck_try!(backend::generate_ed_key_pair(slot_id, curve, pub_attrs, priv_attrs,));
            *ph_pub_key = store_pub(pub_gen);
            *ph_priv_key = store_pair(
                priv_gen,
                priv_always_sensitive,
                priv_never_extractable,
                priv_always_authenticate,
            );
        },
        _ => {
            warn!(context: "MECH", "C_GenerateKeyPair rejected mechanism={}", mech.mechanism);
            return CKR_MECHANISM_INVALID;
        },
    }
    info!(context: "MECH", "C_GenerateKeyPair created pub_handle={} priv_handle={} mech={}", *ph_pub_key, *ph_priv_key, mech.mechanism);
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GenerateKey(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: *const CK_MECHANISM,
    p_template: *const CK_ATTRIBUTE,
    ul_count: CK_ULONG,
    ph_key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "MECH", "C_GenerateKey session={}", h_session);

    if p_mechanism.is_null() || ph_key.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if ul_count > 0 && p_template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let slot_id = ck_try!(session_slot(h_session));
    let mech = &*p_mechanism;
    let mut attrs = ffi_api_crypto::collect_template(p_template, ul_count);

    // Evaluate Token Status for Session R/W requirements
    let is_token = attrs.get(&CKA_TOKEN).is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE);
    if is_token {
        ck_try!(require_rw_session(h_session));
    }

    // Template Consistency Checks (Class & Key Type)
    if let Some(class_val) = attrs.get(&CKA_CLASS) {
        if backend::bytes_to_ulong(class_val) != CKO_SECRET_KEY {
            return CKR_TEMPLATE_INCONSISTENT;
        }
    }

    let expected_key_type = match mech.mechanism {
        CKM_AES_KEY_GEN => CKK_AES,
        CKM_DES_KEY_GEN => CKK_DES,
        CKM_DES3_KEY_GEN => CKK_DES3,
        CKM_CHACHA20_KEY_GEN => CKK_CHACHA20,
        CKM_GENERIC_SECRET_KEY_GEN => CKK_GENERIC_SECRET,
        _ => {
            warn!(context: "MECH", "C_GenerateKey rejected mechanism={}", mech.mechanism);
            return CKR_MECHANISM_INVALID;
        },
    };

    if let Some(type_val) = attrs.get(&CKA_KEY_TYPE) {
        if backend::bytes_to_ulong(type_val) != expected_key_type {
            return CKR_TEMPLATE_INCONSISTENT;
        }
    }

    attrs.entry(CKA_SENSITIVE).or_insert_with(|| vec![CK_TRUE]);
    attrs.entry(CKA_EXTRACTABLE).or_insert_with(|| vec![CK_FALSE]);
    let always_sensitive = attrs
        .get(&CKA_SENSITIVE)
        .map_or(true, |v| !v.is_empty() && v[0] == CK_TRUE);
    let never_extractable = attrs
        .get(&CKA_EXTRACTABLE)
        .map_or(true, |v| v.is_empty() || v[0] == CK_FALSE);

    let gen = match mech.mechanism {
        CKM_AES_KEY_GEN => {
            let key_len = attrs
                .get(&CKA_VALUE_LEN)
                .map(|b| backend::bytes_to_ulong(b) as usize)
                .unwrap_or(32);
            ck_try!(backend::generate_aes_key(slot_id, key_len, attrs))
        },
        CKM_DES_KEY_GEN => {
            ck_try!(backend::generate_legacy_secret_key(
                slot_id,
                mech.mechanism,
                8,
                CKK_DES,
                attrs
            ))
        },
        CKM_DES3_KEY_GEN => {
            ck_try!(backend::generate_legacy_secret_key(
                slot_id,
                mech.mechanism,
                24,
                CKK_DES3,
                attrs
            ))
        },
        CKM_CHACHA20_KEY_GEN => {
            ck_try!(backend::generate_chacha20_key(slot_id, attrs))
        },
        // Generate the generic key
        CKM_GENERIC_SECRET_KEY_GEN => {
            let key_len = attrs
                .get(&CKA_VALUE_LEN)
                .map(|b| backend::bytes_to_ulong(b) as usize)
                .unwrap_or(32);
            ck_try!(backend::generate_generic_secret_key(slot_id, key_len, attrs))
            // <--- Make sure this exists in your backend!
        },
        _ => return CKR_MECHANISM_INVALID,
    };

    let handle = object_store::next_handle();
    let mut obj = object_store::KeyObject::new(handle, slot_id, gen.key_type, gen.key_ref, gen.attrs);
    obj.local = true;
    obj.key_gen_mechanism = gen.key_gen_mechanism;
    obj.always_sensitive = always_sensitive;
    obj.never_extractable = never_extractable;
    object_store::store_object(obj, Some(h_session));
    *ph_key = handle;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GenerateRandom(
    h_session: CK_SESSION_HANDLE,
    p_random: *mut CK_BYTE,
    ul_random_len: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "MECH", "C_GenerateRandom session={} bytes={}", h_session, ul_random_len);
    if p_random.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let slot_id = ck_try!(session_slot(h_session));
    let buf = std::slice::from_raw_parts_mut(p_random, ul_random_len as usize);
    ck_try!(backend::generate_random(slot_id, buf));
    CKR_OK
}

// ── C_CreateObject ────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_CreateObject(
    h_session: CK_SESSION_HANDLE,
    p_template: *const CK_ATTRIBUTE,
    ul_count: CK_ULONG,
    ph_object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "ATTR", "C_CreateObject session={} attr_count={}", h_session, ul_count);
    if ph_object.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if p_template.is_null() || ul_count == 0 {
        return CKR_TEMPLATE_INCOMPLETE;
    }
    let slot_id = ck_try!(session_slot(h_session));
    let attrs = ffi_api_crypto::collect_template(p_template, ul_count);
    let is_token = attrs.get(&CKA_TOKEN).is_some_and(|v| !v.is_empty() && v[0] == CK_TRUE);
    if is_token {
        ck_try!(require_rw_session(h_session));
    }
    // We only support importing AES secret key values via CKA_VALUE
    let class = match attrs.get(&CKA_CLASS).map(|b| backend::bytes_to_ulong(b)) {
        Some(CKO_SECRET_KEY | CKO_PUBLIC_KEY | CKO_PRIVATE_KEY | CKO_DATA) => {
            attrs.get(&CKA_CLASS).map(|b| backend::bytes_to_ulong(b)).unwrap()
        },
        None => return CKR_TEMPLATE_INCOMPLETE,
        _ => return CKR_TEMPLATE_INCONSISTENT,
    };
    let mut key_bytes = Vec::new();

    if class == CKO_SECRET_KEY || class == CKO_DATA {
        if let Some(v) = attrs.get(&CKA_VALUE) {
            key_bytes = v.clone();
        } else {
            return CKR_TEMPLATE_INCOMPLETE;
        }
        // Optional: Length checks for AES
    }

    let handle = object_store::next_handle();
    let key_type = match attrs.get(&CKA_KEY_TYPE).map(|b| backend::bytes_to_ulong(b)) {
        Some(CKK_RSA) if class == CKO_PUBLIC_KEY => object_store::KeyType::RsaPublic,
        Some(CKK_RSA) if class == CKO_PRIVATE_KEY => object_store::KeyType::RsaPrivate,
        Some(CKK_AES) => object_store::KeyType::AesSecret,
        Some(CKK_DES | CKK_DES3 | CKK_GENERIC_SECRET) | None => object_store::KeyType::GenericSecret,
        _ => object_store::KeyType::GenericSecret,
    };
    let obj = object_store::KeyObject::new(
        handle,
        slot_id,
        key_type,
        crate::traits::EngineKeyRef::from_bytes(key_bytes),
        attrs,
    );
    object_store::store_object(obj, Some(h_session));
    *ph_object = handle;
    CKR_OK
}

// ── C_DestroyObject ───────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn C_DestroyObject(h_session: CK_SESSION_HANDLE, h_object: CK_OBJECT_HANDLE) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "STORE", "C_DestroyObject session={} object={}", h_session, h_object);
    let (slot_id, logged_in) = ck_try!(session::with_session(h_session, |s| {
        Ok((s.slot_id, s.login_state != LoginState::NotLoggedIn))
    }));
    // Find the object and check its token status
    let is_token_object = ck_try!(object_store::with_object(h_object, |obj| {
        Ok(object_store::is_token_object(obj))
    }));

    // ONLY require RW session if the object is a Token Object
    if is_token_object {
        ck_try!(require_rw_session(h_session));
    }
    // Validate object exists and belongs to this slot, check access rules.
    ck_try!(object_store::with_object_for_slot(h_object, slot_id, |obj| {
        // Private objects require login.
        if object_store::is_private_object(obj) && !logged_in {
            return Err(Pkcs11Error::UserNotLoggedIn);
        }
        Ok(())
    }));
    ck_try!(object_store::destroy_object(h_object));
    CKR_OK
}

// ── Struct-field attribute synthesis ─────────────────────────────────────────

/// Return a synthesised attribute value for attributes that live as struct
/// fields on `KeyObject` rather than in the attributes HashMap.  Returns
/// `None` for attributes not managed here (fall through to the HashMap).
fn key_object_field_attr(obj: &object_store::KeyObject, attr_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
    let bool_byte = |b: bool| vec![if b { CK_TRUE } else { CK_FALSE }];
    match attr_type {
        CKA_LOCAL => Some(bool_byte(obj.local)),
        CKA_ALWAYS_SENSITIVE => Some(bool_byte(obj.always_sensitive)),
        CKA_NEVER_EXTRACTABLE => Some(bool_byte(obj.never_extractable)),
        CKA_ALWAYS_AUTHENTICATE => Some(bool_byte(obj.always_authenticate)),
        CKA_KEY_GEN_MECHANISM => Some(obj.key_gen_mechanism.to_le_bytes().to_vec()),
        _ => None,
    }
}

// ── C_GetAttributeValue ───────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_GetAttributeValue(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    p_template: *mut CK_ATTRIBUTE,
    ul_count: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "ATTR", "C_GetAttributeValue session={} object={} count={}", h_session, h_object, ul_count);
    if p_template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let slot_id = ck_try!(session_slot(h_session));
    let attrs = std::slice::from_raw_parts_mut(p_template, ul_count as usize);
    let mut any_too_small = false;
    let mut any_sensitive = false;
    let mut any_unavailable = false;

    ck_try!(object_store::with_object_for_slot(h_object, slot_id, |obj| {
        for attr in attrs.iter_mut() {
            // Access control: block CKA_VALUE for sensitive/non-extractable keys.
            if let Err(Pkcs11Error::AttributeSensitive) = attribute_policy::check_attribute_access(attr.r#type, obj) {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                any_sensitive = true;
                continue;
            }
            // Struct-field attributes — synthesised from KeyObject fields, not stored
            // in the attributes HashMap.
            let val_bytes: Vec<u8> = if let Some(v) = key_object_field_attr(obj, attr.r#type) {
                v
            } else if let Some(cached) = obj.attributes.get(&attr.r#type) {
                // Primary path: pre-cached HashMap (no DER parsing).
                cached.clone()
            } else {
                let is_private_key_object = obj.key_type == object_store::KeyType::RsaPrivate
                    || obj
                        .attributes
                        .get(&CKA_CLASS)
                        .map(|v| backend::bytes_to_ulong(v) == CKO_PRIVATE_KEY)
                        .unwrap_or(false);
                if is_private_key_object && is_private_component_attr(attr.r#type) {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    any_sensitive = true;
                    continue;
                }
                // Fallback: ask the engine (parses key_der on demand).
                match backend::get_attribute(obj.slot_id, obj, attr.r#type) {
                    Ok(bytes) => bytes,
                    Err(Pkcs11Error::AttributeSensitive) => {
                        attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        any_sensitive = true;
                        continue;
                    },
                    Err(Pkcs11Error::InvalidAttributeType) => {
                        let is_private_key_object = obj.key_type == object_store::KeyType::RsaPrivate
                            || obj
                                .attributes
                                .get(&CKA_CLASS)
                                .map(|v| backend::bytes_to_ulong(v) == CKO_PRIVATE_KEY)
                                .unwrap_or(false);
                        if is_private_key_object && is_private_component_attr(attr.r#type) {
                            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            any_sensitive = true;
                            continue;
                        }
                        attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        any_unavailable = true;
                        continue;
                    },
                    Err(e) => return Err(e),
                }
            };

            if attr.pValue.is_null() {
                attr.ulValueLen = val_bytes.len() as CK_ULONG;
            } else if (attr.ulValueLen as usize) < val_bytes.len() {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                any_too_small = true;
            } else {
                std::ptr::copy_nonoverlapping(val_bytes.as_ptr(), attr.pValue as *mut u8, val_bytes.len());
                attr.ulValueLen = val_bytes.len() as CK_ULONG;
            }
        }
        Ok(())
    }));

    // PKCS#11 priority: sensitive > unavailable > buffer-too-small > ok
    if any_sensitive {
        CKR_ATTRIBUTE_SENSITIVE
    } else if any_unavailable {
        CKR_ATTRIBUTE_TYPE_INVALID
    } else if any_too_small {
        CKR_BUFFER_TOO_SMALL
    } else {
        CKR_OK
    }
}

// ── C_SetAttributeValue ───────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_SetAttributeValue(
    h_session: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    p_template: *mut CK_ATTRIBUTE,
    ul_count: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    ck_try!(require_rw_session(h_session));
    if p_template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let attrs = std::slice::from_raw_parts(p_template, ul_count as usize);
    let mut mutated_token_object = false;
    ck_try!(object_store::with_object_mut(h_object, |obj| {
        for attr in attrs {
            if attr.pValue.is_null() {
                continue;
            }
            let bytes = std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize);
            // Enforce one-way ratchets and immutability rules.
            let old_val = obj.attributes.get(&attr.r#type).map(|v| v.as_slice());
            attribute_policy::validate_attribute_change(attr.r#type, old_val, bytes)?;
            // Apply the change.
            obj.attributes.insert(attr.r#type, bytes.to_vec());
            // Keep always_sensitive / never_extractable in sync.
            attribute_policy::update_derived_attributes(obj, attr.r#type);
        }
        // Gate persistence: only token objects are saved to disk.
        mutated_token_object = !object_store::is_session_object(obj);
        Ok(())
    }));
    if mutated_token_object {
        object_store::persist_to_disk();
    }
    CKR_OK
}

// ── Find objects ──────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_FindObjectsInit(
    h_session: CK_SESSION_HANDLE,
    p_template: *const CK_ATTRIBUTE,
    ul_count: CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "STORE", "C_FindObjectsInit called session={} count={}", h_session, ul_count);
    let (slot_id, logged_in) = ck_try!(session::with_session(h_session, |s| {
        Ok((s.slot_id, s.login_state != LoginState::NotLoggedIn))
    }));
    let template = ffi_api_crypto::collect_template_vec(p_template, ul_count);
    let results = object_store::find_objects(slot_id, &template, logged_in);
    ck_try!(session::with_session_mut(h_session, |s| {
        if s.find_ctx.is_some() {
            return Err(Pkcs11Error::OperationActive);
        }
        s.find_ctx = Some(FindContext { results, index: 0 });
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_FindObjects(
    h_session: CK_SESSION_HANDLE,
    ph_object: *mut CK_OBJECT_HANDLE,
    ul_max_count: CK_ULONG,
    pul_count: *mut CK_ULONG,
) -> CK_RV {
    ck_try!(check_init());
    trace!(context: "STORE", "C_FindObjects called session={} max={}", h_session, ul_max_count);
    if ph_object.is_null() || pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    ck_try!(session::with_session_mut(h_session, |s| {
        let ctx = s.find_ctx.as_mut().ok_or(Pkcs11Error::OperationNotInitialised)?;
        let avail = ctx.results.len().saturating_sub(ctx.index);
        let n = avail.min(ul_max_count as usize);
        for i in 0..n {
            *ph_object.add(i) = ctx.results[ctx.index + i];
        }
        ctx.index += n;
        *pul_count = n as CK_ULONG;
        Ok(())
    }));
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(h_session: CK_SESSION_HANDLE) -> CK_RV {
    ck_try!(check_init());
    debug!(context: "STORE", "C_FindObjectsFinal called session={}", h_session);
    ck_try!(session::with_session_mut(h_session, |s| {
        s.find_ctx = None;
        Ok(())
    }));
    CKR_OK
}

// ── helpers ───────────────────────────────────────────────────────────────────

// DER-encoded curve OIDs for CKA_EC_PARAMS
const OID_P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

fn ec_curve_from_params(ec_params: Option<&[u8]>) -> crate::types::EcCurve {
    match ec_params {
        Some(OID_P384) => crate::types::EcCurve::P384,
        Some(OID_P521) => crate::types::EcCurve::P521,
        _ => crate::types::EcCurve::P256, // default / P256 OID
    }
}
