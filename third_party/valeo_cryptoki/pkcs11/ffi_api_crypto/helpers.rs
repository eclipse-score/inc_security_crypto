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

// ── Private helpers ───────────────────────────────────────────────────────

pub(crate) unsafe fn collect_template(
    p_template: *const CK_ATTRIBUTE,
    ul_count:   CK_ULONG,
) -> HashMap<CK_ATTRIBUTE_TYPE, Vec<u8>> {
    let mut map = HashMap::new();
    if p_template.is_null() { return map; }
    let attrs = std::slice::from_raw_parts(p_template, ul_count as usize);
    for attr in attrs {
        if !attr.pValue.is_null() && attr.ulValueLen > 0 {
            let bytes = std::slice::from_raw_parts(
                attr.pValue as *const u8, attr.ulValueLen as usize,
            );
            map.insert(attr.r#type, bytes.to_vec());
        } else if attr.ulValueLen == 0 {
            map.insert(attr.r#type, vec![]);
        }
    }
    map
}

pub(crate) unsafe fn collect_template_vec(
    p_template: *const CK_ATTRIBUTE,
    ul_count:   CK_ULONG,
) -> Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> {
    if p_template.is_null() { return Vec::new(); }
    let attrs = std::slice::from_raw_parts(p_template, ul_count as usize);
    let mut out = Vec::with_capacity(attrs.len());
    for attr in attrs {
        if !attr.pValue.is_null() && attr.ulValueLen > 0 {
            let bytes = std::slice::from_raw_parts(
                attr.pValue as *const u8, attr.ulValueLen as usize,
            );
            out.push((attr.r#type, bytes.to_vec()));
        } else if attr.ulValueLen == 0 {
            out.push((attr.r#type, vec![]));
        }
    }
    out
}

pub(crate) unsafe fn extract_cipher_params(mech: &CK_MECHANISM) -> (Vec<u8>, Option<Vec<u8>>, usize) {
    match mech.mechanism {
        CKM_AES_CBC | CKM_AES_CBC_PAD => {
            let iv = if !mech.pParameter.is_null() && mech.ulParameterLen >= 16 {
                std::slice::from_raw_parts(mech.pParameter as *const u8, 16).to_vec()
            } else {
                vec![0u8; 16]
            };
            (iv, None, 0)
        }
        CKM_DES_CBC | CKM_DES3_CBC => {
            let iv = if !mech.pParameter.is_null() && mech.ulParameterLen >= 8 {
                std::slice::from_raw_parts(mech.pParameter as *const u8, 8).to_vec()
            } else {
                vec![0u8; 8]
            };
            (iv, None, 0)
        }
        CKM_AES_GCM => {
            if mech.pParameter.is_null() {
                return (vec![0u8; 12], None, 16);
            }
            let p = &*(mech.pParameter as *const CK_GCM_PARAMS);
            let iv = if !p.pIv.is_null() && p.ulIvLen > 0 {
                std::slice::from_raw_parts(p.pIv, p.ulIvLen as usize).to_vec()
            } else {
                vec![0u8; 12]
            };
            let aad = if !p.pAAD.is_null() && p.ulAADLen > 0 {
                Some(std::slice::from_raw_parts(p.pAAD, p.ulAADLen as usize).to_vec())
            } else {
                None
            };
            let tag_len = (p.ulTagBits / 8) as usize;
            (iv, aad, if tag_len == 0 { 16 } else { tag_len })
        }
        CKM_CHACHA20_POLY1305 => {
            // Reuse GCM_PARAMS structure for nonce/AAD (common pattern)
            if mech.pParameter.is_null() {
                return (vec![0u8; 12], None, 16);
            }
            let p = &*(mech.pParameter as *const CK_GCM_PARAMS);
            let nonce = if !p.pIv.is_null() && p.ulIvLen > 0 {
                std::slice::from_raw_parts(p.pIv, p.ulIvLen as usize).to_vec()
            } else {
                vec![0u8; 12]
            };
            let aad = if !p.pAAD.is_null() && p.ulAADLen > 0 {
                Some(std::slice::from_raw_parts(p.pAAD, p.ulAADLen as usize).to_vec())
            } else {
                None
            };
            (nonce, aad, 16)
        }
        _ => (Vec::new(), None, 0),
    }
}
