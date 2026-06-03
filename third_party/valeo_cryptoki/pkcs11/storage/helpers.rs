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
use super::super::constants::CKA_TOKEN;
use super::super::object_store::KeyObject;
use super::super::types::CK_TRUE;

pub fn is_token_object(obj: &KeyObject) -> bool {
    obj.attributes
        .get(&CKA_TOKEN)
        .map(|v| !v.is_empty() && v[0] == CK_TRUE)
        .unwrap_or(false)
}
