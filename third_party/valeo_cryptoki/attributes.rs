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

/// PKCS#11 attribute types — CKA_* constants.
///
/// The discriminant values match the PKCS#11 specification so the PKCS#11
/// layer can convert directly: `attr_type as u32` == `CKA_*` value.
///
/// Usage in a PKCS#11 implementation:
///
/// // C_GetAttributeValue: map CK_ATTRIBUTE_TYPE → AttributeType, call engine,
/// // then write AttributeValue bytes into the caller's pValue buffer.
/// //let val = engine()?.rsa_attribute(&key_der, is_private, AttributeType::Modulus)?;
///
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeType {
    Class              = 0x00000000, // CKA_CLASS
    Token              = 0x00000001, // CKA_TOKEN
    Private            = 0x00000002, // CKA_PRIVATE
    Label              = 0x00000003, // CKA_LABEL
    Value              = 0x00000011, // CKA_VALUE
    KeyType            = 0x00000100, // CKA_KEY_TYPE
    Id                 = 0x00000102, // CKA_ID
    Sensitive          = 0x00000103, // CKA_SENSITIVE
    Encrypt            = 0x00000104, // CKA_ENCRYPT
    Decrypt            = 0x00000105, // CKA_DECRYPT
    Wrap               = 0x00000106, // CKA_WRAP
    Unwrap             = 0x00000107, // CKA_UNWRAP
    Sign               = 0x00000108, // CKA_SIGN
    Verify             = 0x00000109, // CKA_VERIFY
    Derive             = 0x0000010C, // CKA_DERIVE
    Modulus            = 0x00000120, // CKA_MODULUS            (RSA)
    ModulusBits        = 0x00000121, // CKA_MODULUS_BITS       (RSA)
    PublicExponent     = 0x00000122, // CKA_PUBLIC_EXPONENT    (RSA)
    ValueLen           = 0x00000161, // CKA_VALUE_LEN          (AES)
    Extractable        = 0x00000162, // CKA_EXTRACTABLE
    Local              = 0x00000163, // CKA_LOCAL
    NeverExtractable   = 0x00000164, // CKA_NEVER_EXTRACTABLE
    AlwaysSensitive    = 0x00000165, // CKA_ALWAYS_SENSITIVE
    Modifiable         = 0x00000170, // CKA_MODIFIABLE
    EcParams           = 0x00000180, // CKA_EC_PARAMS          (EC)
    EcPoint            = 0x00000181, // CKA_EC_POINT           (EC)
    AlwaysAuthenticate = 0x00000202, // CKA_ALWAYS_AUTHENTICATE
    Destroyable        = 0x00000172, // CKA_DESTROYABLE (v3.0)
    Copyable           = 0x00000171, // CKA_COPYABLE (v3.0)
    UniqueId           = 0x0000010A, // CKA_UNIQUE_ID (v3.0)
    ProfileId          = 0x00000601, // CKA_PROFILE_ID (v3.0)
    VendorDefined      = 0x80000000, // CKA_VENDOR_DEFINED
}

impl AttributeType {
    /// Construct from a raw CKA_* u32 value.
    /// Returns `None` for unknown values (use `CKR_ATTRIBUTE_TYPE_INVALID`).
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x00000000 => Some(Self::Class),
            0x00000001 => Some(Self::Token),
            0x00000002 => Some(Self::Private),
            0x00000003 => Some(Self::Label),
            0x00000011 => Some(Self::Value),
            0x00000100 => Some(Self::KeyType),
            0x00000102 => Some(Self::Id),
            0x00000103 => Some(Self::Sensitive),
            0x00000104 => Some(Self::Encrypt),
            0x00000105 => Some(Self::Decrypt),
            0x00000106 => Some(Self::Wrap),
            0x00000107 => Some(Self::Unwrap),
            0x00000108 => Some(Self::Sign),
            0x00000109 => Some(Self::Verify),
            0x0000010C => Some(Self::Derive),
            0x00000120 => Some(Self::Modulus),
            0x00000121 => Some(Self::ModulusBits),
            0x00000122 => Some(Self::PublicExponent),
            0x00000161 => Some(Self::ValueLen),
            0x00000162 => Some(Self::Extractable),
            0x00000163 => Some(Self::Local),
            0x00000164 => Some(Self::NeverExtractable),
            0x00000165 => Some(Self::AlwaysSensitive),
            0x00000170 => Some(Self::Modifiable),
            0x00000180 => Some(Self::EcParams),
            0x00000181 => Some(Self::EcPoint),
            0x00000202 => Some(Self::AlwaysAuthenticate),
            0x00000172 => Some(Self::Destroyable),
            0x00000171 => Some(Self::Copyable),
            0x0000010A => Some(Self::UniqueId),
            0x00000601 => Some(Self::ProfileId),
            0x80000000 => Some(Self::VendorDefined),
            _ => None,
        }
    }
}

/// Typed attribute value for a CKA_* query result.
///
/// The PKCS#11 layer serialises this into the caller's `pValue` buffer:
/// - `Bool(b)`    → `CK_BBOOL` (1 byte: 0x00 or 0x01)
/// - `Ulong(n)`   → `CK_ULONG` (4 or 8 bytes, platform-dependent in PKCS#11)
/// - `Bytes(vec)` → raw bytes copied into pValue
#[derive(Debug, Clone)]
pub enum AttributeValue {
    /// Boolean attribute (CK_BBOOL).
    Bool(bool),
    /// Unsigned integer attribute (CK_ULONG).
    Ulong(u64),
    /// Byte-array attribute (CK_BYTE[]).
    Bytes(Vec<u8>),
}

impl AttributeValue {
    /// Serialise to raw bytes in PKCS#11 wire format.
    ///
    /// - `Bool`  → 1 byte (0x00 = false, 0x01 = true)
    /// - `Ulong` → 8 bytes little-endian (matches CK_ULONG on 64-bit platforms)
    /// - `Bytes` → the bytes as-is
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            AttributeValue::Bool(b)    => vec![if *b { 0x01 } else { 0x00 }],
            AttributeValue::Ulong(n)   => n.to_le_bytes().to_vec(),
            AttributeValue::Bytes(v)   => v.clone(),
        }
    }

    /// Byte length of the serialised value (for CK_ATTRIBUTE.ulValueLen).
    pub fn len(&self) -> usize {
        match self {
            AttributeValue::Bool(_)    => 1,
            AttributeValue::Ulong(_)   => 8,
            AttributeValue::Bytes(v)   => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
