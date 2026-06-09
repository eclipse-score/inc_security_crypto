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

/// Unified error type for all crypto engine operations.
/// Every variant maps to a PKCS#11 CKR_* return code via `ckr_code()`.
#[derive(Debug)]
pub enum CryptoError {
    /// CKR_GENERAL_ERROR
    KeyGenFailed { message: String },
    /// CKR_KEY_HANDLE_INVALID
    InvalidKeyData { message: String },
    /// CKR_KEY_SIZE_RANGE
    InvalidKeySize { message: String },
    /// CKR_DATA_INVALID
    DataInvalid { message: String },
    /// CKR_DATA_LEN_RANGE
    DataLenRange { message: String },
    /// CKR_GENERAL_ERROR
    EncryptFailed { message: String },
    /// CKR_ENCRYPTED_DATA_INVALID
    DecryptFailed { message: String },
    /// CKR_GENERAL_ERROR
    SignFailed { message: String },
    /// CKR_SIGNATURE_INVALID
    VerifyFailed { message: String },
    /// CKR_SIGNATURE_LEN_RANGE
    SignatureLenRange { message: String },
    /// CKR_GENERAL_ERROR
    HashFailed { message: String },
    /// CKR_RANDOM_NO_RNG
    RandomFailed { message: String },
    /// CKR_BUFFER_TOO_SMALL
    BufferTooSmall { needed: usize },
    /// CKR_MECHANISM_INVALID
    MechanismInvalid { name: &'static str },
    /// CKR_MECHANISM_PARAM_INVALID
    MechanismParamInvalid { message: String },
    /// CKR_ATTRIBUTE_TYPE_INVALID
    AttributeTypeInvalid,
    /// CKR_ATTRIBUTE_SENSITIVE
    AttributeSensitive,
    /// CKR_ATTRIBUTE_VALUE_INVALID
    AttributeValueInvalid,
    /// CKR_CRYPTOKI_NOT_INITIALIZED
    NotInitialized,
    /// CKR_CRYPTOKI_ALREADY_INITIALIZED
    AlreadyInitialized,
    /// CKR_GENERAL_ERROR
    GeneralError { message: String },
    /// CKR_SLOT_ID_INVALID
    SlotIdInvalid,
}

impl CryptoError {
    /// Returns the PKCS#11 CKR_* return code for this error.
    pub fn ckr_code(&self) -> u32 {
        match self {
            Self::KeyGenFailed { .. }          => 0x00000005,
            Self::InvalidKeyData { .. }        => 0x00000060,
            Self::InvalidKeySize { .. }        => 0x00000062,
            Self::DataInvalid { .. }           => 0x00000020,
            Self::DataLenRange { .. }          => 0x00000021,
            Self::EncryptFailed { .. }         => 0x00000005,
            Self::DecryptFailed { .. }         => 0x00000040,
            Self::SignFailed { .. }            => 0x00000005,
            Self::VerifyFailed { .. }          => 0x000000C0,
            Self::SignatureLenRange { .. }     => 0x000000C1,
            Self::HashFailed { .. }            => 0x00000005,
            Self::RandomFailed { .. }          => 0x00000121,
            Self::BufferTooSmall { .. }        => 0x00000150,
            Self::MechanismInvalid { .. }      => 0x00000070,
            Self::MechanismParamInvalid { .. } => 0x00000071,
            Self::AttributeTypeInvalid         => 0x00000012,
            Self::AttributeSensitive           => 0x00000011,
            Self::AttributeValueInvalid        => 0x00000013,
            Self::NotInitialized               => 0x00000190,
            Self::AlreadyInitialized           => 0x00000191,
            Self::GeneralError { .. }          => 0x00000005,
            Self::SlotIdInvalid                => 0x00000003,
        }
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGenFailed { message }        => write!(f, "key generation failed: {message}"),
            Self::InvalidKeyData { message }      => write!(f, "invalid key data: {message}"),
            Self::InvalidKeySize { message }      => write!(f, "invalid key size: {message}"),
            Self::DataInvalid { message }         => write!(f, "invalid data: {message}"),
            Self::DataLenRange { message }        => write!(f, "data length out of range: {message}"),
            Self::EncryptFailed { message }       => write!(f, "encryption failed: {message}"),
            Self::DecryptFailed { message }       => write!(f, "decryption failed: {message}"),
            Self::SignFailed { message }          => write!(f, "signing failed: {message}"),
            Self::VerifyFailed { message }        => write!(f, "verification failed: {message}"),
            Self::SignatureLenRange { message }   => write!(f, "signature length out of range: {message}"),
            Self::HashFailed { message }          => write!(f, "hash failed: {message}"),
            Self::RandomFailed { message }        => write!(f, "random generation failed: {message}"),
            Self::BufferTooSmall { needed }       => write!(f, "buffer too small: need {needed} bytes"),
            Self::MechanismInvalid { name }       => write!(f, "mechanism not supported: {name}"),
            Self::MechanismParamInvalid { message }=> write!(f, "invalid mechanism parameter: {message}"),
            Self::AttributeTypeInvalid            => write!(f, "attribute type invalid for this object"),
            Self::AttributeSensitive              => write!(f, "attribute is sensitive and cannot be read"),
            Self::AttributeValueInvalid           => write!(f, "attribute value is invalid"),
            Self::NotInitialized                  => write!(f, "crypto engine not initialized"),
            Self::AlreadyInitialized              => write!(f, "crypto engine already initialized"),
            Self::GeneralError { message }        => write!(f, "general error: {message}"),
            Self::SlotIdInvalid                  => write!(f, "slot ID is invalid"),
        }
    }
}

impl std::error::Error for CryptoError {}
