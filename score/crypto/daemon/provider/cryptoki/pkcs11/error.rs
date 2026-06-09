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

//! PKCS#11 error type with CK_RV conversion.
use super::constants::*;
use super::types::CK_RV;

/// Unified error type for the PKCS#11 layer.
/// Every variant maps to a specific `CKR_*` return code via [`Pkcs11Error::to_ckr`].
#[derive(Debug)]
pub enum Pkcs11Error {
    NotInitialised,
    AlreadyInitialised,
    InvalidSlotId,
    InvalidSessionHandle,
    InvalidObjectHandle,
    InvalidMechanism,
    MechanismUnsupported,
    MechanismParamInvalid,
    InvalidAttributeType,
    AttributeReadOnly,
    AttributeValueInvalid,
    AttributeSensitive,
    TemplateIncomplete,
    TemplateInconsistent,
    ArgumentsBad,
    BufferTooSmall(usize),
    UserNotLoggedIn,
    UserAlreadyLoggedIn,
    UserAnotherAlreadyLoggedIn,
    UserPinNotInitialized,
    UserTypeInvalid,
    PinIncorrect,
    PinLenRange,
    PinLocked,
    OperationActive,
    OperationNotInitialised,
    SessionReadOnly,
    SessionParallelNotSupported,
    SessionReadWriteSoExists,
    TokenWriteProtected,
    KeyTypeInconsistent,
    KeyHandleInvalid,
    KeySizeRange,
    KeyFunctionNotPermitted,
    KeyNotExtractable,
    KeyNotWrappable,
    SignatureInvalid,
    DataInvalid,
    DataLenRange,
    EncryptedDataInvalid,
    FunctionNotSupported,
    GeneralError,
    OpenSsl(openssl::error::ErrorStack),
}

impl Pkcs11Error {
    pub fn to_ckr(&self) -> CK_RV {
        match self {
            Self::NotInitialised          => CKR_CRYPTOKI_NOT_INITIALIZED,
            Self::AlreadyInitialised      => CKR_CRYPTOKI_ALREADY_INITIALIZED,
            Self::InvalidSlotId           => CKR_SLOT_ID_INVALID,
            Self::InvalidSessionHandle    => CKR_SESSION_HANDLE_INVALID,
            Self::InvalidObjectHandle     => CKR_OBJECT_HANDLE_INVALID,
            Self::InvalidMechanism
            | Self::MechanismUnsupported  => CKR_MECHANISM_INVALID,
            Self::MechanismParamInvalid   => CKR_MECHANISM_PARAM_INVALID,
            Self::InvalidAttributeType    => CKR_ATTRIBUTE_TYPE_INVALID,
            Self::AttributeReadOnly       => CKR_ATTRIBUTE_READ_ONLY,
            Self::AttributeValueInvalid   => CKR_ATTRIBUTE_VALUE_INVALID,
            Self::AttributeSensitive      => CKR_ATTRIBUTE_SENSITIVE,
            Self::TemplateIncomplete      => CKR_TEMPLATE_INCOMPLETE,
            Self::TemplateInconsistent    => CKR_TEMPLATE_INCONSISTENT,
            Self::ArgumentsBad            => CKR_ARGUMENTS_BAD,
            Self::BufferTooSmall(_)       => CKR_BUFFER_TOO_SMALL,
            Self::UserNotLoggedIn              => CKR_USER_NOT_LOGGED_IN,
            Self::UserAlreadyLoggedIn          => CKR_USER_ALREADY_LOGGED_IN,
            Self::UserAnotherAlreadyLoggedIn   => CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
            Self::UserPinNotInitialized        => CKR_USER_PIN_NOT_INITIALIZED,
            Self::UserTypeInvalid              => CKR_USER_TYPE_INVALID,
            Self::PinIncorrect                 => CKR_PIN_INCORRECT,
            Self::PinLenRange                  => CKR_PIN_LEN_RANGE,
            Self::PinLocked                    => CKR_PIN_LOCKED,
            Self::OperationActive         => CKR_OPERATION_ACTIVE,
            Self::OperationNotInitialised => CKR_OPERATION_NOT_INITIALIZED,
            Self::SessionReadOnly         => CKR_SESSION_READ_ONLY,
            Self::SessionParallelNotSupported => CKR_SESSION_PARALLEL_NOT_SUPPORTED,
            Self::SessionReadWriteSoExists    => CKR_SESSION_READ_WRITE_SO_EXISTS,
            Self::TokenWriteProtected         => CKR_TOKEN_WRITE_PROTECTED,
            Self::KeyTypeInconsistent     => CKR_KEY_TYPE_INCONSISTENT,
            Self::KeyHandleInvalid        => CKR_KEY_HANDLE_INVALID,
            Self::KeySizeRange            => CKR_KEY_SIZE_RANGE,
            Self::KeyFunctionNotPermitted => CKR_KEY_FUNCTION_NOT_PERMITTED,
            Self::KeyNotExtractable       => CKR_KEY_UNEXTRACTABLE,
            Self::KeyNotWrappable         => CKR_KEY_NOT_WRAPPABLE,
            Self::SignatureInvalid        => CKR_SIGNATURE_INVALID,
            Self::DataInvalid             => CKR_DATA_INVALID,
            Self::DataLenRange            => CKR_DATA_LEN_RANGE,
            Self::EncryptedDataInvalid    => CKR_ENCRYPTED_DATA_INVALID,
            Self::FunctionNotSupported    => CKR_FUNCTION_NOT_SUPPORTED,
            Self::GeneralError
            | Self::OpenSsl(_)            => CKR_GENERAL_ERROR,
        }
    }
}

impl From<openssl::error::ErrorStack> for Pkcs11Error {
    fn from(e: openssl::error::ErrorStack) -> Self { Pkcs11Error::OpenSsl(e) }
}

impl From<crate::error::CryptoError> for Pkcs11Error {
    fn from(e: crate::error::CryptoError) -> Self {
        use crate::error::CryptoError::*;
        match e {
            KeyGenFailed { .. }          => Pkcs11Error::GeneralError,
            InvalidKeyData { .. }        => Pkcs11Error::KeyHandleInvalid,
            InvalidKeySize { .. }        => Pkcs11Error::KeySizeRange,
            DataInvalid { .. }           => Pkcs11Error::DataInvalid,
            DataLenRange { .. }          => Pkcs11Error::DataLenRange,
            EncryptFailed { .. }         => Pkcs11Error::GeneralError,
            DecryptFailed { .. }         => Pkcs11Error::EncryptedDataInvalid,
            SignFailed { .. }            => Pkcs11Error::GeneralError,
            VerifyFailed { .. }          => Pkcs11Error::SignatureInvalid,
            SignatureLenRange { .. }     => Pkcs11Error::SignatureInvalid,
            HashFailed { .. }            => Pkcs11Error::GeneralError,
            RandomFailed { .. }          => Pkcs11Error::GeneralError,
            BufferTooSmall { needed }    => Pkcs11Error::BufferTooSmall(needed),
            MechanismInvalid { .. }      => Pkcs11Error::InvalidMechanism,
            MechanismParamInvalid { .. } => Pkcs11Error::MechanismParamInvalid,
            AttributeTypeInvalid         => Pkcs11Error::InvalidAttributeType,
            AttributeSensitive           => Pkcs11Error::AttributeSensitive,
            AttributeValueInvalid        => Pkcs11Error::AttributeValueInvalid,
            NotInitialized               => Pkcs11Error::NotInitialised,
            AlreadyInitialized           => Pkcs11Error::AlreadyInitialised,
            GeneralError { .. }          => Pkcs11Error::GeneralError,
            SlotIdInvalid                => Pkcs11Error::InvalidSlotId,
        }
    }
}

pub type Result<T> = std::result::Result<T, Pkcs11Error>;
