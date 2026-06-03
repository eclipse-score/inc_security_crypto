/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_CRYPTO_DAEMON_COMMON_DAEMON_ERROR_HPP
#define SCORE_CRYPTO_DAEMON_COMMON_DAEMON_ERROR_HPP

// Forward-declaration of the translation target; only ToCryptoErrorCode() needs
// the full CryptoErrorCode definition.
#include "score/mw/crypto/api/common/error_domain.hpp"

#include <cstdint>

namespace score::crypto::daemon::common
{

/// @brief Complete, self-contained error code vocabulary for the crypto daemon.
///
/// All daemon-internal code (handlers, executors, key-management, data-manager)
/// uses ONLY this enum — never score::crypto::daemon::common::DaemonErrorCode directly.
/// This makes the daemon independent of the library API version: if CryptoErrorCode
/// values or names change in a future library release, only ToCryptoErrorCode()
/// below needs updating, not the daemon implementation files.
///
/// Numeric values are stable daemon-private identifiers (0x01xx–0x0Bxx ranges
/// mirroring the API categories, 0x10xx for daemon-only codes). They are never
/// used as wire values; the IPC boundary converts to CryptoErrorCode via
/// ToCryptoErrorCode() before encoding OperationResult.
enum class DaemonErrorCode : std::uint32_t
{
    // ---- General / initialization ----
    kUninitializedStack = 0x0101,  ///< Daemon (or underlying stack) not initialised
    kAlreadyInitialized = 0x0102,  ///< Daemon (or stack) already initialised
    kConnectionFailed = 0x0103,    ///< IPC channel could not be established
    kInternalError = 0x0104,       ///< Unspecified daemon-internal error

    // ---- Operation ----
    kUnsupportedOperation = 0x0201,  ///< Requested operation is not supported by the provider
    kInvalidOperation = 0x0202,      ///< Operation not valid in the current context state
    kOperationFailed = 0x0203,       ///< Operation execution failed
    kOperationTimedOut = 0x0204,     ///< Operation exceeded its deadline

    // ---- Parameter / validation ----
    kInvalidArgument = 0x0301,         ///< Argument value is out of range or malformed
    kInvalidResourceId = 0x0302,       ///< Resource identifier does not resolve to a known resource
    kInvalidResourceType = 0x0303,     ///< Resource type does not match the expected type
    kInsufficientBufferSize = 0x0304,  ///< Output buffer provided by the caller is too small
    kInvalidFormat = 0x0305,           ///< Data format not recognised (e.g. DER/PEM)
    kParamTruncated = 0x0306,          ///< Parameter silently truncated (exceeds fixed-capacity storage)

    // ---- Streaming ----
    kStreamNotInitialized = 0x0401,  ///< Init() not called before Update()/Finalize()
    kStreamAlreadyActive = 0x0402,   ///< Init() called while a stream is already active
    kStreamIncomplete = 0x0403,      ///< Finalize() called without sufficient input data

    // ---- Algorithm ----
    kUnsupportedAlgorithm = 0x0501,  ///< Algorithm not supported by any configured provider
    kAlgorithmMismatch = 0x0502,     ///< Algorithm is incompatible with the key or slot

    // ---- Memory / resource ----
    kAllocationFailed = 0x0601,     ///< Shared-memory or heap allocation failed
    kQuotaExceeded = 0x0602,        ///< Per-application resource quota exceeded
    kInvalidMemoryRegion = 0x0603,  ///< Memory region is invalid or already released

    // ---- Context ----
    kContextCreationFailed = 0x0701,    ///< Failed to create an operation context
    kContextAlreadyDestroyed = 0x0702,  ///< Context used after destruction
    kContextResetFailed = 0x0703,       ///< Failed to reset context to initial state
    kSessionExpired = 0x0704,           ///< Session sentinel expired (context was bulk-destroyed)

    // ---- Key management ----
    kKeySlotEmpty = 0x0801,              ///< Key slot contains no key material
    kKeySlotOccupied = 0x0802,           ///< Key slot already occupied
    kKeyNotExportable = 0x0803,          ///< Key cannot be exported from its provider
    kKeyGenerationFailed = 0x0804,       ///< Key generation failed
    kKeyDerivationFailed = 0x0805,       ///< Key derivation failed
    kKeyAgreementFailed = 0x0806,        ///< Key agreement failed
    kWrapUnwrapFailed = 0x0807,          ///< Key wrap/unwrap operation failed
    kPersistFailed = 0x0808,             ///< Failed to persist ephemeral key
    kIncompatibleKeyType = 0x0809,       ///< Key type is incompatible with the requested operation
    kKeyOperationNotPermitted = 0x080A,  ///< Key's permitted-operations policy forbids this use

    // ---- Certificate ----
    kCertificateParsingFailed = 0x0901,
    kCertificateExpired = 0x0902,
    kCertificateRevoked = 0x0903,
    kCertificateVerifyFailed = 0x0904,
    kCertChainVerifyFailed = 0x0905,
    kCrlImportFailed = 0x0906,
    kCsrGenerationFailed = 0x0907,
    kOcspError = 0x0908,
    kTrustAnchorNotFound = 0x0909,

    // ---- Provider ----
    kProviderNotAvailable = 0x0A01,
    kProviderBusy = 0x0A02,
    kCrossProviderIncompatible = 0x0A03,

    // ---- Access control ----
    kAccessDenied = 0x0B01,
    kResourceNotAllocated = 0x0B02,

    // ---- Daemon-internal only (no direct single-concept CryptoErrorCode equivalent) ----
    // These codes carry finer-grained internal detail that is translated down to a
    // broader public code at the ToCryptoErrorCode() boundary.
    kInvalidState = 0x1001,                   ///< Internal state machine is in an unexpected state
    kOperationInProgress = 0x1002,            ///< A conflicting operation is already running internally
    kInvalidContext = 0x1003,                 ///< Internal context handle is null or corrupted
    kInsufficientParameters = 0x1004,         ///< A required internal parameter is absent
    kInvalidDataType = 0x1005,                ///< Parameter variant holds an unexpected alternative type
    kInvalidStreamOperation = 0x1006,         ///< Stream operation issued in the wrong internal sequence
    kAlgorithmInitializationFailed = 0x1007,  ///< Crypto algorithm context could not be set up
    kAlgorithmExecutionFailed = 0x1008,       ///< Crypto algorithm operation returned an error
    kResourceBusy = 0x1009,                   ///< An internal resource is locked by another operation
    kContextCleanupFailed = 0x100A,           ///< Internal context resources could not be fully released
    kSessionInvalid = 0x100B,                 ///< PKCS#11 session is no longer valid (token removed, HSM error)
    kUnknown = 0xFFFF,                        ///< Unclassified daemon-internal error
};

/// @brief Translates a daemon-internal error code to the closest public API error code.
///
/// This is the **sole** translation point between daemon internals and the
/// library-visible API.  All make_unexpected() calls in daemon code use
/// DaemonErrorCode.  Only the IPC boundary (control_protocol.h return_error,
/// mediator) calls this function to encode the wire OperationResult.
///
/// When CryptoErrorCode evolves in a later library version, update only this
/// function — no daemon handler or executor files need to change.
inline score::mw::crypto::CryptoErrorCode ToCryptoErrorCode(DaemonErrorCode code) noexcept
{
    using C = score::mw::crypto::CryptoErrorCode;
    switch (code)
    {
        // ---- General ----
        case DaemonErrorCode::kUninitializedStack:
            return C::kUninitializedStack;
        case DaemonErrorCode::kAlreadyInitialized:
            return C::kAlreadyInitialized;
        case DaemonErrorCode::kConnectionFailed:
            return C::kConnectionFailed;
        case DaemonErrorCode::kInternalError:
            return C::kInternalError;
        // ---- Operation ----
        case DaemonErrorCode::kUnsupportedOperation:
            return C::kUnsupportedOperation;
        case DaemonErrorCode::kInvalidOperation:
            return C::kInvalidOperation;
        case DaemonErrorCode::kOperationFailed:
            return C::kOperationFailed;
        case DaemonErrorCode::kOperationTimedOut:
            return C::kOperationTimedOut;
        // ---- Parameter ----
        case DaemonErrorCode::kInvalidArgument:
            return C::kInvalidArgument;
        case DaemonErrorCode::kInvalidResourceId:
            return C::kInvalidResourceId;
        case DaemonErrorCode::kInvalidResourceType:
            return C::kInvalidResourceType;
        case DaemonErrorCode::kInsufficientBufferSize:
            return C::kInsufficientBufferSize;
        case DaemonErrorCode::kInvalidFormat:
            return C::kInvalidFormat;
        case DaemonErrorCode::kParamTruncated:
            return C::kParamTruncated;
        // ---- Streaming ----
        case DaemonErrorCode::kStreamNotInitialized:
            return C::kStreamNotInitialized;
        case DaemonErrorCode::kStreamAlreadyActive:
            return C::kStreamAlreadyActive;
        case DaemonErrorCode::kStreamIncomplete:
            return C::kStreamIncomplete;
        // ---- Algorithm ----
        case DaemonErrorCode::kUnsupportedAlgorithm:
            return C::kUnsupportedAlgorithm;
        case DaemonErrorCode::kAlgorithmMismatch:
            return C::kAlgorithmMismatch;
        // ---- Memory / resource ----
        case DaemonErrorCode::kAllocationFailed:
            return C::kAllocationFailed;
        case DaemonErrorCode::kQuotaExceeded:
            return C::kQuotaExceeded;
        case DaemonErrorCode::kInvalidMemoryRegion:
            return C::kInvalidMemoryRegion;
        // ---- Context ----
        case DaemonErrorCode::kContextCreationFailed:
            return C::kContextCreationFailed;
        case DaemonErrorCode::kContextAlreadyDestroyed:
            return C::kContextAlreadyDestroyed;
        case DaemonErrorCode::kContextResetFailed:
            return C::kContextResetFailed;
        case DaemonErrorCode::kSessionExpired:
            return C::kSessionExpired;
        // ---- Key management ----
        case DaemonErrorCode::kKeySlotEmpty:
            return C::kKeySlotEmpty;
        case DaemonErrorCode::kKeySlotOccupied:
            return C::kKeySlotOccupied;
        case DaemonErrorCode::kKeyNotExportable:
            return C::kKeyNotExportable;
        case DaemonErrorCode::kKeyGenerationFailed:
            return C::kKeyGenerationFailed;
        case DaemonErrorCode::kKeyDerivationFailed:
            return C::kKeyDerivationFailed;
        case DaemonErrorCode::kKeyAgreementFailed:
            return C::kKeyAgreementFailed;
        case DaemonErrorCode::kWrapUnwrapFailed:
            return C::kWrapUnwrapFailed;
        case DaemonErrorCode::kPersistFailed:
            return C::kPersistFailed;
        case DaemonErrorCode::kIncompatibleKeyType:
            return C::kIncompatibleKeyType;
        case DaemonErrorCode::kKeyOperationNotPermitted:
            return C::kKeyOperationNotPermitted;
        // ---- Certificate ----
        case DaemonErrorCode::kCertificateParsingFailed:
            return C::kCertificateParsingFailed;
        case DaemonErrorCode::kCertificateExpired:
            return C::kCertificateExpired;
        case DaemonErrorCode::kCertificateRevoked:
            return C::kCertificateRevoked;
        case DaemonErrorCode::kCertificateVerifyFailed:
            return C::kCertificateVerifyFailed;
        case DaemonErrorCode::kCertChainVerifyFailed:
            return C::kCertChainVerifyFailed;
        case DaemonErrorCode::kCrlImportFailed:
            return C::kCrlImportFailed;
        case DaemonErrorCode::kCsrGenerationFailed:
            return C::kCsrGenerationFailed;
        case DaemonErrorCode::kOcspError:
            return C::kOcspError;
        case DaemonErrorCode::kTrustAnchorNotFound:
            return C::kTrustAnchorNotFound;
        // ---- Provider ----
        case DaemonErrorCode::kProviderNotAvailable:
            return C::kProviderNotAvailable;
        case DaemonErrorCode::kProviderBusy:
            return C::kProviderBusy;
        case DaemonErrorCode::kCrossProviderIncompatible:
            return C::kCrossProviderIncompatible;
        // ---- Access control ----
        case DaemonErrorCode::kAccessDenied:
            return C::kAccessDenied;
        case DaemonErrorCode::kResourceNotAllocated:
            return C::kResourceNotAllocated;
        // ---- Daemon-internal (translated to broader public codes) ----
        case DaemonErrorCode::kInvalidState:
            return C::kInvalidOperation;
        case DaemonErrorCode::kOperationInProgress:
            return C::kInvalidOperation;
        case DaemonErrorCode::kInvalidContext:
            return C::kInvalidOperation;
        case DaemonErrorCode::kInsufficientParameters:
            return C::kInvalidArgument;
        case DaemonErrorCode::kInvalidDataType:
            return C::kInvalidArgument;
        case DaemonErrorCode::kInvalidStreamOperation:
            return C::kInvalidOperation;
        case DaemonErrorCode::kAlgorithmInitializationFailed:
            return C::kOperationFailed;
        case DaemonErrorCode::kAlgorithmExecutionFailed:
            return C::kOperationFailed;
        case DaemonErrorCode::kResourceBusy:
            return C::kOperationFailed;
        case DaemonErrorCode::kContextCleanupFailed:
            return C::kOperationFailed;
        case DaemonErrorCode::kSessionInvalid:
            return C::kSessionExpired;
        case DaemonErrorCode::kUnknown:
            return C::kInternalError;
    }
    return C::kInternalError;
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_DAEMON_COMMON_DAEMON_ERROR_HPP
