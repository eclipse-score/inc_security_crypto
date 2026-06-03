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

#ifndef SCORE_MW_CRYPTO_API_COMMON_ERROR_DOMAIN_HPP
#define SCORE_MW_CRYPTO_API_COMMON_ERROR_DOMAIN_HPP

#include "score/result/result.h"

#include <string_view>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Error codes for the crypto stack, organized by category.
///
/// Hex categories follow the pattern 0x01CCxxxx where CC is the category:
///   01 = General / initialization errors
///   02 = Operation errors
///   03 = Parameter / validation errors
///   04 = Streaming errors
///   05 = Algorithm errors
///   06 = Memory / resource errors
///   07 = Context errors
///   08 = Key management errors
///   09 = Certificate errors
///   0A = Provider errors
///   0B = Access control errors
enum class CryptoErrorCode : score::result::ErrorCode
{
    // ---- General / initialization errors (0x01010000) ----
    kUninitializedStack = 0x01010001,  ///< Stack not initialized
    kAlreadyInitialized = 0x01010002,  ///< Stack already initialized
    kConnectionFailed = 0x01010003,    ///< Failed to connect to daemon
    kInternalError = 0x01010004,       ///< Unspecified internal error

    // ---- Operation errors (0x01020000) ----
    kUnsupportedOperation = 0x01020001,  ///< Operation not supported by provider
    kInvalidOperation = 0x01020002,      ///< Operation not valid in current state
    kOperationFailed = 0x01020003,       ///< Operation execution failed
    kOperationTimedOut = 0x01020004,     ///< Operation exceeded configured timeout deadline

    // ---- Parameter / validation errors (0x01030000) ----
    kInvalidArgument = 0x01030001,         ///< Invalid argument provided
    kResourceNotFound = 0x01030002,        ///< Requested resource not found
    kInvalidResourceId = 0x01030003,       ///< Resource ID does not resolve to a valid resource
    kInvalidResourceType = 0x01030004,     ///< Resource type mismatch
    kInsufficientBufferSize = 0x01030005,  ///< Output buffer too small
    kInvalidFormat = 0x01030006,           ///< Data format not recognized (DER/PEM)
    kParamTruncated = 0x01030007,          ///< Input parameter exceeded fixed-capacity storage and was
                                           ///< silently truncated (e.g. KDF salt or seed too long)

    // ---- Streaming errors (0x01040000) ----
    kStreamNotInitialized = 0x01040001,  ///< Init() not called before Update()/Finalize()
    kStreamAlreadyActive = 0x01040002,   ///< Init() called while stream is active
    kStreamIncomplete = 0x01040003,      ///< Finalize() called without sufficient data

    // ---- Algorithm errors (0x01050000) ----
    kUnsupportedAlgorithm = 0x01050001,  ///< Algorithm not supported by any configured provider
    kAlgorithmMismatch = 0x01050002,     ///< Algorithm incompatible with key/slot

    // ---- Memory / resource errors (0x01060000) ----
    kAllocationFailed = 0x01060001,     ///< Shared memory allocation failed
    kQuotaExceeded = 0x01060002,        ///< Per-application memory quota exceeded
    kInvalidMemoryRegion = 0x01060003,  ///< Memory region is invalid or already released

    // ---- Context errors (0x01070000) ----
    kContextCreationFailed = 0x01070001,    ///< Failed to create operation context
    kContextAlreadyDestroyed = 0x01070002,  ///< Context used after destruction
    kContextResetFailed = 0x01070003,       ///< Failed to reset context to initial state
    kSessionExpired = 0x01070004,           ///< Guard's session sentinel expired (context destroyed);
                                            ///< logged for diagnostics, daemon bulk-cleans via EndSession

    // ---- Key management errors (0x01080000) ----
    kKeySlotEmpty = 0x01080001,              ///< Key slot contains no key material
    kKeySlotOccupied = 0x01080002,           ///< Key slot already occupied (for persist/import)
    kKeyNotExportable = 0x01080003,          ///< Key cannot be exported from its provider
    kKeyGenerationFailed = 0x01080004,       ///< Key generation failed
    kKeyDerivationFailed = 0x01080005,       ///< Key derivation failed
    kKeyAgreementFailed = 0x01080006,        ///< Key agreement failed
    kWrapUnwrapFailed = 0x01080007,          ///< Key wrap/unwrap operation failed
    kPersistFailed = 0x01080008,             ///< Failed to persist ephemeral key
    kIncompatibleKeyType = 0x01080009,       ///< Key type incompatible with requested operation
    kKeyOperationNotPermitted = 0x0108000A,  ///< Key's permitted operations do not include the
                                             ///< requested operation (e.g., encrypt-only key
                                             ///< used for signing)

    // ---- Certificate errors (0x01090000) ----
    kCertificateParsingFailed = 0x01090001,  ///< Certificate data could not be parsed
    kCertificateExpired = 0x01090002,        ///< Certificate has expired
    kCertificateRevoked = 0x01090003,        ///< Certificate has been revoked
    kCertificateVerifyFailed = 0x01090004,   ///< Certificate verification failed
    kCertChainVerifyFailed = 0x01090005,     ///< Certificate chain verification failed
    kCrlImportFailed = 0x01090006,           ///< CRL import failed
    kCsrGenerationFailed = 0x01090007,       ///< CSR generation failed
    kOcspError = 0x01090008,                 ///< OCSP request/response error
    kTrustAnchorNotFound = 0x01090009,       ///< Trust anchor resource not found or empty

    // ---- Provider errors (0x010A0000) ----
    kProviderNotAvailable = 0x010A0001,       ///< Requested provider is not available
    kProviderBusy = 0x010A0002,               ///< Provider is temporarily busy
    kCrossProviderIncompatible = 0x010A0003,  ///< Resource cannot be used with the target provider

    // ---- Access control errors (0x010B0000) ----
    kAccessDenied = 0x010B0001,          ///< Application not authorized for this resource
    kResourceNotAllocated = 0x010B0002,  ///< Resource not allocated to this application
};

/// @brief Error domain for the crypto stack.
///
/// Follows the score::result::ErrorDomain pattern. A single constexpr instance
/// is used throughout the crypto API.
class CryptoErrorDomain final : public score::result::ErrorDomain
{
  public:
    /// @brief Returns a human-readable message for the given error code.
    std::string_view MessageFor(const score::result::ErrorCode& code) const noexcept override;
};

/// @brief Global constexpr instance of the crypto error domain.
constexpr CryptoErrorDomain kCryptoErrorDomain{};

/// @brief Creates an Error from a CryptoErrorCode and optional user message.
/// @param code The crypto error code
/// @param user_message Optional additional context for the error
/// @return A score::result::Error bound to the crypto error domain
///
/// Inline definition to support ADL in result.h templates
inline score::result::Error MakeError(CryptoErrorCode code, std::string_view user_message = "") noexcept
{
    return {static_cast<score::result::ErrorCode>(code), kCryptoErrorDomain, user_message};
}

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_COMMON_ERROR_DOMAIN_HPP
