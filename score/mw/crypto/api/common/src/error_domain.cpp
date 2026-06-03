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

#include "score/mw/crypto/api/common/error_domain.hpp"

namespace score
{
namespace mw
{
namespace crypto
{

std::string_view CryptoErrorDomain::MessageFor(const score::result::ErrorCode& code) const noexcept
{
    const auto crypto_code = static_cast<CryptoErrorCode>(code);
    switch (crypto_code)
    {
        // General / initialization
        case CryptoErrorCode::kUninitializedStack:
            return "Crypto stack not initialized";
        case CryptoErrorCode::kAlreadyInitialized:
            return "Crypto stack already initialized";
        case CryptoErrorCode::kConnectionFailed:
            return "Failed to connect to crypto daemon";
        case CryptoErrorCode::kInternalError:
            return "Internal error";

        // Operation
        case CryptoErrorCode::kUnsupportedOperation:
            return "Unsupported operation";
        case CryptoErrorCode::kInvalidOperation:
            return "Invalid operation in current state";
        case CryptoErrorCode::kOperationFailed:
            return "Operation failed";
        case CryptoErrorCode::kOperationTimedOut:
            return "Operation exceeded configured timeout deadline";

        // Parameter / validation
        case CryptoErrorCode::kInvalidArgument:
            return "Invalid argument";
        case CryptoErrorCode::kInvalidResourceId:
            return "Invalid resource identifier";
        case CryptoErrorCode::kInvalidResourceType:
            return "Resource type mismatch";
        case CryptoErrorCode::kInsufficientBufferSize:
            return "Output buffer too small";
        case CryptoErrorCode::kInvalidFormat:
            return "Invalid data format";
        case CryptoErrorCode::kParamTruncated:
            return "Parameter truncated: input exceeds fixed-capacity storage (reduce salt or seed size)";

        // Streaming
        case CryptoErrorCode::kStreamNotInitialized:
            return "Stream not initialized";
        case CryptoErrorCode::kStreamAlreadyActive:
            return "Stream already active";
        case CryptoErrorCode::kStreamIncomplete:
            return "Stream incomplete";

        // Algorithm
        case CryptoErrorCode::kUnsupportedAlgorithm:
            return "Unsupported algorithm";
        case CryptoErrorCode::kAlgorithmMismatch:
            return "Algorithm mismatch with key or slot";

        // Memory / resource
        case CryptoErrorCode::kAllocationFailed:
            return "Memory allocation failed";
        case CryptoErrorCode::kQuotaExceeded:
            return "Memory quota exceeded";
        case CryptoErrorCode::kInvalidMemoryRegion:
            return "Invalid memory region";

        // Context
        case CryptoErrorCode::kContextCreationFailed:
            return "Context creation failed";
        case CryptoErrorCode::kContextAlreadyDestroyed:
            return "Context already destroyed";
        case CryptoErrorCode::kContextResetFailed:
            return "Context reset failed";
        case CryptoErrorCode::kSessionExpired:
            return "Session expired (context destroyed)";

        // Key management
        case CryptoErrorCode::kKeySlotEmpty:
            return "Key slot is empty";
        case CryptoErrorCode::kKeySlotOccupied:
            return "Key slot is already occupied";
        case CryptoErrorCode::kKeyNotExportable:
            return "Key is not exportable";
        case CryptoErrorCode::kKeyGenerationFailed:
            return "Key generation failed";
        case CryptoErrorCode::kKeyDerivationFailed:
            return "Key derivation failed";
        case CryptoErrorCode::kKeyAgreementFailed:
            return "Key agreement failed";
        case CryptoErrorCode::kWrapUnwrapFailed:
            return "Key wrap/unwrap failed";
        case CryptoErrorCode::kPersistFailed:
            return "Key persist failed";
        case CryptoErrorCode::kIncompatibleKeyType:
            return "Incompatible key type";
        case CryptoErrorCode::kKeyOperationNotPermitted:
            return "Key operation not permitted by slot policy";

        // Certificate
        case CryptoErrorCode::kCertificateParsingFailed:
            return "Certificate parsing failed";
        case CryptoErrorCode::kCertificateExpired:
            return "Certificate expired";
        case CryptoErrorCode::kCertificateRevoked:
            return "Certificate revoked";
        case CryptoErrorCode::kCertificateVerifyFailed:
            return "Certificate verification failed";
        case CryptoErrorCode::kCertChainVerifyFailed:
            return "Certificate chain verification failed";
        case CryptoErrorCode::kCrlImportFailed:
            return "CRL import failed";
        case CryptoErrorCode::kCsrGenerationFailed:
            return "CSR generation failed";
        case CryptoErrorCode::kOcspError:
            return "OCSP error";
        case CryptoErrorCode::kTrustAnchorNotFound:
            return "Trust anchor not found";

        // Provider
        case CryptoErrorCode::kProviderNotAvailable:
            return "Provider not available";
        case CryptoErrorCode::kProviderBusy:
            return "Provider busy";
        case CryptoErrorCode::kCrossProviderIncompatible:
            return "Cross-provider incompatible";

        // Access control
        case CryptoErrorCode::kAccessDenied:
            return "Access denied";
        case CryptoErrorCode::kResourceNotAllocated:
            return "Resource not allocated to application";

        default:
            return "Unrecognized crypto error code";
    }
}

}  // namespace crypto
}  // namespace mw
}  // namespace score
