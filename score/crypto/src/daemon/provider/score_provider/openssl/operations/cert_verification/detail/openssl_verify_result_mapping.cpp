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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/detail/openssl_verify_result_mapping.hpp"
#include "score/crypto/src/api/types/certificate.hpp"

#include <openssl/x509.h>

namespace score::crypto::daemon::provider::openssl::detail
{

std::optional<std::uint8_t> MapX509Error(int x509_err)
{
    using R = ::score::crypto::CertVerifyResult;
    switch (x509_err)
    {
        case X509_V_ERR_CERT_HAS_EXPIRED:
            return static_cast<uint8_t>(R::kExpired);
        case X509_V_ERR_CERT_NOT_YET_VALID:
            return static_cast<uint8_t>(R::kNotYetValid);
        case X509_V_ERR_CERT_REVOKED:
            return static_cast<uint8_t>(R::kRevoked);
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
            return static_cast<uint8_t>(R::kChainIncomplete);
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_CERT_UNTRUSTED:
            return static_cast<uint8_t>(R::kNoRootFound);
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            return static_cast<uint8_t>(R::kSignatureInvalid);
        case X509_V_ERR_INVALID_PURPOSE:
            return static_cast<uint8_t>(R::kInvalidPurpose);
        case X509_V_ERR_UNABLE_TO_GET_CRL:
        case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
        case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
        case X509_V_ERR_CRL_NOT_YET_VALID:
        case X509_V_ERR_CRL_HAS_EXPIRED:
            return static_cast<uint8_t>(R::kRevocationStatusUnavailable);
        default:
            return std::nullopt;
    }
}

common::DaemonErrorCode MapX509OperationError(int x509_err)
{
    using E = common::DaemonErrorCode;
    switch (x509_err)
    {
        case X509_V_ERR_OUT_OF_MEM:
            return E::kAllocationFailed;
        case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            return E::kCertificateParsingFailed;
        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
        case X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
        case X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
        case X509_V_ERR_UNSUPPORTED_NAME_SYNTAX:
            return E::kUnsupportedOperation;
        default:
            return E::kOperationFailed;
    }
}

}  // namespace score::crypto::daemon::provider::openssl::detail
