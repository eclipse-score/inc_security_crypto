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

#include <gtest/gtest.h>

namespace
{

using score::crypto::CertVerifyResult;
using score::crypto::daemon::common::DaemonErrorCode;
using score::crypto::daemon::provider::openssl::detail::MapX509Error;
using score::crypto::daemon::provider::openssl::detail::MapX509OperationError;

std::uint8_t ToCode(CertVerifyResult result)
{
    return static_cast<std::uint8_t>(result);
}

}  // namespace

TEST(OpenSslVerifyResultMappingTest, VerificationDecisionsMapToCertVerifyResult)
{
    EXPECT_EQ(MapX509Error(X509_V_ERR_CERT_HAS_EXPIRED), ToCode(CertVerifyResult::kExpired));
    EXPECT_EQ(MapX509Error(X509_V_ERR_CERT_REVOKED), ToCode(CertVerifyResult::kRevoked));
    EXPECT_EQ(MapX509Error(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY), ToCode(CertVerifyResult::kChainIncomplete));
    EXPECT_EQ(MapX509Error(X509_V_ERR_CERT_SIGNATURE_FAILURE), ToCode(CertVerifyResult::kSignatureInvalid));
    EXPECT_EQ(MapX509Error(X509_V_ERR_UNABLE_TO_GET_CRL), ToCode(CertVerifyResult::kRevocationStatusUnavailable));
}

TEST(OpenSslVerifyResultMappingTest, NonOutcomeErrorsHaveNoVerifyResult)
{
    EXPECT_FALSE(MapX509Error(X509_V_ERR_OUT_OF_MEM).has_value());
    EXPECT_FALSE(MapX509Error(X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION).has_value());
    EXPECT_FALSE(MapX509Error(X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD).has_value());
}

TEST(OpenSslVerifyResultMappingTest, AllocationFailureMapsToAllocationFailed)
{
    EXPECT_EQ(MapX509OperationError(X509_V_ERR_OUT_OF_MEM), DaemonErrorCode::kAllocationFailed);
}

TEST(OpenSslVerifyResultMappingTest, MalformedCertificateFieldsMapToParsingFailed)
{
    EXPECT_EQ(MapX509OperationError(X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY),
              DaemonErrorCode::kCertificateParsingFailed);
    EXPECT_EQ(MapX509OperationError(X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD),
              DaemonErrorCode::kCertificateParsingFailed);
    EXPECT_EQ(MapX509OperationError(X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD),
              DaemonErrorCode::kCertificateParsingFailed);
}

TEST(OpenSslVerifyResultMappingTest, UnsupportedFeaturesMapToUnsupportedOperation)
{
    EXPECT_EQ(MapX509OperationError(X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION), DaemonErrorCode::kUnsupportedOperation);
    EXPECT_EQ(MapX509OperationError(X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE), DaemonErrorCode::kUnsupportedOperation);
    EXPECT_EQ(MapX509OperationError(X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE), DaemonErrorCode::kUnsupportedOperation);
    EXPECT_EQ(MapX509OperationError(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX), DaemonErrorCode::kUnsupportedOperation);
}

TEST(OpenSslVerifyResultMappingTest, UnknownErrorFallsBackToOperationFailed)
{
    constexpr int kUnmappedCode = 0x7FFF;
    EXPECT_FALSE(MapX509Error(kUnmappedCode).has_value());
    EXPECT_EQ(MapX509OperationError(kUnmappedCode), DaemonErrorCode::kOperationFailed);
}
