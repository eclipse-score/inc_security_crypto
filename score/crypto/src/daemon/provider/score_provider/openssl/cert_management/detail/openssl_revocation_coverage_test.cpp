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

#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/detail/openssl_revocation_coverage.hpp"

#include <openssl/x509.h>

#include <gtest/gtest.h>

#include <memory>

TEST(OpenSslRevocationCoverageTest, CrlSignatureFailureIsNotClearedUnderBestEffort)
{
    using score::crypto::daemon::provider::openssl::detail::RevocationCoverageState;
    using score::crypto::daemon::provider::openssl::detail::VerifyCrlCoverageCallback;

    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx{X509_STORE_CTX_new(), &X509_STORE_CTX_free};
    ASSERT_NE(ctx.get(), nullptr);
    RevocationCoverageState state{true};
    X509_STORE_CTX_set_app_data(ctx.get(), &state);

    // A CRL whose signature does not verify is evidence of a problem, so the failure stays.
    X509_STORE_CTX_set_error(ctx.get(), X509_V_ERR_CRL_SIGNATURE_FAILURE);
    EXPECT_EQ(VerifyCrlCoverageCallback(0, ctx.get()), 0);
    EXPECT_EQ(X509_STORE_CTX_get_error(ctx.get()), X509_V_ERR_CRL_SIGNATURE_FAILURE);

    // Missing CRL evidence is still cleared under best-effort (control case).
    X509_STORE_CTX_set_error(ctx.get(), X509_V_ERR_UNABLE_TO_GET_CRL);
    EXPECT_EQ(VerifyCrlCoverageCallback(0, ctx.get()), 1);
    EXPECT_EQ(X509_STORE_CTX_get_error(ctx.get()), X509_V_OK);
}
