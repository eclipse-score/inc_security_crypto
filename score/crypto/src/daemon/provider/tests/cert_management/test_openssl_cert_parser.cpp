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

#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace
{
using score::crypto::FormatType;
using score::crypto::daemon::common::ProviderId;
using score::crypto::daemon::provider::score_provider::openssl::OpenSslCertParser;

std::string ReadCertificateVector()
{
    std::ifstream input{"score/tests/test_vectors/certificate/certificate.pem"};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

TEST(OpenSslCertParserTest, ParsesPemCertificateAndExtractsMetadata)
{
    const auto pem = ReadCertificateVector();
    ASSERT_FALSE(pem.empty());
    OpenSslCertParser parser{ProviderId{1U}};
    const auto result =
        parser.ParseCertificate(reinterpret_cast<const std::uint8_t*>(pem.data()), pem.size(), FormatType::kPem);

    ASSERT_TRUE(result.has_value());
    ASSERT_NE(*result, nullptr);
    EXPECT_EQ((*result)->GetFormat(), FormatType::kPem);
    EXPECT_EQ((*result)->GetSubject(), "CN=cert-management-test,O=Eclipse");
    EXPECT_EQ((*result)->GetIssuer(), "CN=cert-management-test,O=Eclipse");
    EXPECT_TRUE((*result)->IsCA());
    EXPECT_EQ((*result)->GetSkid().size(), 20U);
    EXPECT_EQ((*result)->GetFingerprint().size(), 32U);
    EXPECT_EQ((*result)->GetRawBytes().size(), pem.size());
}

TEST(OpenSslCertParserTest, ParsesPemBundleIntoSeparateCertificateObjects)
{
    const auto pem = ReadCertificateVector();
    ASSERT_FALSE(pem.empty());
    const auto bundle = pem + pem;
    OpenSslCertParser parser{ProviderId{1U}};
    const auto result =
        parser.ParseCertificates(reinterpret_cast<const std::uint8_t*>(bundle.data()), bundle.size(), FormatType::kPem);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 2U);
    EXPECT_EQ((*result)[0]->GetFormat(), FormatType::kDer);
    EXPECT_EQ((*result)[1]->GetFormat(), FormatType::kDer);
    EXPECT_TRUE(std::equal((*result)[0]->GetFingerprint().begin(),
                           (*result)[0]->GetFingerprint().end(),
                           (*result)[1]->GetFingerprint().begin(),
                           (*result)[1]->GetFingerprint().end()));
}

TEST(OpenSslCertParserTest, RejectsMalformedCertificate)
{
    constexpr std::string malformed{"not a certificate"};
    OpenSslCertParser parser{ProviderId{1U}};
    const auto result = parser.ParseCertificate(
        reinterpret_cast<const std::uint8_t*>(malformed.data()), malformed.size(), FormatType::kPem);

    EXPECT_FALSE(result.has_value());
}
}  // namespace
