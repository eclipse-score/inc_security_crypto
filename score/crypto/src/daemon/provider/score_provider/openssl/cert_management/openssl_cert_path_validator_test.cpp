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

#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_path_validator.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace
{
using score::crypto::CertVerifyResult;
using score::crypto::FormatType;
using score::crypto::RevocationCheckPolicy;
using score::crypto::RevocationCoveragePolicy;
using score::crypto::daemon::cert_management::CertObject;
using score::crypto::daemon::cert_management::CrlData;
using score::crypto::daemon::common::DaemonErrorCode;
using score::crypto::daemon::common::ProviderId;
using score::crypto::daemon::provider::cert_management::PathValidationRequest;
using score::crypto::daemon::provider::score_provider::openssl::OpenSslCertParser;
using score::crypto::daemon::provider::score_provider::openssl::OpenSslCertPathValidator;

// Slack added to the latest notBefore so the verification time lies inside both certificates' validity windows.
constexpr std::int64_t kSlackSeconds{60};

// Reads a PEM vector from the certificate test vectors and parses it. Returns nullptr if parsing fails.
std::shared_ptr<CertObject> ParseVector(OpenSslCertParser& parser, const std::string& relative_path)
{
    std::ifstream input{"score/tests/test_vectors/certificate/" + relative_path};
    const std::string pem(std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{});
    const auto result =
        parser.ParseCertificate(reinterpret_cast<const std::uint8_t*>(pem.data()), pem.size(), FormatType::kPem);
    if (!result.has_value())
        return nullptr;
    return *result;
}

// Reads a binary vector (for example a DER CRL) from the certificate test vectors.
std::vector<std::uint8_t> ReadVectorBytes(const std::string& relative_path)
{
    std::ifstream input{"score/tests/test_vectors/certificate/" + relative_path, std::ios::binary};
    const std::string content(std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{});
    return std::vector<std::uint8_t>(content.begin(), content.end());
}

// Wraps DER CRL bytes as the request's CRL input.
std::shared_ptr<const CrlData> MakeDerCrl(std::vector<std::uint8_t> bytes)
{
    auto crl = std::make_shared<CrlData>();
    crl->bytes = std::move(bytes);
    crl->format = FormatType::kDer;
    return crl;
}

struct BasicPair
{
    std::shared_ptr<CertObject> leaf;
    std::shared_ptr<CertObject> root;
};

BasicPair LoadBasicPair(OpenSslCertParser& parser)
{
    return {ParseVector(parser, "basic/certificate_leaf.pem"), ParseVector(parser, "basic/certificate.pem")};
}

// Request for the basic leaf and root, with the verification time inside both validity windows.
PathValidationRequest BasicRequest(const BasicPair& pair)
{
    PathValidationRequest request;
    request.leaf = pair.leaf;
    request.trust_anchors = {pair.root};
    request.verification_time_epoch_s = std::max(pair.leaf->GetNotBefore(), pair.root->GetNotBefore()) + kSlackSeconds;
    return request;
}

}  // namespace

TEST(OpenSslCertPathValidatorTest, ValidBasicChainValidatesToValid)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto leaf = ParseVector(parser, "basic/certificate_leaf.pem");
    const auto root = ParseVector(parser, "basic/certificate.pem");
    ASSERT_NE(leaf, nullptr);
    ASSERT_NE(root, nullptr);

    PathValidationRequest request;
    request.leaf = leaf;
    request.trust_anchors = {root};
    // Pinned so the verdict does not depend on the wall clock.
    request.verification_time_epoch_s = std::max(leaf->GetNotBefore(), root->GetNotBefore()) + kSlackSeconds;

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->result, CertVerifyResult::kValid);
    ASSERT_EQ(outcome->chain.size(), 2U);
    EXPECT_EQ(outcome->chain[0], leaf);
    EXPECT_EQ(outcome->chain[1], root);
    EXPECT_TRUE(outcome->selected_crl_metadata.empty());
}

TEST(OpenSslCertPathValidatorTest, NullLeafIsAnInvalidArgument)
{
    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(PathValidationRequest{});

    ASSERT_FALSE(outcome.has_value());
    EXPECT_EQ(outcome.error(), DaemonErrorCode::kInvalidArgument);
}

TEST(OpenSslCertPathValidatorTest, NoTrustAnchorsGivesNoRootFound)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);

    PathValidationRequest request = BasicRequest(pair);
    request.trust_anchors.clear();

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->result, CertVerifyResult::kNoRootFound);
    EXPECT_TRUE(outcome->chain.empty());
}

// A null anchor is counted as skipped. A verdict that does not depend on it is still reported.
TEST(OpenSslCertPathValidatorTest, SkippedNullAnchorDoesNotWithholdValidVerdict)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);
    ASSERT_NE(pair.root, nullptr);

    PathValidationRequest request = BasicRequest(pair);
    request.trust_anchors = {nullptr, pair.root};

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->result, CertVerifyResult::kValid);
    ASSERT_EQ(outcome->chain.size(), 2U);
}

// With only a null anchor the leaf has no issuer in the store. That verdict depends on the skipped input, so it
// is withheld as a parsing failure rather than reported as an incomplete chain.
TEST(OpenSslCertPathValidatorTest, SkippedAnchorWithholdsInputDependentVerdict)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);

    PathValidationRequest request = BasicRequest(pair);
    request.trust_anchors = {nullptr};

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_FALSE(outcome.has_value());
    EXPECT_EQ(outcome.error(), DaemonErrorCode::kCertificateParsingFailed);
}

// Both certificates are expired at this time, so the verdict is kExpired whichever one OpenSSL reports first.
TEST(OpenSslCertPathValidatorTest, DefiniteVerdictIsReportedDespiteSkippedAnchor)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);
    ASSERT_NE(pair.root, nullptr);

    PathValidationRequest request = BasicRequest(pair);
    request.trust_anchors = {nullptr, pair.root};
    request.verification_time_epoch_s = pair.leaf->GetNotAfter() + 1;

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->result, CertVerifyResult::kExpired);
    EXPECT_TRUE(outcome->chain.empty());
}

TEST(OpenSslCertPathValidatorTest, RevokedLeafIsReportedAsRevokedWithCrlSelected)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);
    ASSERT_NE(pair.root, nullptr);

    PathValidationRequest request = BasicRequest(pair);
    request.revocation_check = RevocationCheckPolicy::kCrlOnly;
    request.revocation_coverage = RevocationCoveragePolicy::kFailClosed;
    request.crls = {MakeDerCrl(ReadVectorBytes("basic/certificate.crl.der"))};

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->result, CertVerifyResult::kRevoked);
    EXPECT_TRUE(outcome->chain.empty());
    EXPECT_EQ(outcome->selected_crl_metadata.size(), 1U);
}

TEST(OpenSslCertPathValidatorTest, RevocationIsNotClearedUnderBestEffort)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);
    ASSERT_NE(pair.root, nullptr);

    PathValidationRequest request = BasicRequest(pair);
    request.revocation_check = RevocationCheckPolicy::kCrlOnly;
    request.revocation_coverage = RevocationCoveragePolicy::kBestEffort;
    request.crls = {MakeDerCrl(ReadVectorBytes("basic/certificate.crl.der"))};

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->result, CertVerifyResult::kRevoked);
}

// The last DER byte lies in the CRL signature. The CRL still parses, but its signature no longer verifies, so
// selection skips it and the leaf has no CRL evidence.
TEST(OpenSslCertPathValidatorTest, TamperedCrlIsNotAppliedAndFailsClosed)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);
    ASSERT_NE(pair.root, nullptr);

    std::vector<std::uint8_t> bytes = ReadVectorBytes("basic/certificate.crl.der");
    ASSERT_FALSE(bytes.empty());
    bytes.back() = static_cast<std::uint8_t>(bytes.back() ^ 0x01U);

    PathValidationRequest request = BasicRequest(pair);
    request.revocation_check = RevocationCheckPolicy::kCrlOnly;
    request.revocation_coverage = RevocationCoveragePolicy::kFailClosed;
    request.crls = {MakeDerCrl(std::move(bytes))};

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->result, CertVerifyResult::kRevocationStatusUnavailable);
    EXPECT_TRUE(outcome->selected_crl_metadata.empty());
}

TEST(OpenSslCertPathValidatorTest, TamperedCrlIsIgnoredUnderBestEffort)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);
    ASSERT_NE(pair.root, nullptr);

    std::vector<std::uint8_t> bytes = ReadVectorBytes("basic/certificate.crl.der");
    ASSERT_FALSE(bytes.empty());
    bytes.back() = static_cast<std::uint8_t>(bytes.back() ^ 0x01U);

    PathValidationRequest request = BasicRequest(pair);
    request.revocation_check = RevocationCheckPolicy::kCrlOnly;
    request.revocation_coverage = RevocationCoveragePolicy::kBestEffort;
    request.crls = {MakeDerCrl(std::move(bytes))};

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->result, CertVerifyResult::kValid);
    EXPECT_EQ(outcome->chain.size(), 2U);
    EXPECT_TRUE(outcome->selected_crl_metadata.empty());
}

TEST(OpenSslCertPathValidatorTest, OcspPoliciesAreUnsupported)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);
    ASSERT_NE(pair.root, nullptr);

    OpenSslCertPathValidator validator;
    for (const auto policy : {RevocationCheckPolicy::kOcspOnly, RevocationCheckPolicy::kOcspWithCrlFallback})
    {
        PathValidationRequest request = BasicRequest(pair);
        request.revocation_check = policy;

        const auto outcome = validator.Validate(request);
        ASSERT_FALSE(outcome.has_value());
        EXPECT_EQ(outcome.error(), DaemonErrorCode::kUnsupportedOperation);
    }
}

// No CRL means the leaf's revocation status is unknown, which fail-closed reports as unavailable.
TEST(OpenSslCertPathValidatorTest, MissingCrlIsUnavailableUnderFailClosed)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);
    ASSERT_NE(pair.root, nullptr);

    PathValidationRequest request = BasicRequest(pair);
    request.revocation_check = RevocationCheckPolicy::kCrlOnly;
    request.revocation_coverage = RevocationCoveragePolicy::kFailClosed;

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->result, CertVerifyResult::kRevocationStatusUnavailable);
    EXPECT_TRUE(outcome->selected_crl_metadata.empty());
}

TEST(OpenSslCertPathValidatorTest, MissingCrlIsIgnoredUnderBestEffort)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);
    ASSERT_NE(pair.root, nullptr);

    PathValidationRequest request = BasicRequest(pair);
    request.revocation_check = RevocationCheckPolicy::kCrlOnly;
    request.revocation_coverage = RevocationCoveragePolicy::kBestEffort;

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->result, CertVerifyResult::kValid);
    EXPECT_EQ(outcome->chain.size(), 2U);
    EXPECT_TRUE(outcome->selected_crl_metadata.empty());
}

// With the leaf as the only anchor, its issuer is absent from the store, so the chain is incomplete.
TEST(OpenSslCertPathValidatorTest, LeafAsOnlyAnchorGivesChainIncomplete)
{
    OpenSslCertParser parser{ProviderId{1U}};
    const auto pair = LoadBasicPair(parser);
    ASSERT_NE(pair.leaf, nullptr);

    PathValidationRequest request = BasicRequest(pair);
    request.trust_anchors = {pair.leaf};

    OpenSslCertPathValidator validator;
    const auto outcome = validator.Validate(request);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->result, CertVerifyResult::kChainIncomplete);
    EXPECT_TRUE(outcome->chain.empty());
}
