/*******************************************************************************
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
 *******************************************************************************/

#include "score/crypto/src/api/config/certificate_context_config.hpp"
#include "score/crypto/src/api/config/certificate_verification_context_config.hpp"
#include "score/crypto/src/api/contexts/i_certificate_management_context.hpp"
#include "score/crypto/src/api/contexts/i_certificate_verification_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/objects/i_trust_store_object.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

std::string DaemonEndpoint()
{
    const auto* endpoint = std::getenv("SCORE_CRYPTO_DAEMON_ENDPOINT");
#ifdef __QNXNTO__
    constexpr std::string_view default_endpoint = "unix:///opt/crypto_daemon.sock";
#else
    constexpr std::string_view default_endpoint = "unix:///tmp/crypto_daemon.sock";
#endif
    return endpoint == nullptr ? std::string{default_endpoint} : endpoint;
}

std::string VectorPath(std::string_view relative_path)
{
    const auto* root = std::getenv("TEST_VECTORS_DIR");
    std::string path = root == nullptr ? "/opt/crypto/share/test_vectors" : root;
    if (!path.empty() && path.back() != '/')
        path.push_back('/');
    path.append(relative_path);
    return path;
}

std::vector<std::uint8_t> ReadFile(const std::string& path)
{
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

class CertificateVerificationIntegrationTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        score::crypto::CryptoStackConfig stack_config;
        stack_config.SetConnectionEndpoint(DaemonEndpoint());
        auto stack_result = score::crypto::CreateCryptoStack(stack_config);
        ASSERT_TRUE(stack_result.has_value());
        m_stack = std::move(stack_result.value());

        auto context_result = m_stack->CreateCryptoContext();
        ASSERT_TRUE(context_result.has_value());
        m_context = std::move(context_result.value());

        score::crypto::CertificateContextConfig management_config;
        auto management_result = m_context->CreateCertificateManagementContext(management_config);
        ASSERT_TRUE(management_result.has_value());
        m_management = std::move(management_result.value());

        m_full_trust_store = ResolveTrustStore("verification_tls_roots");
        m_root_trust_store = ResolveTrustStore("verification_root_trust");
        m_intermediate_trust_store = ResolveTrustStore("verification_intermediate_roots");
    }

    score::crypto::CryptoResourceId ResolveTrustStore(const char* name)
    {
        auto result = m_context->ResolveResource(name, score::crypto::ResourceType::kCertificateTrustStore);
        EXPECT_TRUE(result.has_value());
        return result.has_value() ? result.value() : score::crypto::CryptoResourceId{};
    }

    std::optional<score::crypto::CryptoResourceGuard> ParseCertificate(std::string_view relative_path)
    {
        const auto bytes = ReadFile(VectorPath(relative_path));
        EXPECT_FALSE(bytes.empty());
        auto result = m_management->ParseCertificate(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()},
                                                     score::crypto::FormatType::kPem);
        EXPECT_TRUE(result.has_value());
        if (!result.has_value())
            return std::nullopt;
        return std::move(result.value());
    }

    score::crypto::ICertificateVerificationContext::Uptr CreateVerificationContext()
    {
        score::crypto::CertificateVerificationContextConfig config;
        auto result = m_context->CreateCertificateVerificationContext(config);
        EXPECT_TRUE(result.has_value());
        if (!result.has_value())
            return nullptr;
        return std::move(result.value());
    }

    score::crypto::ICryptoStack::Uptr m_stack;
    score::crypto::ICryptoContext::Uptr m_context;
    score::crypto::ICertificateManagementContext::Uptr m_management;
    score::crypto::CryptoResourceId m_full_trust_store{};
    score::crypto::CryptoResourceId m_root_trust_store{};
    score::crypto::CryptoResourceId m_intermediate_trust_store{};
};

TEST_F(CertificateVerificationIntegrationTest, VerifiesSelfSignedRootAgainstTrustStore)
{
    auto root = ParseCertificate("certificate/pki_chain/root_ca.pem");
    ASSERT_TRUE(root.has_value());

    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*root).has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_root_trust_store).has_value());
    ASSERT_TRUE(verification->SetEvidenceMode(score::crypto::VerificationEvidenceMode::kChain).has_value());

    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kValid);

    auto chain_length = verification->GetVerifiedChainCertificateCount();
    ASSERT_TRUE(chain_length.has_value());
    EXPECT_EQ(*chain_length, 1U);
}

TEST_F(CertificateVerificationIntegrationTest, BuildsLeafIntermediateRootChainFromMultipleAnchors)
{
    auto trust_store = m_context->GetTrustStoreObject(m_full_trust_store);
    ASSERT_TRUE(trust_store.has_value());
    ASSERT_EQ((*trust_store)->GetMembers().size(), 2U);

    const auto chain_bytes = ReadFile(VectorPath("certificate/pki_chain/leaf.chain.pem"));
    ASSERT_FALSE(chain_bytes.empty());
    auto parsed = m_management->ParseCertificates(
        score::cpp::span<const std::uint8_t>{chain_bytes.data(), chain_bytes.size()}, score::crypto::FormatType::kPem);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 3U);

    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    std::array<score::crypto::CryptoResourceId, 3U> chain_ids{(*parsed)[0].Id(), (*parsed)[1].Id(), (*parsed)[2].Id()};
    ASSERT_TRUE(verification
                    ->SetCertificateChain(
                        score::cpp::span<const score::crypto::CryptoResourceId>{chain_ids.data(), chain_ids.size()})
                    .has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_full_trust_store).has_value());
    ASSERT_TRUE(
        verification->SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy::kRootRequired).has_value());
    ASSERT_TRUE(verification->SetEvidenceMode(score::crypto::VerificationEvidenceMode::kChain).has_value());

    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kValid);

    auto chain_length = verification->GetVerifiedChainCertificateCount();
    ASSERT_TRUE(chain_length.has_value());
    ASSERT_EQ(*chain_length, 3U);
}

TEST_F(CertificateVerificationIntegrationTest, RetainsCertificateAfterInputGuardRelease)
{
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    ASSERT_TRUE(leaf.has_value());

    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_full_trust_store).has_value());
    ASSERT_TRUE(leaf->Release().has_value());

    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kValid);
}

TEST_F(CertificateVerificationIntegrationTest, ExportsVerifiedChainAndIndividualCertificate)
{
    const auto chain_bytes = ReadFile(VectorPath("certificate/pki_chain/leaf.chain.pem"));
    ASSERT_FALSE(chain_bytes.empty());
    auto parsed = m_management->ParseCertificates(
        score::cpp::span<const std::uint8_t>{chain_bytes.data(), chain_bytes.size()}, score::crypto::FormatType::kPem);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 3U);

    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    std::array<score::crypto::CryptoResourceId, 3U> chain_ids{(*parsed)[0].Id(), (*parsed)[1].Id(), (*parsed)[2].Id()};
    ASSERT_TRUE(verification
                    ->SetCertificateChain(
                        score::cpp::span<const score::crypto::CryptoResourceId>{chain_ids.data(), chain_ids.size()})
                    .has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_full_trust_store).has_value());
    ASSERT_TRUE(verification->SetEvidenceMode(score::crypto::VerificationEvidenceMode::kChain).has_value());
    for (auto& certificate : *parsed)
        ASSERT_TRUE(certificate.Release().has_value());
    ASSERT_TRUE(verification->Verify().has_value());

    auto pem_size = verification->GetVerifiedChainExportSize(score::crypto::FormatType::kPem);
    ASSERT_TRUE(pem_size.has_value());
    std::vector<std::uint8_t> exported_pem(*pem_size);
    ASSERT_EQ(
        *verification->ExportVerifiedChain(score::crypto::FormatType::kPem,
                                           score::cpp::span<std::uint8_t>{exported_pem.data(), exported_pem.size()}),
        *pem_size);

    auto reparsed =
        m_management->ParseCertificates(score::cpp::span<const std::uint8_t>{exported_pem.data(), exported_pem.size()},
                                        score::crypto::FormatType::kPem);
    ASSERT_TRUE(reparsed.has_value());
    ASSERT_EQ(reparsed->size(), 3U);

    auto der_size = verification->GetVerifiedCertificateExportSize(1U, score::crypto::FormatType::kDer);
    ASSERT_TRUE(der_size.has_value());
    std::vector<std::uint8_t> exported_der(*der_size);
    ASSERT_EQ(*verification->ExportVerifiedCertificate(
                  1U,
                  score::crypto::FormatType::kDer,
                  score::cpp::span<std::uint8_t>{exported_der.data(), exported_der.size()}),
              *der_size);
    auto single =
        m_management->ParseCertificate(score::cpp::span<const std::uint8_t>{exported_der.data(), exported_der.size()},
                                       score::crypto::FormatType::kDer);
    ASSERT_TRUE(single.has_value());
}

TEST_F(CertificateVerificationIntegrationTest, BuildsMissingIntermediateFromAdditionalCertificates)
{
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    auto intermediate = ParseCertificate("certificate/pki_chain/intermediate_ca.pem");
    ASSERT_TRUE(leaf.has_value());
    ASSERT_TRUE(intermediate.has_value());

    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_root_trust_store).has_value());
    const std::array<score::crypto::CryptoResourceId, 1U> additional{intermediate->Id()};
    ASSERT_TRUE(verification
                    ->SetAdditionalCertificates(
                        score::cpp::span<const score::crypto::CryptoResourceId>{additional.data(), additional.size()})
                    .has_value());

    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kValid);
}

TEST_F(CertificateVerificationIntegrationTest, VerifiesLeafAgainstStandaloneIntermediateAnchor)
{
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    auto intermediate = ParseCertificate("certificate/pki_chain/intermediate_ca.pem");
    ASSERT_TRUE(leaf.has_value());
    ASSERT_TRUE(intermediate.has_value());

    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    const std::array<score::crypto::CryptoResourceId, 1U> anchors{intermediate->Id()};
    ASSERT_TRUE(verification
                    ->SetTrustedCertificates(
                        score::cpp::span<const score::crypto::CryptoResourceId>{anchors.data(), anchors.size()})
                    .has_value());
    ASSERT_TRUE(verification->SetEvidenceMode(score::crypto::VerificationEvidenceMode::kChain).has_value());

    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kValid);
    auto chain_length = verification->GetVerifiedChainCertificateCount();
    ASSERT_TRUE(chain_length.has_value());
    EXPECT_EQ(*chain_length, 2U);
}

TEST_F(CertificateVerificationIntegrationTest, RootRequiredBuildsThroughIntermediateInMixedTrustStore)
{
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    ASSERT_TRUE(leaf.has_value());

    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_full_trust_store).has_value());
    ASSERT_TRUE(
        verification->SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy::kRootRequired).has_value());
    ASSERT_TRUE(verification->SetEvidenceMode(score::crypto::VerificationEvidenceMode::kChain).has_value());

    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kValid);
    auto chain_length = verification->GetVerifiedChainCertificateCount();
    ASSERT_TRUE(chain_length.has_value());
    EXPECT_EQ(*chain_length, 3U);
}

TEST_F(CertificateVerificationIntegrationTest, TrustStoreTerminatedStopsAtIntermediateInMixedTrustStore)
{
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    ASSERT_TRUE(leaf.has_value());

    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_full_trust_store).has_value());
    ASSERT_TRUE(verification->SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy::kTrustStoreTerminated)
                    .has_value());
    ASSERT_TRUE(verification->SetEvidenceMode(score::crypto::VerificationEvidenceMode::kChain).has_value());

    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kValid);
    auto chain_length = verification->GetVerifiedChainCertificateCount();
    ASSERT_TRUE(chain_length.has_value());
    EXPECT_EQ(*chain_length, 2U);
}

TEST_F(CertificateVerificationIntegrationTest, CombinesTrustStoreAndExplicitTrustedCertificates)
{
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    auto root = ParseCertificate("certificate/pki_chain/root_ca.pem");
    ASSERT_TRUE(leaf.has_value());
    ASSERT_TRUE(root.has_value());

    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_intermediate_trust_store).has_value());
    const std::array<score::crypto::CryptoResourceId, 1U> explicit_anchors{root->Id()};
    ASSERT_TRUE(verification
                    ->SetTrustedCertificates(score::cpp::span<const score::crypto::CryptoResourceId>{
                        explicit_anchors.data(), explicit_anchors.size()})
                    .has_value());
    ASSERT_TRUE(
        verification->SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy::kRootRequired).has_value());
    ASSERT_TRUE(verification->SetEvidenceMode(score::crypto::VerificationEvidenceMode::kChain).has_value());

    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kValid);
    auto chain_length = verification->GetVerifiedChainCertificateCount();
    ASSERT_TRUE(chain_length.has_value());
    EXPECT_EQ(*chain_length, 3U);
}

TEST_F(CertificateVerificationIntegrationTest, RejectsLeafWhenIntermediateIsMissing)
{
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    ASSERT_TRUE(leaf.has_value());
    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_root_trust_store).has_value());

    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kNoRootFound);
}

TEST_F(CertificateVerificationIntegrationTest, TrustStoreTerminatedAcceptsTrustedIntermediate)
{
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    ASSERT_TRUE(leaf.has_value());

    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_intermediate_trust_store).has_value());
    ASSERT_TRUE(verification->SetEvidenceMode(score::crypto::VerificationEvidenceMode::kChain).has_value());
    ASSERT_TRUE(verification->SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy::kTrustStoreTerminated)
                    .has_value());

    auto terminated_result = verification->Verify();
    ASSERT_TRUE(terminated_result.has_value());
    EXPECT_EQ(*terminated_result, score::crypto::CertVerifyResult::kValid);
    auto chain_length = verification->GetVerifiedChainCertificateCount();
    ASSERT_TRUE(chain_length.has_value());
    EXPECT_EQ(*chain_length, 2U);
}

TEST_F(CertificateVerificationIntegrationTest, RootRequiredRejectsTrustedIntermediateAsTerminal)
{
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    ASSERT_TRUE(leaf.has_value());
    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_intermediate_trust_store).has_value());
    ASSERT_TRUE(
        verification->SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy::kRootRequired).has_value());

    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kNoRootFound);
}

TEST_F(CertificateVerificationIntegrationTest, RejectsRevokedLeafWithIntermediateCrl)
{
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    auto intermediate = ParseCertificate("certificate/pki_chain/intermediate_ca.pem");
    ASSERT_TRUE(leaf.has_value());
    ASSERT_TRUE(intermediate.has_value());
    auto intermediate_view = m_context->GetCertificateObject(*intermediate);
    ASSERT_TRUE(intermediate_view.has_value());
    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_intermediate_trust_store).has_value());
    ASSERT_TRUE(verification->SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy::kTrustStoreTerminated)
                    .has_value());
    ASSERT_TRUE(verification->SetRevocationCheckPolicy(score::crypto::RevocationCheckPolicy::kCrlOnly).has_value());
    ASSERT_TRUE(verification->SetEvidenceMode(score::crypto::VerificationEvidenceMode::kChainAndCrl).has_value());

    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kRevoked);
    auto metadata_size = verification->GetSelectedCrlMetadataCount();
    ASSERT_TRUE(metadata_size.has_value());
    EXPECT_GT(*metadata_size, 0U);
    std::vector<score::crypto::CrlMetadata> metadata(*metadata_size);
    ASSERT_EQ(*verification->GetSelectedCrlMetadata(
                  score::cpp::span<score::crypto::CrlMetadata>{metadata.data(), metadata.size()}),
              *metadata_size);

    const auto intermediate_fingerprint = (*intermediate_view)->GetFingerprint();
    const auto matching = std::find_if(metadata.begin(), metadata.end(), [&](const auto& item) {
        return item.issuer_fingerprint == intermediate_fingerprint;
    });
    ASSERT_NE(matching, metadata.end());
    EXPECT_NE(matching->fingerprint, (std::array<std::uint8_t, 32U>{}));
    EXPECT_LT(matching->this_update, matching->next_update);
}

TEST_F(CertificateVerificationIntegrationTest, StandaloneAnchorAndVerificationTimeAreIndependentOfTrustStore)
{
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    auto intermediate = ParseCertificate("certificate/pki_chain/intermediate_ca.pem");
    auto root = ParseCertificate("certificate/pki_chain/root_ca.pem");
    ASSERT_TRUE(leaf.has_value());
    ASSERT_TRUE(intermediate.has_value());
    ASSERT_TRUE(root.has_value());

    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    const std::array<score::crypto::CryptoResourceId, 1U> anchors{root->Id()};
    ASSERT_TRUE(verification
                    ->SetTrustedCertificates(
                        score::cpp::span<const score::crypto::CryptoResourceId>{anchors.data(), anchors.size()})
                    .has_value());
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    const std::array<score::crypto::CryptoResourceId, 1U> additional{intermediate->Id()};
    ASSERT_TRUE(verification
                    ->SetAdditionalCertificates(
                        score::cpp::span<const score::crypto::CryptoResourceId>{additional.data(), additional.size()})
                    .has_value());
    auto leaf_view = m_context->GetCertificateObject(*leaf);
    ASSERT_TRUE(leaf_view.has_value());
    ASSERT_TRUE(verification->SetVerificationTime((*leaf_view)->GetNotBefore() - 1).has_value());

    auto future_result = verification->Verify();
    ASSERT_TRUE(future_result.has_value());
    EXPECT_EQ(*future_result, score::crypto::CertVerifyResult::kNotYetValid);
}

}  // namespace
