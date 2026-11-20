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
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace
{

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
        ASSERT_NO_FATAL_FAILURE(OpenClient());
    }

    void OpenClient()
    {
        auto stack_result = score::crypto::CreateCryptoStack();
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

    void CloseClient()
    {
        m_management.reset();
        m_context.reset();
        m_stack.reset();
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

TEST_F(CertificateVerificationIntegrationTest, RejectsInvalidRevocationPolicies)
{
    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);

    const auto invalid_check_policy = static_cast<score::crypto::RevocationCheckPolicy>(0xFFU);
    EXPECT_FALSE(verification->SetRevocationCheckPolicy(invalid_check_policy).has_value());

    const auto invalid_coverage_policy = static_cast<score::crypto::RevocationCoveragePolicy>(0xFFU);
    EXPECT_FALSE(verification->SetRevocationCoveragePolicy(invalid_coverage_policy).has_value());
}

TEST_F(CertificateVerificationIntegrationTest, MissingCrlCoverageFollowsCoveragePolicy)
{
    const auto chain_bytes = ReadFile(VectorPath("certificate/pki_chain/leaf.chain.pem"));
    ASSERT_FALSE(chain_bytes.empty());
    auto parsed = m_management->ParseCertificates(
        score::cpp::span<const std::uint8_t>{chain_bytes.data(), chain_bytes.size()}, score::crypto::FormatType::kPem);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 3U);

    const std::array<score::crypto::CryptoResourceId, 3U> chain_ids{
        (*parsed)[0].Id(), (*parsed)[1].Id(), (*parsed)[2].Id()};
    const std::array<score::crypto::CryptoResourceId, 1U> trust_anchors{(*parsed)[2].Id()};

    auto fail_closed = CreateVerificationContext();
    ASSERT_NE(fail_closed, nullptr);
    ASSERT_TRUE(fail_closed
                    ->SetCertificateChain(
                        score::cpp::span<const score::crypto::CryptoResourceId>{chain_ids.data(), chain_ids.size()})
                    .has_value());
    ASSERT_TRUE(fail_closed
                    ->SetTrustedCertificates(score::cpp::span<const score::crypto::CryptoResourceId>{
                        trust_anchors.data(), trust_anchors.size()})
                    .has_value());
    ASSERT_TRUE(
        fail_closed->SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy::kRootRequired).has_value());
    ASSERT_TRUE(fail_closed->SetRevocationCheckPolicy(score::crypto::RevocationCheckPolicy::kCrlOnly).has_value());
    ASSERT_TRUE(
        fail_closed->SetRevocationCoveragePolicy(score::crypto::RevocationCoveragePolicy::kFailClosed).has_value());

    const auto fail_closed_result = fail_closed->Verify();
    ASSERT_TRUE(fail_closed_result.has_value());
    EXPECT_EQ(*fail_closed_result, score::crypto::CertVerifyResult::kRevocationStatusUnavailable);

    auto best_effort = CreateVerificationContext();
    ASSERT_NE(best_effort, nullptr);
    ASSERT_TRUE(best_effort
                    ->SetCertificateChain(
                        score::cpp::span<const score::crypto::CryptoResourceId>{chain_ids.data(), chain_ids.size()})
                    .has_value());
    ASSERT_TRUE(best_effort
                    ->SetTrustedCertificates(score::cpp::span<const score::crypto::CryptoResourceId>{
                        trust_anchors.data(), trust_anchors.size()})
                    .has_value());
    ASSERT_TRUE(
        best_effort->SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy::kRootRequired).has_value());
    ASSERT_TRUE(best_effort->SetRevocationCheckPolicy(score::crypto::RevocationCheckPolicy::kCrlOnly).has_value());
    ASSERT_TRUE(
        best_effort->SetRevocationCoveragePolicy(score::crypto::RevocationCoveragePolicy::kBestEffort).has_value());

    const auto best_effort_result = best_effort->Verify();
    ASSERT_TRUE(best_effort_result.has_value());
    EXPECT_EQ(*best_effort_result, score::crypto::CertVerifyResult::kValid);
}

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

TEST_F(CertificateVerificationIntegrationTest, BuildsMissingIntermediateFromUntrustedCertificates)
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
                    ->SetUntrustedCertificates(
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
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kChainIncomplete);
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
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kChainIncomplete);
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
                    ->SetUntrustedCertificates(
                        score::cpp::span<const score::crypto::CryptoResourceId>{additional.data(), additional.size()})
                    .has_value());
    auto leaf_view = m_context->GetCertificateObject(*leaf);
    ASSERT_TRUE(leaf_view.has_value());
    ASSERT_TRUE(verification->SetVerificationTime((*leaf_view)->GetNotBefore() - 1).has_value());

    auto future_result = verification->Verify();
    ASSERT_TRUE(future_result.has_value());
    EXPECT_EQ(*future_result, score::crypto::CertVerifyResult::kNotYetValid);
}

// Two 4 MiB SHM pools fill the 8 MiB per-uid quota, so the fixture's stack is closed while the workers run.
constexpr std::size_t kConcurrentWorkers = 2U;
constexpr std::size_t kIterationsPerWorker = 4U;

/// What one worker observed. A worker writes only its own report, and the main thread reads the reports after join().
struct VerificationWorkerReport
{
    std::size_t completed_iterations{0U};
    std::vector<std::string> failures;
};

void RecordFailure(VerificationWorkerReport& report, std::string message)
{
    report.failures.push_back(std::move(message));
}

/// Verifies the leaf-intermediate-root chain and exports it. The worker releases its certificate handles once the
/// verification context has taken their IDs, as the export test does, and checks the exported chain against the
/// parsed one.
void RunAcceptingVerification(score::crypto::ICryptoContext& context,
                              score::crypto::ICertificateManagementContext& management,
                              const score::crypto::CryptoResourceId& full_trust_store,
                              VerificationWorkerReport& report)
{
    const auto chain_bytes = ReadFile(VectorPath("certificate/pki_chain/leaf.chain.pem"));
    if (chain_bytes.empty())
    {
        RecordFailure(report, "leaf.chain.pem is empty");
        return;
    }
    auto parsed = management.ParseCertificates(
        score::cpp::span<const std::uint8_t>{chain_bytes.data(), chain_bytes.size()}, score::crypto::FormatType::kPem);
    if (!parsed.has_value() || parsed->size() != 3U)
    {
        RecordFailure(report, "leaf.chain.pem did not parse to three certificates");
        return;
    }
    const std::array<score::crypto::CryptoResourceId, 3U> chain_ids{
        (*parsed)[0].Id(), (*parsed)[1].Id(), (*parsed)[2].Id()};

    score::crypto::CertificateVerificationContextConfig config;
    auto verification_result = context.CreateCertificateVerificationContext(config);
    if (!verification_result.has_value())
    {
        RecordFailure(report, "CreateCertificateVerificationContext failed");
        return;
    }
    auto verification = std::move(verification_result.value());

    const score::cpp::span<const score::crypto::CryptoResourceId> chain_span{chain_ids.data(), chain_ids.size()};
    if (!verification->SetCertificateChain(chain_span).has_value() ||
        !verification->SetVerificationTrustStore(full_trust_store).has_value() ||
        !verification->SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy::kRootRequired).has_value() ||
        !verification->SetEvidenceMode(score::crypto::VerificationEvidenceMode::kChain).has_value())
    {
        RecordFailure(report, "configuring the accepting verification failed");
        return;
    }

    for (auto& certificate : *parsed)
    {
        if (!certificate.Release().has_value())
        {
            RecordFailure(report, "releasing a certificate handle failed");
            return;
        }
    }

    const auto result = verification->Verify();
    if (!result.has_value() || *result != score::crypto::CertVerifyResult::kValid)
    {
        RecordFailure(report, "a valid chain did not verify as kValid");
        return;
    }

    const auto chain_length = verification->GetVerifiedChainCertificateCount();
    if (!chain_length.has_value() || *chain_length != 3U)
    {
        RecordFailure(report, "the verified chain does not hold three certificates");
        return;
    }

    const auto export_size = verification->GetVerifiedChainExportSize(score::crypto::FormatType::kPem);
    if (!export_size.has_value())
    {
        RecordFailure(report, "GetVerifiedChainExportSize failed");
        return;
    }
    std::vector<std::uint8_t> exported(*export_size);
    const auto exported_size = verification->ExportVerifiedChain(
        score::crypto::FormatType::kPem, score::cpp::span<std::uint8_t>{exported.data(), exported.size()});
    if (!exported_size.has_value() || *exported_size != *export_size)
    {
        RecordFailure(report, "ExportVerifiedChain did not write the advertised size");
        return;
    }

    auto reparsed = management.ParseCertificates(score::cpp::span<const std::uint8_t>{exported.data(), exported.size()},
                                                 score::crypto::FormatType::kPem);
    if (!reparsed.has_value() || reparsed->size() != 3U)
    {
        RecordFailure(report, "the exported chain did not reparse to three certificates");
        return;
    }
    ++report.completed_iterations;
}

/// Verifies a leaf whose intermediate is absent from the trust store. The expected outcome is a failure, so the
/// failing path runs on this worker while other workers are on the accepting path.
void RunRejectingVerification(score::crypto::ICryptoContext& context,
                              score::crypto::ICertificateManagementContext& management,
                              const score::crypto::CryptoResourceId& root_trust_store,
                              VerificationWorkerReport& report)
{
    const auto leaf_bytes = ReadFile(VectorPath("certificate/pki_chain/leaf.pem"));
    if (leaf_bytes.empty())
    {
        RecordFailure(report, "leaf.pem is empty");
        return;
    }
    auto leaf = management.ParseCertificate(score::cpp::span<const std::uint8_t>{leaf_bytes.data(), leaf_bytes.size()},
                                            score::crypto::FormatType::kPem);
    if (!leaf.has_value())
    {
        RecordFailure(report, "leaf.pem did not parse");
        return;
    }

    score::crypto::CertificateVerificationContextConfig config;
    auto verification_result = context.CreateCertificateVerificationContext(config);
    if (!verification_result.has_value())
    {
        RecordFailure(report, "CreateCertificateVerificationContext failed");
        return;
    }
    auto verification = std::move(verification_result.value());

    if (!verification->SetCertificate(leaf.value()).has_value() ||
        !verification->SetVerificationTrustStore(root_trust_store).has_value())
    {
        RecordFailure(report, "configuring the rejecting verification failed");
        return;
    }

    const auto result = verification->Verify();
    if (!result.has_value() || *result != score::crypto::CertVerifyResult::kChainIncomplete)
    {
        RecordFailure(report, "a leaf without its intermediate did not verify as kChainIncomplete");
        return;
    }
    ++report.completed_iterations;
}

/// One worker is one client with its own stack, context and management context, so it owns every handle and buffer it
/// uses. Workers start on different iterations, so accepting and rejecting verifications overlap in time.
void RunConcurrentVerificationWorker(std::size_t worker_index, VerificationWorkerReport& report)
{
    auto stack_result = score::crypto::CreateCryptoStack();
    if (!stack_result.has_value())
    {
        RecordFailure(report, "CreateCryptoStack failed");
        return;
    }
    auto stack = std::move(stack_result.value());

    auto context_result = stack->CreateCryptoContext();
    if (!context_result.has_value())
    {
        RecordFailure(report, "CreateCryptoContext failed");
        return;
    }
    auto context = std::move(context_result.value());

    score::crypto::CertificateContextConfig management_config;
    auto management_result = context->CreateCertificateManagementContext(management_config);
    if (!management_result.has_value())
    {
        RecordFailure(report, "CreateCertificateManagementContext failed");
        return;
    }
    auto management = std::move(management_result.value());

    const auto full_trust_store =
        context->ResolveResource("verification_tls_roots", score::crypto::ResourceType::kCertificateTrustStore);
    const auto root_trust_store =
        context->ResolveResource("verification_root_trust", score::crypto::ResourceType::kCertificateTrustStore);
    if (!full_trust_store.has_value() || !root_trust_store.has_value())
    {
        RecordFailure(report, "resolving the verification trust stores failed");
        return;
    }

    for (std::size_t iteration = 0U; iteration < kIterationsPerWorker; ++iteration)
    {
        if (((worker_index + iteration) % 2U) == 0U)
            RunAcceptingVerification(*context, *management, full_trust_store.value(), report);
        else
            RunRejectingVerification(*context, *management, root_trust_store.value(), report);
        if (!report.failures.empty())
            return;
    }
}

TEST_F(CertificateVerificationIntegrationTest, ConcurrentVerificationsKeepPerThreadResults)
{
    CloseClient();

    std::vector<VerificationWorkerReport> reports(kConcurrentWorkers);
    std::vector<std::thread> workers;
    workers.reserve(kConcurrentWorkers);
    for (std::size_t index = 0U; index < kConcurrentWorkers; ++index)
    {
        workers.emplace_back([index, &reports]() {
            RunConcurrentVerificationWorker(index, reports[index]);
        });
    }
    for (auto& worker : workers)
    {
        worker.join();
    }

    for (std::size_t index = 0U; index < kConcurrentWorkers; ++index)
    {
        for (const auto& failure : reports[index].failures)
        {
            ADD_FAILURE() << "worker " << index << ": " << failure;
        }
        EXPECT_EQ(reports[index].completed_iterations, kIterationsPerWorker) << "worker " << index;
    }

    // The fixture's client still verifies after the workers have released their own handles.
    ASSERT_NO_FATAL_FAILURE(OpenClient());
    auto leaf = ParseCertificate("certificate/pki_chain/leaf.pem");
    ASSERT_TRUE(leaf.has_value());
    auto verification = CreateVerificationContext();
    ASSERT_NE(verification, nullptr);
    ASSERT_TRUE(verification->SetCertificate(*leaf).has_value());
    ASSERT_TRUE(verification->SetVerificationTrustStore(m_full_trust_store).has_value());
    auto result = verification->Verify();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, score::crypto::CertVerifyResult::kValid);
}

}  // namespace
