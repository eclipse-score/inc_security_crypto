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
#include "score/crypto/src/api/config/trust_store_management_context_config.hpp"
#include "score/crypto/src/api/contexts/i_certificate_management_context.hpp"
#include "score/crypto/src/api/contexts/i_trust_store_management_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/objects/i_cert_slot_object.hpp"
#include "score/crypto/src/api/objects/i_certificate_object.hpp"
#include "score/crypto/src/api/objects/i_trust_store_object.hpp"
#include "score/crypto/src/api/types/certificate.hpp"

#include <gtest/gtest.h>

#include <unistd.h>
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

bool FileExists(const std::string& path)
{
    std::ifstream f{path, std::ios::binary};
    return f.is_open();
}

class CertificateManagementIntegrationTest : public ::testing::Test
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

        score::crypto::TrustStoreManagementContextConfig trust_store_config;
        auto trust_store_mgmt_result = m_context->CreateTrustStoreManagementContext(trust_store_config);
        ASSERT_TRUE(trust_store_mgmt_result.has_value());
        m_trust_store_mgmt = std::move(trust_store_mgmt_result.value());

        auto slot_result = m_context->ResolveResource("device_cert", score::crypto::ResourceType::kCertSlot);
        ASSERT_TRUE(slot_result.has_value());
        m_device_slot = slot_result.value();

        auto trust_store_result =
            m_context->ResolveResource("tls_roots", score::crypto::ResourceType::kCertificateTrustStore);
        ASSERT_TRUE(trust_store_result.has_value());
        m_trust_store = trust_store_result.value();

        auto mutable_trust_store_result =
            m_context->ResolveResource("mutable_trust_store", score::crypto::ResourceType::kCertificateTrustStore);
        ASSERT_TRUE(mutable_trust_store_result.has_value());
        m_mutable_trust_store = mutable_trust_store_result.value();
    }

    std::optional<score::crypto::CryptoResourceGuard> ParseBasicCertificate()
    {
        const auto bytes = ReadFile(VectorPath("certificate/basic/certificate.pem"));
        EXPECT_FALSE(bytes.empty());
        auto result = m_management->ParseCertificate(score::cpp::span<const std::uint8_t>{bytes.data(), bytes.size()},
                                                     score::crypto::FormatType::kPem);
        EXPECT_TRUE(result.has_value());
        if (!result.has_value())
            return std::nullopt;
        return std::move(result.value());
    }

    score::crypto::ICryptoStack::Uptr m_stack;
    score::crypto::ICryptoContext::Uptr m_context;
    score::crypto::ICertificateManagementContext::Uptr m_management;
    score::crypto::ITrustStoreManagementContext::Uptr m_trust_store_mgmt;
    score::crypto::CryptoResourceId m_device_slot{};
    score::crypto::CryptoResourceId m_trust_store{};
    score::crypto::CryptoResourceId m_mutable_trust_store{};
};

TEST_F(CertificateManagementIntegrationTest, ParsesAndInspectsCertificate)
{
    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());

    auto certificate_view = m_context->GetCertificateObject(*certificate);
    ASSERT_TRUE(certificate_view.has_value());

    EXPECT_EQ((*certificate_view)->GetType(), score::crypto::ResourceType::kCertificate);
    EXPECT_EQ((*certificate_view)->GetSubject(), "CN=cert-management-test,O=Eclipse");
    EXPECT_EQ((*certificate_view)->GetIssuer(), "CN=cert-management-test,O=Eclipse");
    EXPECT_GT((*certificate_view)->GetNotAfter(), (*certificate_view)->GetNotBefore());
    EXPECT_FALSE((*certificate_view)->GetSerialNumber().empty());
    EXPECT_EQ((*certificate_view)->GetFingerprint().size(), 32U);
}

TEST_F(CertificateManagementIntegrationTest, ParsesPemBundle)
{
    const auto certificate = ReadFile(VectorPath("certificate/basic/certificate.pem"));
    ASSERT_FALSE(certificate.empty());
    std::vector<std::uint8_t> bundle{certificate};
    bundle.insert(bundle.end(), certificate.begin(), certificate.end());

    auto result = m_management->ParseCertificates(score::cpp::span<const std::uint8_t>{bundle.data(), bundle.size()},
                                                  score::crypto::FormatType::kPem);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 2U);
    auto first_view = m_context->GetCertificateObject((*result)[0]);
    auto second_view = m_context->GetCertificateObject((*result)[1]);
    ASSERT_TRUE(first_view.has_value());
    ASSERT_TRUE(second_view.has_value());
    EXPECT_EQ((*first_view)->GetSubject(), (*second_view)->GetSubject());
}

TEST_F(CertificateManagementIntegrationTest, SavesExportsAndClearsCertificateSlot)
{
    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());
    ASSERT_TRUE(m_management->SaveCertificate(*certificate, m_device_slot).has_value());

    auto slot_object = m_context->GetCertSlotObject(m_device_slot);
    ASSERT_TRUE(slot_object.has_value());
    ASSERT_TRUE((*slot_object)->IsOccupied());

    auto export_size = m_management->GetCertificateExportSize(*certificate, score::crypto::FormatType::kDer);
    ASSERT_TRUE(export_size.has_value());
    ASSERT_GT(*export_size, 0U);
    std::vector<std::uint8_t> exported(*export_size);
    auto export_result =
        m_management->ExportCertificate(*certificate,
                                        score::crypto::FormatType::kDer,
                                        score::cpp::span<std::uint8_t>{exported.data(), exported.size()});
    ASSERT_TRUE(export_result.has_value());
    ASSERT_EQ(*export_result, exported.size());

    auto persistent = m_context->GetCertificateObject(m_device_slot);
    ASSERT_TRUE(persistent.has_value());
    auto certificate_view = m_context->GetCertificateObject(*certificate);
    ASSERT_TRUE(certificate_view.has_value());
    EXPECT_EQ((*persistent)->GetFingerprint(), (*certificate_view)->GetFingerprint());

    ASSERT_TRUE(m_management->ClearCertificate(m_device_slot).has_value());
    auto cleared_slot = m_context->GetCertSlotObject(m_device_slot);
    ASSERT_TRUE(cleared_slot.has_value());
    EXPECT_FALSE((*cleared_slot)->IsOccupied());
}

TEST_F(CertificateManagementIntegrationTest, LoadsCertificateSlotIntoReusableGuard)
{
    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());
    ASSERT_TRUE(m_management->SaveCertificate(*certificate, m_device_slot).has_value());

    auto loaded = m_management->LoadCertificate(m_device_slot);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->Id().type, score::crypto::ResourceType::kCertificate);

    auto loaded_view = m_context->GetCertificateObject(*loaded);
    ASSERT_TRUE(loaded_view.has_value());
    EXPECT_EQ((*loaded_view)->GetSubject(), "CN=cert-management-test,O=Eclipse");
    EXPECT_EQ((*loaded_view)->GetFingerprint().size(), 32U);

    ASSERT_TRUE(m_management->ClearCertificate(m_device_slot).has_value());
}

TEST_F(CertificateManagementIntegrationTest, TrustStoreObjectFindsAndTogglesMember)
{
    auto trust_store = m_context->GetTrustStoreObject(m_trust_store);
    ASSERT_TRUE(trust_store.has_value());
    ASSERT_FALSE((*trust_store)->GetMembers().empty());

    const auto& member = (*trust_store)->GetMembers().front();
    const auto* found_by_slot = (*trust_store)->FindMember(member.slot_id);
    ASSERT_NE(found_by_slot, nullptr);
    const score::cpp::span<const std::uint8_t> fingerprint{member.sha256_fingerprint.data(),
                                                           member.sha256_fingerprint.size()};
    EXPECT_NE((*trust_store)->FindMemberByFingerprint(fingerprint), nullptr);

    ASSERT_TRUE(m_trust_store_mgmt->DisableTrustStoreMember(m_trust_store, member.slot_id).has_value());
    auto disabled = m_context->GetTrustStoreObject(m_trust_store);
    ASSERT_TRUE(disabled.has_value());
    EXPECT_FALSE((*disabled)->GetDisabledMemberSlotIds().empty());
    ASSERT_TRUE(m_trust_store_mgmt->EnableTrustStoreMember(m_trust_store, member.slot_id).has_value());
}

TEST_F(CertificateManagementIntegrationTest, AddsCertificateParsedByManagementContextToTrustStoreViaTrustStoreContext)
{
    // Certificate parsing/inspection stays on ICertificateManagementContext; the
    // resulting ephemeral resource is handed to ITrustStoreManagementContext for
    // the actual membership mutation — exercising the CERT:TRUST_STORE context
    // creation/routing path end to end.
    //
    // The fixture's "tls_roots" store has no kExclusiveMutable slot configured, and
    // ParseBasicCertificate() parses the exact cert already pinned there as the
    // kSharedStatic "integration_root_ca" member (see integration_root_ca.kv). So
    // AddCertificateToTrustStore hits the dedup path (idempotent success against an
    // already-present member) rather than allocating a new owned slot, and
    // RemoveCertificateFromTrustStore is correctly rejected — shared-static
    // membership is not mutable through the trust-store API.
    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());

    auto add_result = m_trust_store_mgmt->AddCertificateToTrustStore(m_trust_store, *certificate);
    ASSERT_TRUE(add_result.has_value());

    auto certificate_view = m_context->GetCertificateObject(*certificate);
    ASSERT_TRUE(certificate_view.has_value());
    auto trust_store = m_context->GetTrustStoreObject(m_trust_store);
    ASSERT_TRUE(trust_store.has_value());
    const auto fingerprint_bytes = (*certificate_view)->GetFingerprint();
    const score::cpp::span<const std::uint8_t> fingerprint{fingerprint_bytes.data(), fingerprint_bytes.size()};
    ASSERT_NE((*trust_store)->FindMemberByFingerprint(fingerprint), nullptr);

    EXPECT_FALSE(m_trust_store_mgmt->RemoveCertificateFromTrustStore(m_trust_store, fingerprint).has_value());
    auto after_removal = m_context->GetTrustStoreObject(m_trust_store);
    ASSERT_TRUE(after_removal.has_value());
    EXPECT_NE((*after_removal)->FindMemberByFingerprint(fingerprint), nullptr);
}

TEST_F(CertificateManagementIntegrationTest, AddsNewCertificateIntoEmptyExclusiveSlotThenRemovesIt)
{
    // "mutable_trust_store" (integration_mutable_trust_store) has exactly one
    // kExclusiveMutable member (integration_exclusive_slot) and starts empty — its
    // cert_path points at a file that is never packaged into the test image. This
    // exercises the real allocate-an-owned-slot path in TrustStoreManager::AddMember,
    // unlike the dedup/idempotent path exercised against "tls_roots" above.
    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());

    auto certificate_view = m_context->GetCertificateObject(*certificate);
    ASSERT_TRUE(certificate_view.has_value());
    const auto fingerprint_bytes = (*certificate_view)->GetFingerprint();
    const score::cpp::span<const std::uint8_t> fingerprint{fingerprint_bytes.data(), fingerprint_bytes.size()};

    ASSERT_TRUE(m_trust_store_mgmt->AddCertificateToTrustStore(m_mutable_trust_store, *certificate).has_value());

    auto trust_store = m_context->GetTrustStoreObject(m_mutable_trust_store);
    ASSERT_TRUE(trust_store.has_value());
    const auto* member = (*trust_store)->FindMemberByFingerprint(fingerprint);
    ASSERT_NE(member, nullptr);
    EXPECT_EQ(member->kind, score::crypto::MemberKind::kExclusiveMutable);
    EXPECT_TRUE(member->is_enabled);

    // Now that the slot is genuinely owned by the trust store, removal must succeed
    // (unlike the shared-static case above).
    ASSERT_TRUE(m_trust_store_mgmt->RemoveCertificateFromTrustStore(m_mutable_trust_store, fingerprint).has_value());

    auto after_removal = m_context->GetTrustStoreObject(m_mutable_trust_store);
    ASSERT_TRUE(after_removal.has_value());
    EXPECT_EQ((*after_removal)->FindMemberByFingerprint(fingerprint), nullptr);
}

TEST_F(CertificateManagementIntegrationTest, EnablesAndDisablesExclusiveTrustStoreMember)
{
    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());
    ASSERT_TRUE(m_trust_store_mgmt->AddCertificateToTrustStore(m_mutable_trust_store, *certificate).has_value());

    auto certificate_view = m_context->GetCertificateObject(*certificate);
    ASSERT_TRUE(certificate_view.has_value());
    const auto fingerprint_bytes = (*certificate_view)->GetFingerprint();
    const score::cpp::span<const std::uint8_t> fingerprint{fingerprint_bytes.data(), fingerprint_bytes.size()};

    auto trust_store = m_context->GetTrustStoreObject(m_mutable_trust_store);
    ASSERT_TRUE(trust_store.has_value());
    const auto* member = (*trust_store)->FindMemberByFingerprint(fingerprint);
    ASSERT_NE(member, nullptr);
    const auto slot_id = member->slot_id;

    ASSERT_TRUE(m_trust_store_mgmt->DisableTrustStoreMember(m_mutable_trust_store, slot_id).has_value());
    auto disabled = m_context->GetTrustStoreObject(m_mutable_trust_store);
    ASSERT_TRUE(disabled.has_value());
    const auto* disabled_member = (*disabled)->FindMember(slot_id);
    ASSERT_NE(disabled_member, nullptr);
    EXPECT_FALSE(disabled_member->is_enabled);

    ASSERT_TRUE(m_trust_store_mgmt->EnableTrustStoreMember(m_mutable_trust_store, slot_id).has_value());
    auto enabled = m_context->GetTrustStoreObject(m_mutable_trust_store);
    ASSERT_TRUE(enabled.has_value());
    const auto* enabled_member = (*enabled)->FindMember(slot_id);
    ASSERT_NE(enabled_member, nullptr);
    EXPECT_TRUE(enabled_member->is_enabled);

    ASSERT_TRUE(m_trust_store_mgmt->RemoveCertificateFromTrustStore(m_mutable_trust_store, fingerprint).has_value());
}

TEST_F(CertificateManagementIntegrationTest, ImportsCrlForExclusiveTrustStoreMember)
{
    const auto crl_path = VectorPath("certificate/basic/certificate.crl.pem");
    if (!FileExists(crl_path))
    {
        GTEST_SKIP() << "certificate.crl.pem not generated - run: "
                        "python generate_certificates.py crl certificate "
                        "--manifest basic/manifest.json";
    }

    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());
    ASSERT_TRUE(m_trust_store_mgmt->AddCertificateToTrustStore(m_mutable_trust_store, *certificate).has_value());

    auto certificate_view = m_context->GetCertificateObject(*certificate);
    ASSERT_TRUE(certificate_view.has_value());
    const auto fingerprint_bytes = (*certificate_view)->GetFingerprint();
    const score::cpp::span<const std::uint8_t> fingerprint{fingerprint_bytes.data(), fingerprint_bytes.size()};

    auto trust_store = m_context->GetTrustStoreObject(m_mutable_trust_store);
    ASSERT_TRUE(trust_store.has_value());
    const auto* member = (*trust_store)->FindMemberByFingerprint(fingerprint);
    ASSERT_NE(member, nullptr);
    const auto slot_id = member->slot_id;

    const auto crl_bytes = ReadFile(crl_path);
    ASSERT_FALSE(crl_bytes.empty());
    ASSERT_TRUE(
        m_trust_store_mgmt
            ->ImportCrlForTrustStoreMember(m_mutable_trust_store,
                                           slot_id,
                                           score::cpp::span<const std::uint8_t>{crl_bytes.data(), crl_bytes.size()},
                                           score::crypto::FormatType::kPem)
            .has_value());

    auto slot_object = m_context->GetCertSlotObject(slot_id);
    ASSERT_TRUE(slot_object.has_value());
    EXPECT_TRUE((*slot_object)->HasCrl());

    ASSERT_TRUE(m_trust_store_mgmt->DeleteCrlForTrustStoreMember(m_mutable_trust_store, slot_id).has_value());
    auto cleared_slot_object = m_context->GetCertSlotObject(slot_id);
    ASSERT_TRUE(cleared_slot_object.has_value());
    EXPECT_FALSE((*cleared_slot_object)->HasCrl());

    // Cleanup also clears the slot's CRL (FileBackedSlotHandler::ClearSlot).
    ASSERT_TRUE(m_trust_store_mgmt->RemoveCertificateFromTrustStore(m_mutable_trust_store, fingerprint).has_value());
}

TEST_F(CertificateManagementIntegrationTest, RejectsMalformedCrl)
{
    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());
    const std::vector<std::uint8_t> malformed{0xDEU, 0xADU, 0xBEU, 0xEFU};
    auto result = m_management->ImportCrl(score::cpp::span<const std::uint8_t>{malformed.data(), malformed.size()},
                                          score::crypto::FormatType::kDer,
                                          *certificate);
    EXPECT_FALSE(result.has_value());
}

TEST_F(CertificateManagementIntegrationTest, ImportsCrlSessionScopedOnEphemeralCert)
{
    const auto crl_path = VectorPath("certificate/basic/certificate.crl.pem");
    if (!FileExists(crl_path))
    {
        GTEST_SKIP() << "certificate.crl.pem not generated - run: "
                        "python generate_certificates.py crl certificate "
                        "--manifest basic/manifest.json";
    }

    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());

    const auto crl_bytes = ReadFile(crl_path);
    ASSERT_FALSE(crl_bytes.empty());
    auto result = m_management->ImportCrl(score::cpp::span<const std::uint8_t>{crl_bytes.data(), crl_bytes.size()},
                                          score::crypto::FormatType::kPem,
                                          *certificate);
    EXPECT_TRUE(result.has_value());

    auto certificate_view = m_context->GetCertificateObject(*certificate);
    ASSERT_TRUE(certificate_view.has_value());
    const auto crl_metadata = (*certificate_view)->GetCrlMetadata();
    ASSERT_TRUE(crl_metadata.has_value());
    EXPECT_NE(crl_metadata->fingerprint, (std::array<std::uint8_t, 32U>{}));
    EXPECT_EQ(crl_metadata->issuer_fingerprint, (*certificate_view)->GetFingerprint());
    EXPECT_LT(crl_metadata->this_update, crl_metadata->next_update);

    // Slot state is unaffected - the CRL is session-scoped on the ephemeral cert.
    auto slot_object = m_context->GetCertSlotObject(m_device_slot);
    ASSERT_TRUE(slot_object.has_value());
    EXPECT_FALSE((*slot_object)->HasCrl());
}

TEST_F(CertificateManagementIntegrationTest, ImportsCrlPersistentToSlotAndReflectsInSlotInfo)
{
    const auto crl_path = VectorPath("certificate/basic/certificate.crl.pem");
    if (!FileExists(crl_path))
    {
        GTEST_SKIP() << "certificate.crl.pem not generated - run: "
                        "python generate_certificates.py crl certificate "
                        "--manifest basic/manifest.json";
    }

    const auto crl_bytes = ReadFile(crl_path);
    ASSERT_FALSE(crl_bytes.empty());

    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());
    ASSERT_TRUE(m_management->SaveCertificate(*certificate, m_device_slot).has_value());

    // Persist CRL to the device_cert slot (which holds the root CA).
    auto import_result =
        m_management->ImportCrlToSlot(score::cpp::span<const std::uint8_t>{crl_bytes.data(), crl_bytes.size()},
                                      score::crypto::FormatType::kPem,
                                      m_device_slot);
    ASSERT_TRUE(import_result.has_value());

    auto slot_object = m_context->GetCertSlotObject(m_device_slot);
    ASSERT_TRUE(slot_object.has_value());
    EXPECT_TRUE((*slot_object)->IsOccupied());
    EXPECT_TRUE((*slot_object)->HasCrl());

    auto certificate_view = m_context->GetCertificateObject(m_device_slot);
    ASSERT_TRUE(certificate_view.has_value());
    const auto crl_metadata = (*certificate_view)->GetCrlMetadata();
    ASSERT_TRUE(crl_metadata.has_value());
    EXPECT_NE(crl_metadata->fingerprint, (std::array<std::uint8_t, 32U>{}));
    EXPECT_EQ(crl_metadata->issuer_fingerprint, (*certificate_view)->GetFingerprint());
    EXPECT_LT(crl_metadata->this_update, crl_metadata->next_update);

    ASSERT_TRUE(m_management->DeleteCrl(m_device_slot).has_value());
    auto cleared_slot_object = m_context->GetCertSlotObject(m_device_slot);
    ASSERT_TRUE(cleared_slot_object.has_value());
    EXPECT_FALSE((*cleared_slot_object)->HasCrl());

    auto cleared_certificate_view = m_context->GetCertificateObject(m_device_slot);
    ASSERT_TRUE(cleared_certificate_view.has_value());
    EXPECT_FALSE((*cleared_certificate_view)->GetCrlMetadata().has_value());

    ASSERT_TRUE(m_management->ClearCertificate(m_device_slot).has_value());
}

TEST_F(CertificateManagementIntegrationTest, SaveCertificateWithCrlPropagatesSessionCrlToSlot)
{
    const auto crl_path = VectorPath("certificate/basic/certificate.crl.pem");
    if (!FileExists(crl_path))
    {
        GTEST_SKIP() << "certificate.crl.pem not generated - run: "
                        "python generate_certificates.py crl certificate "
                        "--manifest basic/manifest.json";
    }

    // Parse the root CA into an ephemeral kCertificate resource.
    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());

    // Associate the CRL session-scoped with the ephemeral certificate.
    const auto crl_bytes = ReadFile(crl_path);
    ASSERT_FALSE(crl_bytes.empty());
    ASSERT_TRUE(m_management
                    ->ImportCrl(score::cpp::span<const std::uint8_t>{crl_bytes.data(), crl_bytes.size()},
                                score::crypto::FormatType::kPem,
                                *certificate)
                    .has_value());

    // SaveCertificateWithCrl: daemon copies the ephemeral CRL to the slot
    // without the caller re-passing raw bytes.
    ASSERT_TRUE(m_management->SaveCertificateWithCrl(*certificate, m_device_slot).has_value());

    auto slot_object = m_context->GetCertSlotObject(m_device_slot);
    ASSERT_TRUE(slot_object.has_value());
    EXPECT_TRUE((*slot_object)->IsOccupied());
    EXPECT_TRUE((*slot_object)->HasCrl());

    ASSERT_TRUE(m_management->ClearCertificate(m_device_slot).has_value());
    auto cleared_slot_object = m_context->GetCertSlotObject(m_device_slot);
    ASSERT_TRUE(cleared_slot_object.has_value());
    EXPECT_FALSE((*cleared_slot_object)->IsOccupied());
    EXPECT_FALSE((*cleared_slot_object)->HasCrl());
}

TEST_F(CertificateManagementIntegrationTest, AddLoadedSlotCertificateWithCrlPropagatesPersistentCrl)
{
    const auto crl_path = VectorPath("certificate/basic/certificate.crl.pem");
    if (!FileExists(crl_path))
    {
        GTEST_SKIP() << "certificate.crl.pem not generated - run: "
                        "python generate_certificates.py crl certificate "
                        "--manifest basic/manifest.json";
    }

    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());
    ASSERT_TRUE(m_management->SaveCertificate(*certificate, m_device_slot).has_value());

    const auto crl_bytes = ReadFile(crl_path);
    ASSERT_FALSE(crl_bytes.empty());
    ASSERT_TRUE(m_management
                    ->ImportCrlToSlot(score::cpp::span<const std::uint8_t>{crl_bytes.data(), crl_bytes.size()},
                                      score::crypto::FormatType::kPem,
                                      m_device_slot)
                    .has_value());

    auto loaded = m_management->LoadCertificate(m_device_slot);
    ASSERT_TRUE(loaded.has_value());
    ASSERT_TRUE(m_trust_store_mgmt->AddCertificateToTrustStoreWithCrl(m_mutable_trust_store, *loaded).has_value());

    auto certificate_view = m_context->GetCertificateObject(*loaded);
    ASSERT_TRUE(certificate_view.has_value());
    const auto fingerprint_bytes = (*certificate_view)->GetFingerprint();
    const score::cpp::span<const std::uint8_t> fingerprint{fingerprint_bytes.data(), fingerprint_bytes.size()};

    auto trust_store = m_context->GetTrustStoreObject(m_mutable_trust_store);
    ASSERT_TRUE(trust_store.has_value());
    const auto* member = (*trust_store)->FindMemberByFingerprint(fingerprint);
    ASSERT_NE(member, nullptr);

    auto member_slot = m_context->GetCertSlotObject(member->slot_id);
    ASSERT_TRUE(member_slot.has_value());
    EXPECT_TRUE((*member_slot)->HasCrl());

    ASSERT_TRUE(m_trust_store_mgmt->RemoveCertificateFromTrustStore(m_mutable_trust_store, fingerprint).has_value());
    ASSERT_TRUE(m_management->DeleteCrl(m_device_slot).has_value());
    ASSERT_TRUE(m_management->ClearCertificate(m_device_slot).has_value());
}

TEST_F(CertificateManagementIntegrationTest, RejectsCertificateSlotWriteWithoutPermission)
{
    if (getuid() == 0U)
    {
        GTEST_SKIP() << "Run this test as UID 1000 to exercise the denied writer path";
    }

    auto certificate = ParseBasicCertificate();
    ASSERT_TRUE(certificate.has_value());

    const auto result = m_management->SaveCertificate(*certificate, m_device_slot);
    EXPECT_FALSE(result.has_value());
}

}  // namespace
