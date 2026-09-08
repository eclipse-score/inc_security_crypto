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

#include "score/crypto/src/daemon/cert_management/slot/config_driven_slot_catalog.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/tests/test_environment.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/config_driven_trust_store_catalog.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <utility>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;
namespace storage = score::crypto::daemon::common::storage;
namespace openssl = score::crypto::daemon::provider::score_provider::openssl;

// ---------------------------------------------------------------------------
// Helper — build a ClientId from explicit pid/uid fields.
// Mirrors the union layout used by GetUidFromClientId in control_protocol.h.
// ---------------------------------------------------------------------------
score::crypto::daemon::data_manager::ClientId MakeClientId(std::uint32_t pid, std::uint32_t uid)
{
    union
    {
        score::crypto::daemon::data_manager::ClientId id;
        struct
        {
            std::uint32_t process_id;
            std::uint32_t user_id;
        } parts;
    } value{0U};
    value.parts.process_id = pid;
    value.parts.user_id = uid;
    return value.id;
}

class CertificateManagementIntegrationTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_directory = cert::test::TempDirectory("score_cert_management_integration");
        std::filesystem::remove_all(m_directory);
        std::filesystem::create_directories(m_directory);
        m_descriptor_path = m_directory / "device_root.kv";
        m_certificate_path = m_directory / "device_root.pem";
        m_trust_store_path = m_directory / "tls_roots.kv";

        ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/certificate.pem",
                                               m_certificate_path,
                                               std::filesystem::copy_options::overwrite_existing));
        ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/certificate_updated.pem",
                                               m_directory / "certificate_updated.pem",
                                               std::filesystem::copy_options::overwrite_existing));

        storage::DeploymentDescriptor slot_desc;
        slot_desc.Set("certificate", "cert_path", m_certificate_path.string());
        slot_desc.Set("certificate", "cert_format", "pem");
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(m_descriptor_path.string(), slot_desc).has_value());

        ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/basic/trust_store.kv",
                                               m_trust_store_path,
                                               std::filesystem::copy_options::overwrite_existing));

        config::CertificateConfig::CertSlotEntry slot;
        slot.slot_name = "device/root-ca";
        slot.storage_backend = "DEFAULT";
        slot.deployment_path = m_descriptor_path.string();
        slot.deployment_format = "kv";
        slot.allowed_uids = {0U};
        slot.allowed_write_uids = {0U};
        m_config.AddSlotEntry(std::move(slot));

        config::CertificateConfig::TrustStoreEntry trust_store;
        trust_store.store_name = "tls-roots";
        trust_store.members.push_back(
            {"device/root-ca", config::CertificateConfig::TrustStoreMemberKind::kSharedStatic});
        trust_store.deployment_path = m_trust_store_path.string();
        trust_store.deployment_format = "kv";
        trust_store.allowed_uids = {0U};
        trust_store.allowed_write_uids = {0U};
        m_config.AddTrustStoreEntry(std::move(trust_store));
        m_config.AddAppCertSlotEntry({0U, "device_certificate", "device/root-ca"});
        m_config.AddAppTrustStoreEntry({0U, "tls_roots", "tls-roots"});

        m_parser = std::make_shared<openssl::OpenSslCertParser>(1U);
        m_slot_registry = std::make_shared<cert::CertSlotRegistry>();
        cert::ConfigDrivenSlotCatalog slot_catalog{m_config};
        slot_catalog.Load(*m_slot_registry);

        m_trust_store_manager = std::make_shared<cert::TrustStoreManager>();
        m_slot_manager = std::make_shared<cert::CertSlotManager>(m_slot_registry, [this](const cert::CertSlotConfig&) {
            return std::make_shared<cert::FileBackedSlotHandler>(m_parser);
        });
        cert::ConfigDrivenTrustStoreCatalog trust_store_catalog{m_config};
        trust_store_catalog.Load(*m_trust_store_manager, m_slot_registry, m_slot_manager);
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(m_directory, error);
    }

    std::string ReadFile(const std::filesystem::path& path) const
    {
        std::ifstream input{path};
        return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    }

    std::filesystem::path m_directory;
    std::filesystem::path m_descriptor_path;
    std::filesystem::path m_certificate_path;
    std::filesystem::path m_trust_store_path;
    config::CertificateConfig m_config;
    std::shared_ptr<openssl::OpenSslCertParser> m_parser;
    cert::CertSlotRegistry::Sptr m_slot_registry;
    cert::CertSlotManager::Sptr m_slot_manager;
    cert::TrustStoreManager::Sptr m_trust_store_manager;
};

TEST_F(CertificateManagementIntegrationTest, LoadsPersistsUpdatesAndInvalidatesTrustStoreAnchor)
{
    const auto slot = m_slot_registry->ResolveAppResource("device_certificate", 0U);
    ASSERT_TRUE(slot.has_value());
    const auto slot_config = m_slot_registry->GetConfig(*slot);
    ASSERT_TRUE(slot_config.has_value());

    auto slot_handler = std::make_shared<cert::FileBackedSlotHandler>(m_parser);
    const auto initial = slot_handler->LoadCertificate(**slot_config);
    ASSERT_TRUE(initial.has_value());
    EXPECT_EQ((*initial)->GetSubject(), "CN=cert-management-test,O=Eclipse");
    EXPECT_TRUE((*initial)->IsCA());

    auto trust_store_handle = m_trust_store_manager->ResolveAppResource("tls_roots", 0U);
    ASSERT_TRUE(trust_store_handle.has_value());
    auto trust_store = m_trust_store_manager->GetStore(*trust_store_handle);
    ASSERT_NE(trust_store, nullptr);

    const auto initial_anchors = trust_store->GetAnchors();
    ASSERT_TRUE(initial_anchors.has_value());
    ASSERT_EQ(initial_anchors->size(), 1U);
    EXPECT_EQ((*initial_anchors)[0]->GetSubject(), "CN=cert-management-test,O=Eclipse");

    const auto updated_pem = ReadFile(m_directory / "certificate_updated.pem");
    ASSERT_FALSE(updated_pem.empty());
    const auto updated = m_parser->ParseCertificate(
        reinterpret_cast<const std::uint8_t*>(updated_pem.data()), updated_pem.size(), score::crypto::FormatType::kPem);
    ASSERT_TRUE(updated.has_value());
    ASSERT_TRUE(slot_handler->StoreCertificate(**slot_config, **updated).has_value());

    const auto descriptor = cert::DeploymentLoader::Load(m_descriptor_path.string(), "kv");
    ASSERT_TRUE(descriptor.has_value());
    EXPECT_EQ(descriptor->Get("certificate_metadata", "subject"), "CN=cert-management-updated,O=Eclipse");
    EXPECT_EQ(descriptor->Get("certificate_metadata", "issuer"), "CN=cert-management-updated,O=Eclipse");
    EXPECT_EQ(descriptor->Get("certificate_metadata", "is_ca"), "true");

    m_trust_store_manager->NotifySlotChanged(*trust_store_handle, *slot);
    const auto updated_anchors = trust_store->GetAnchors();
    ASSERT_TRUE(updated_anchors.has_value());
    ASSERT_EQ(updated_anchors->size(), 1U);
    EXPECT_EQ((*updated_anchors)[0]->GetSubject(), "CN=cert-management-updated,O=Eclipse");
    EXPECT_FALSE(std::equal((*updated_anchors)[0]->GetFingerprint().begin(),
                            (*updated_anchors)[0]->GetFingerprint().end(),
                            (*initial_anchors)[0]->GetFingerprint().begin(),
                            (*initial_anchors)[0]->GetFingerprint().end()));
}
// ===========================================================================
// Access control — CertSlotManager
//
// The fixture configures the slot with allowed_write_uids={0}, so:
//   MakeClientId(pid, 0)  → UID 0 → write authorized
//   MakeClientId(pid, 99) → UID 99 → write denied
// Reads are unconditionally permitted regardless of UID.
// ===========================================================================

// Any UID can load a certificate; reads are unrestricted after resource resolution.
TEST_F(CertificateManagementIntegrationTest, LoadCertificate_IsUnrestrictedForAnyUid)
{
    const auto slot = m_slot_registry->ResolveAppResource("device_certificate", 0U);
    ASSERT_TRUE(slot.has_value());

    EXPECT_TRUE(m_slot_manager->LoadCertificate(*slot, MakeClientId(1U, 0U)).has_value());
    EXPECT_TRUE(m_slot_manager->LoadCertificate(*slot, MakeClientId(2U, 99U)).has_value());
}

// StoreCertificate succeeds when the caller's UID is in allowed_write_uids.
TEST_F(CertificateManagementIntegrationTest, StoreCertificate_GrantedForAuthorizedUid)
{
    const auto slot = m_slot_registry->ResolveAppResource("device_certificate", 0U);
    ASSERT_TRUE(slot.has_value());
    const auto cert = m_slot_manager->LoadCertificate(*slot, MakeClientId(1U, 0U));
    ASSERT_TRUE(cert.has_value());

    EXPECT_TRUE(m_slot_manager->StoreCertificate(*slot, MakeClientId(1U, 0U), **cert).has_value());
}

// StoreCertificate is denied when the caller's UID is not in allowed_write_uids.
TEST_F(CertificateManagementIntegrationTest, StoreCertificate_DeniedForUnauthorizedUid)
{
    const auto slot = m_slot_registry->ResolveAppResource("device_certificate", 0U);
    ASSERT_TRUE(slot.has_value());
    const auto cert = m_slot_manager->LoadCertificate(*slot, MakeClientId(1U, 0U));
    ASSERT_TRUE(cert.has_value());

    const auto result = m_slot_manager->StoreCertificate(*slot, MakeClientId(2U, 99U), **cert);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kAccessDenied);
}

// ClearSlot is denied when the caller's UID is not in allowed_write_uids.
TEST_F(CertificateManagementIntegrationTest, ClearSlot_DeniedForUnauthorizedUid)
{
    const auto slot = m_slot_registry->ResolveAppResource("device_certificate", 0U);
    ASSERT_TRUE(slot.has_value());

    const auto result = m_slot_manager->ClearSlot(*slot, MakeClientId(2U, 99U));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kAccessDenied);
}

// A slot with an empty allowed_write_uids list denies writes from every UID,
// including UID 0. This is the default-deny invariant.
TEST_F(CertificateManagementIntegrationTest, WritesDeniedWhenAllowedWriteUidsIsEmpty)
{
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    cert::CertSlotConfig cfg;
    cfg.slot_name = "test/locked-slot";
    // access_policy.allowed_write_uids left empty — default-deny for all UIDs.
    const auto locked_slot = registry->RegisterSlot(cfg);

    auto handler = std::make_shared<cert::FileBackedSlotHandler>(m_parser);
    cert::CertSlotManager locked_mgr{registry, [&handler](const cert::CertSlotConfig&) {
                                         return handler;
                                     }};

    const auto src_slot = m_slot_registry->ResolveAppResource("device_certificate", 0U);
    ASSERT_TRUE(src_slot.has_value());
    const auto cert = m_slot_manager->LoadCertificate(*src_slot, MakeClientId(1U, 0U));
    ASSERT_TRUE(cert.has_value());

    // Even UID 0 is denied because the allowlist is empty.
    const auto result = locked_mgr.StoreCertificate(locked_slot, MakeClientId(1U, 0U), **cert);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kAccessDenied);
}

// ===========================================================================
// Access control — TrustStoreManager
//
// The fixture configures the trust store with allowed_write_uids={0}.
// TrustStoreManager checks CheckTrustStoreWritePermission internally before
// any membership mutation.
// ===========================================================================

// Trust-store membership mutations are denied for UIDs not in the store's
// allowed_write_uids, regardless of whether the member slot is valid.
TEST_F(CertificateManagementIntegrationTest, TrustStoreMutation_DeniedForUnauthorizedUid)
{
    const auto trust_store = m_trust_store_manager->ResolveAppResource("tls_roots", 0U);
    ASSERT_TRUE(trust_store.has_value());
    const auto slot = m_slot_registry->ResolveAppResource("device_certificate", 0U);
    ASSERT_TRUE(slot.has_value());

    // UID 99 is not in the trust store's allowed_write_uids={0}.
    const auto enable_result = m_trust_store_manager->EnableMember(*trust_store, *slot, MakeClientId(2U, 99U));
    ASSERT_FALSE(enable_result.has_value());
    EXPECT_EQ(enable_result.error(), common::DaemonErrorCode::kAccessDenied);

    const auto disable_result = m_trust_store_manager->DisableMember(*trust_store, *slot, MakeClientId(2U, 99U));
    ASSERT_FALSE(disable_result.has_value());
    EXPECT_EQ(disable_result.error(), common::DaemonErrorCode::kAccessDenied);
}

}  // namespace
