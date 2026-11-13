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

// Integration test for the certificate management configuration pipeline.
//
// Tests the full config-to-registry path:
//   binary FlatBuffer file → FlatBufferConfigParser → CertificateConfig
//              → ConfigDrivenSlotCatalog → CertSlotRegistry
//              → ConfigDrivenTrustStoreCatalog → TrustStoreManager
//
// Mirrors score/crypto/tests/key_management/test_key_config_manager.cpp for
// the key management configuration pipeline. The source JSON is compiled to
// a binary FlatBuffer by the Bazel config target.

#include "score/crypto/src/daemon/cert_management/slot/config_driven_slot_catalog.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/config_driven_trust_store_catalog.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/config/src/flatbuffer_config_parser.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>

namespace cert = score::crypto::daemon::cert_management;
namespace config = score::crypto::daemon::config;
using score::crypto::daemon::common::DaemonErrorCode;

static constexpr std::string_view kConfigPath =
    "score/crypto/tests/cert_management/config/cert_management_test_config.bin";

// ---------------------------------------------------------------------------
// Fixture - parses the binary config and loads it into registry + trust store
// ---------------------------------------------------------------------------

class CertConfigManagerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto parse_result = config::FlatBufferConfigParser::ParseCertConfigFromFile(kConfigPath, m_cert_config);
        ASSERT_TRUE(parse_result.has_value()) << "Failed to parse cert config from: " << kConfigPath;

        m_registry = std::make_shared<cert::CertSlotRegistry>();
        cert::ConfigDrivenSlotCatalog slot_catalog{m_cert_config};
        slot_catalog.Load(*m_registry);

        cert::ConfigDrivenTrustStoreCatalog ts_catalog{m_cert_config};
        // Slot handler factory is null — no cert file I/O, only registration.
        ts_catalog.Load(m_trust_store_manager, m_registry, /*factory=*/{});
    }

    config::CertificateConfig m_cert_config;
    std::shared_ptr<cert::CertSlotRegistry> m_registry;
    cert::TrustStoreManager m_trust_store_manager;
};

// ---------------------------------------------------------------------------
// Config parsing tests
// ---------------------------------------------------------------------------

TEST_F(CertConfigManagerTest, ParsedConfig_HasExpectedSlotCount)
{
    EXPECT_EQ(m_cert_config.GetSlotEntries().size(), 3U);
}

TEST_F(CertConfigManagerTest, ParsedConfig_HasExpectedTrustStoreCount)
{
    EXPECT_EQ(m_cert_config.GetTrustStoreEntries().size(), 2U);
}

TEST_F(CertConfigManagerTest, ParsedConfig_HasExpectedAppCertSlotMappings)
{
    // uid=0 has 2 mappings, uid=1000 has 1
    EXPECT_EQ(m_cert_config.GetAppCertSlotEntries().size(), 3U);
}

TEST_F(CertConfigManagerTest, ParsedConfig_HasExpectedAppTrustStoreMappings)
{
    EXPECT_EQ(m_cert_config.GetAppTrustStoreEntries().size(), 3U);
}

TEST_F(CertConfigManagerTest, ParsedConfig_CertSlotEntry_AllFieldsCorrect)
{
    const auto& slots = m_cert_config.GetSlotEntries();
    ASSERT_GE(slots.size(), 1U);
    EXPECT_EQ(slots[0].slot_name, "test/root-ca");
    EXPECT_EQ(slots[0].storage_backend, "DEFAULT");
    EXPECT_EQ(slots[0].deployment_format, "kv");
    EXPECT_EQ(slots[0].integrity_policy, "disabled");
    ASSERT_EQ(slots[0].allowed_uids.size(), 2U);
    EXPECT_EQ(slots[0].allowed_uids[0], 0U);
    EXPECT_EQ(slots[0].allowed_uids[1], 1000U);
    ASSERT_EQ(slots[0].allowed_write_uids.size(), 1U);
    EXPECT_EQ(slots[0].allowed_write_uids[0], 0U);
}

TEST_F(CertConfigManagerTest, ParsedConfig_TrustStoreEntry_MembersCorrect)
{
    const auto& stores = m_cert_config.GetTrustStoreEntries();
    ASSERT_GE(stores.size(), 1U);
    EXPECT_EQ(stores[0].store_name, "test/tls-roots");
    ASSERT_EQ(stores[0].members.size(), 2U);
    EXPECT_EQ(stores[0].members[0].slot_name, "test/root-ca");
    EXPECT_EQ(stores[0].members[0].kind, config::CertificateConfig::TrustStoreMemberKind::kSharedStatic);
    EXPECT_EQ(stores[0].members[1].slot_name, "test/exclusive-slot");
    EXPECT_EQ(stores[0].members[1].kind, config::CertificateConfig::TrustStoreMemberKind::kExclusiveMutable);
}

TEST_F(CertConfigManagerTest, ParsedConfig_TrustStoreEntry_ConditionalExternalMember)
{
    const auto& stores = m_cert_config.GetTrustStoreEntries();
    ASSERT_GE(stores.size(), 2U);
    EXPECT_EQ(stores[1].store_name, "test/ota-roots");
    ASSERT_EQ(stores[1].members.size(), 1U);
    EXPECT_EQ(stores[1].members[0].kind, config::CertificateConfig::TrustStoreMemberKind::kConditionalExternal);
    EXPECT_EQ(stores[1].conditional_slot_initialization,
              config::CertificateConfig::ConditionalSlotInitialization::kEnableAndAcceptCurrent);
}

// ---------------------------------------------------------------------------
// CertSlotRegistry tests (after ConfigDrivenSlotCatalog load)
// ---------------------------------------------------------------------------

TEST_F(CertConfigManagerTest, Registry_SlotCount_MatchesConfig)
{
    EXPECT_EQ(m_registry->GetSlotCount(), 3U);
}

TEST_F(CertConfigManagerTest, Registry_KnownSlotName_ReturnsValidHandle)
{
    auto result = m_registry->ResolveSlotInternal("test/root-ca");
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->IsValid());
}

TEST_F(CertConfigManagerTest, Registry_AllThreeSlots_AreResolvable)
{
    for (const auto* name : {"test/root-ca", "test/device-cert", "test/exclusive-slot"})
    {
        auto result = m_registry->ResolveSlotInternal(name);
        ASSERT_TRUE(result.has_value()) << "Slot not found: " << name;
        EXPECT_TRUE(result->IsValid()) << "Invalid handle for slot: " << name;
    }
}

TEST_F(CertConfigManagerTest, Registry_UnknownSlotName_ReturnsError)
{
    auto result = m_registry->ResolveSlotInternal("test/nonexistent");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidResourceId);
}

TEST_F(CertConfigManagerTest, Registry_SlotConfig_ContainsExpectedDeploymentPath)
{
    auto handle = m_registry->ResolveSlotInternal("test/device-cert");
    ASSERT_TRUE(handle.has_value());
    auto cfg = m_registry->GetConfig(*handle);
    ASSERT_TRUE(cfg.has_value());
    EXPECT_EQ((*cfg)->slot_name, "test/device-cert");
    EXPECT_EQ((*cfg)->deployment_path, "/opt/crypto/deploy/certs/device_cert.kv");
}

TEST_F(CertConfigManagerTest, Registry_AppResourceMappings_Populated)
{
    // uid=0, "device_cert" → "test/device-cert"
    auto result = m_registry->ResolveAppResource("device_cert", /*client_id=*/0U);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->IsValid());
}

TEST_F(CertConfigManagerTest, Registry_UnknownAppResource_ReturnsError)
{
    auto result = m_registry->ResolveAppResource("nonexistent", 0U);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidResourceId);
}

// ---------------------------------------------------------------------------
// TrustStoreManager tests (after ConfigDrivenTrustStoreCatalog load)
// ---------------------------------------------------------------------------

TEST_F(CertConfigManagerTest, TrustStoreManager_KnownStoreName_ReturnsValidHandle)
{
    const auto handle = m_trust_store_manager.ResolveByName("test/tls-roots");
    EXPECT_TRUE(handle.IsValid());
}

TEST_F(CertConfigManagerTest, TrustStoreManager_BothStores_AreResolvable)
{
    EXPECT_TRUE(m_trust_store_manager.ResolveByName("test/tls-roots").IsValid());
    EXPECT_TRUE(m_trust_store_manager.ResolveByName("test/ota-roots").IsValid());
}

TEST_F(CertConfigManagerTest, TrustStoreManager_UnknownStoreName_ReturnsInvalidHandle)
{
    const auto handle = m_trust_store_manager.ResolveByName("test/nonexistent");
    EXPECT_FALSE(handle.IsValid());
}

TEST_F(CertConfigManagerTest, TrustStoreManager_StoreConfig_HasExpectedMemberCount)
{
    const auto handle = m_trust_store_manager.ResolveByName("test/tls-roots");
    ASSERT_TRUE(handle.IsValid());
    const auto* cfg = m_trust_store_manager.GetStoreConfig(handle);
    ASSERT_NE(cfg, nullptr);
    EXPECT_EQ(cfg->members.size(), 2U);
}

TEST_F(CertConfigManagerTest, TrustStoreManager_SlotMembership_RootCaInBothStores)
{
    const auto root_handle = m_registry->ResolveSlotInternal("test/root-ca");
    ASSERT_TRUE(root_handle.has_value());

    const auto memberships = m_trust_store_manager.GetMembershipsForSlot(*root_handle);
    // "test/root-ca" is a member of both tls-roots and ota-roots
    EXPECT_EQ(memberships.size(), 2U);
}

TEST_F(CertConfigManagerTest, TrustStoreManager_ExclusiveSlot_MemberOfOnlyOneStore)
{
    const auto excl_handle = m_registry->ResolveSlotInternal("test/exclusive-slot");
    ASSERT_TRUE(excl_handle.has_value());

    const auto memberships = m_trust_store_manager.GetMembershipsForSlot(*excl_handle);
    EXPECT_EQ(memberships.size(), 1U);
}
