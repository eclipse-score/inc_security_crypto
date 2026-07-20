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

#include "score/crypto/daemon/config/src/flatbuffer_config_parser.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/daemon/key_management/slot/config_driven_slot_catalog.hpp"
#include "score/crypto/daemon/key_management/slot/slot_registry.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include <gtest/gtest.h>

namespace km = score::crypto::daemon::key_management;
namespace config = score::crypto::daemon::config;

class SlotRegistryTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_slot_registry = std::make_shared<km::SlotRegistry>();
    }

    // Helper to initialize with test slot definitions from test config
    void InitializeWithTestConfig()
    {
        config::KeyConfig test_config{};
        auto result = config::FlatBufferConfigParser::ParseFromFile(
            "tests/key_management/config/key_management_test_config.bin", test_config);
        ASSERT_TRUE(result.has_value()) << "Failed to parse test config";

        // Use ConfigDrivenSlotCatalog to properly convert and register slots
        km::ConfigDrivenSlotCatalog catalog{test_config};
        catalog.Load(*m_slot_registry);
    }

    std::shared_ptr<km::SlotRegistry> m_slot_registry;
};

// ============================================================================
// ResolveSlot tests
// ============================================================================

TEST_F(SlotRegistryTest, ResolveSlot_KnownName_ReturnsValidHandle)
{
    InitializeWithTestConfig();

    // UID 0 (root) is in allowed_uids
    auto result = m_slot_registry->ResolveSlot("test/hmac-sha256", 0U);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value().IsValid());
    EXPECT_EQ(result.value().index, 0U);
}

TEST_F(SlotRegistryTest, ResolveSlot_SecondSlot_ReturnsIndex1)
{
    InitializeWithTestConfig();

    auto result = m_slot_registry->ResolveSlot("test/aes-256-cmac", 0U);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().index, 1U);
}

TEST_F(SlotRegistryTest, ResolveSlot_UnknownName_ReturnsError)
{
    InitializeWithTestConfig();

    auto result = m_slot_registry->ResolveSlot("nonexistent/slot", 0U);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
}

TEST_F(SlotRegistryTest, ResolveSlot_DisallowedUid_ReturnsAccessDenied)
{
    InitializeWithTestConfig();

    // UID is extracted from the upper 32 bits of client_id by GetUidFromClientId
    // UID 9999 is NOT in allowed_uids {0, 1000}
    uint64_t client_id = static_cast<uint64_t>(9999U) << 32U;
    auto result = m_slot_registry->ResolveSlot("test/hmac-sha256", client_id);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kAccessDenied);
}

TEST_F(SlotRegistryTest, ResolveSlot_AllowedUid1000_Succeeds)
{
    InitializeWithTestConfig();

    // UID is extracted from the upper 32 bits of client_id by GetUidFromClientId
    uint64_t client_id = static_cast<uint64_t>(1000U) << 32U;
    auto result = m_slot_registry->ResolveSlot("test/hmac-sha256", client_id);
    ASSERT_TRUE(result.has_value());
}

// ============================================================================
// GetConfig tests
// ============================================================================

TEST_F(SlotRegistryTest, GetConfig_ValidHandle_ReturnsConfig)
{
    InitializeWithTestConfig();

    km::SlotHandle handle{0};
    auto config_res = m_slot_registry->GetConfig(handle);
    ASSERT_TRUE(config_res.has_value());
    EXPECT_EQ(config_res.value()->slot_name, "test/hmac-sha256");
    EXPECT_EQ(config_res.value()->algorithm, "HMAC-SHA256");
    // provider_ids is empty until ResolveProviderIds() is called at daemon startup
    EXPECT_EQ(config_res.value()->GetPrimaryProviderId(), score::crypto::daemon::common::kInvalidProviderId);
}

TEST_F(SlotRegistryTest, GetConfig_InvalidHandle_ReturnsError)
{
    InitializeWithTestConfig();

    km::SlotHandle handle{};  // UINT32_MAX = invalid
    auto config_res = m_slot_registry->GetConfig(handle);
    EXPECT_FALSE(config_res.has_value());
    EXPECT_EQ(config_res.error(), score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
}

// ============================================================================
// RegisterSlot / GetSlotCount tests
// ============================================================================

TEST_F(SlotRegistryTest, GetSlotCount_AfterInit_ReturnsFiveSlots)
{
    InitializeWithTestConfig();
    // Compiled catalog has 3 slots: test/hmac-sha256, test/aes-256-cmac, test/pkcs11-hmac-sha256
    EXPECT_EQ(m_slot_registry->GetSlotCount(), 3U);
}
