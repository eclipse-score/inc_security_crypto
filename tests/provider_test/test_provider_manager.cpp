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

/// @file test_provider_manager.cpp
/// @brief Unit tests for ProviderManager::GetProviderType and
///        IsProviderCompatibleWithType.

#include "score/crypto/daemon/config/inc/config.hpp"
#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/provider/handler/context_data_node.hpp"
#include "score/crypto/daemon/provider/i_provider.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"

#include <gtest/gtest.h>
#include <memory>

namespace provider = score::crypto::daemon::provider;
namespace common = score::crypto::daemon::common;

// ---------------------------------------------------------------------------
// Minimal IProvider stub — satisfies the pure-virtual interface so
// RegisterProvider can accept non-null instances.
// ---------------------------------------------------------------------------
namespace
{
class StubProvider final : public provider::IProvider
{
  public:
    explicit StubProvider(const std::string& name, common::ProviderId id) : m_name{name}, m_id{id} {}

    bool Initialize(const provider::ProviderInitContext& ctx) override
    {
        return true;
    }

    void Shutdown() override {}

    common::ProviderId GetProviderId() const override
    {
        return m_id;
    }

    const common::ProviderName& GetProviderName() const override
    {
        return m_name;
    }

  private:
    std::string m_name;
    common::ProviderId m_id;
};
}  // namespace

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------
class ProviderManagerTypeTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        score::crypto::daemon::config::Config config;
        m_mgr = std::make_shared<provider::ProviderManager>(config);

        // Register SW_PROVIDER (ID 0)
        m_mgr->RegisterProvider(
            "SW_PROVIDER", std::make_shared<StubProvider>("SW_PROVIDER", 0), common::CryptoProviderType::SOFTWARE);

        // Register HW_PROVIDER (ID 1)
        m_mgr->RegisterProvider(
            "HW_PROVIDER", std::make_shared<StubProvider>("HW_PROVIDER", 1), common::CryptoProviderType::HARDWARE);
    }

    provider::ProviderManager::Sptr m_mgr;
};

// ===========================================================================
// GetProviderType
// ===========================================================================

TEST_F(ProviderManagerTypeTest, GetProviderType_KnownSoftware)
{
    auto type = m_mgr->GetProviderType("SW_PROVIDER");
    ASSERT_TRUE(type.has_value());
    EXPECT_EQ(type.value(), common::CryptoProviderType::SOFTWARE);
}

TEST_F(ProviderManagerTypeTest, GetProviderType_KnownHardware)
{
    auto type = m_mgr->GetProviderType("HW_PROVIDER");
    ASSERT_TRUE(type.has_value());
    EXPECT_EQ(type.value(), common::CryptoProviderType::HARDWARE);
}

TEST_F(ProviderManagerTypeTest, GetProviderType_UnknownReturnsNullopt)
{
    auto type = m_mgr->GetProviderType("NONEXISTENT");
    EXPECT_FALSE(type.has_value());
}

// ===========================================================================
// IsProviderCompatibleWithType
// ===========================================================================

TEST_F(ProviderManagerTypeTest, DefaultMatchesAnyProvider)
{
    EXPECT_TRUE(m_mgr->IsProviderCompatibleWithType(0, common::CryptoProviderType::DEFAULT));  // SW_PROVIDER
    EXPECT_TRUE(m_mgr->IsProviderCompatibleWithType(1, common::CryptoProviderType::DEFAULT));  // HW_PROVIDER
}

TEST_F(ProviderManagerTypeTest, SoftwareMatchesSoftware)
{
    EXPECT_TRUE(m_mgr->IsProviderCompatibleWithType(0, common::CryptoProviderType::SOFTWARE));  // SW_PROVIDER
}

TEST_F(ProviderManagerTypeTest, HardwareMatchesHardware)
{
    EXPECT_TRUE(m_mgr->IsProviderCompatibleWithType(1, common::CryptoProviderType::HARDWARE));  // HW_PROVIDER
}

TEST_F(ProviderManagerTypeTest, SoftwareDoesNotMatchHardware)
{
    EXPECT_FALSE(m_mgr->IsProviderCompatibleWithType(0, common::CryptoProviderType::HARDWARE));  // SW_PROVIDER
}

TEST_F(ProviderManagerTypeTest, HardwareDoesNotMatchSoftware)
{
    EXPECT_FALSE(m_mgr->IsProviderCompatibleWithType(1, common::CryptoProviderType::SOFTWARE));  // HW_PROVIDER
}

TEST_F(ProviderManagerTypeTest, UnknownProviderReturnsFalse)
{
    EXPECT_FALSE(
        m_mgr->IsProviderCompatibleWithType(999, common::CryptoProviderType::SOFTWARE));  // Invalid provider ID
}

// ===========================================================================
// ContextDataNode GetNodeType
// ===========================================================================

namespace dm = score::crypto::daemon::data_manager;
namespace handler_ns = score::crypto::daemon::provider::handler;

TEST(ContextDataNodeTypeTest, GetNodeType_ReturnsContext)
{
    // ContextDataNode requires a handler; pass nullptr for this type-only test.
    handler_ns::ContextDataNode node(nullptr, "HMAC-SHA256");
    EXPECT_EQ(node.GetNodeType(), dm::DataNodeType::kContext);
}
