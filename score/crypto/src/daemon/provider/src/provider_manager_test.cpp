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

#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"

#include <gtest/gtest.h>
#include <memory>

namespace provider = score::crypto::daemon::provider;
namespace common = score::crypto::daemon::common;

namespace
{
class ConfigurableStubProvider final : public provider::IProvider
{
  public:
    ConfigurableStubProvider(const std::string& name,
                             common::ProviderId id,
                             bool fail_init,
                             common::ProviderCapability capabilities = common::ProviderCapability::kNone)
        : m_name{name}, m_id{id}, m_fail_init{fail_init}, m_capabilities{capabilities}
    {
    }

    bool Initialize(const provider::ProviderInitContext& ctx) override
    {
        if (m_fail_init)
        {
            return false;
        }
        m_initialized = true;
        return true;
    }

    void Shutdown() override
    {
        m_initialized = false;
    }

    [[nodiscard]] bool IsInitialized() const override
    {
        return m_initialized;
    }

    common::ProviderId GetProviderId() const override
    {
        return m_id;
    }
    const common::ProviderName& GetProviderName() const override
    {
        return m_name;
    }

    common::ProviderCapability GetProviderCapabilities() override
    {
        return m_capabilities;
    }

  private:
    std::string m_name;
    common::ProviderId m_id;
    bool m_fail_init;
    common::ProviderCapability m_capabilities;
    bool m_initialized{false};
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
        m_mgr = std::make_shared<provider::ProviderManager>(config.GetProviderInitConfig());

        // Register SW_PROVIDER (ID 0)
        m_mgr->RegisterProvider("SW_PROVIDER",
                                std::make_shared<ConfigurableStubProvider>("SW_PROVIDER", 0, false),
                                common::CryptoProviderType::SOFTWARE);

        // Register HW_PROVIDER (ID 1)
        m_mgr->RegisterProvider("HW_PROVIDER",
                                std::make_shared<ConfigurableStubProvider>("HW_PROVIDER", 1, false),
                                common::CryptoProviderType::HARDWARE);

        m_mgr->Initialize();
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
// Initialization state tracking
// ===========================================================================

TEST(ProviderManagerInitStateTest, FailedProviderRemainsRegisteredButUnavailable)
{
    score::crypto::daemon::config::Config config;
    provider::ProviderManager mgr(config.GetProviderInitConfig());

    auto ok_provider = std::make_shared<ConfigurableStubProvider>("OK_PROVIDER", 0, false);
    auto fail_provider = std::make_shared<ConfigurableStubProvider>("FAIL_PROVIDER", 1, true);

    ASSERT_TRUE(mgr.RegisterProvider("OK_PROVIDER", ok_provider, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(mgr.RegisterProvider("FAIL_PROVIDER", fail_provider, common::CryptoProviderType::HARDWARE));

    // Lookup initializes registered providers on demand. A failed provider
    // remains registered but is unavailable to callers.
    EXPECT_EQ(mgr.GetProvider("OK_PROVIDER"), ok_provider);
    EXPECT_EQ(mgr.GetProvider("FAIL_PROVIDER"), nullptr);
    EXPECT_EQ(mgr.GetProvider(common::CryptoProviderType::SOFTWARE), ok_provider);
    EXPECT_EQ(mgr.GetProvider(common::CryptoProviderType::HARDWARE), nullptr);

    // The registry still knows about both entries even when one is unavailable.
    EXPECT_TRUE(mgr.GetProviderType("OK_PROVIDER").has_value());
    EXPECT_TRUE(mgr.GetProviderType("FAIL_PROVIDER").has_value());
}

// ===========================================================================
// GetProviderForCapability
// ===========================================================================

namespace
{
// SW provider offers crypto + cert; HW provider offers crypto + key management.
provider::ProviderManager::Sptr MakeCapabilityManager()
{
    score::crypto::daemon::config::Config config;
    auto mgr = std::make_shared<provider::ProviderManager>(config.GetProviderInitConfig());

    mgr->RegisterProvider(
        "SW_PROVIDER",
        std::make_shared<ConfigurableStubProvider>(
            "SW_PROVIDER", 0, false,
            common::ProviderCapability::kCrypto | common::ProviderCapability::kCertManagement),
        common::CryptoProviderType::SOFTWARE);

    mgr->RegisterProvider(
        "HW_PROVIDER",
        std::make_shared<ConfigurableStubProvider>(
            "HW_PROVIDER", 1, false,
            common::ProviderCapability::kCrypto | common::ProviderCapability::kKeyManagement),
        common::CryptoProviderType::HARDWARE);

    mgr->Initialize();
    return mgr;
}
}  // namespace

TEST(ProviderManagerCapabilityTest, ReturnsOnlyCapableProvider)
{
    auto mgr = MakeCapabilityManager();
    // Only the SW provider advertises certificate capability.
    auto cert_prov = mgr->GetProviderForCapability(common::ProviderCapability::kCertManagement);
    ASSERT_NE(cert_prov, nullptr);
    EXPECT_EQ(cert_prov->GetProviderName(), "SW_PROVIDER");
}

TEST(ProviderManagerCapabilityTest, PreferenceOrderPicksAmongCapableProviders)
{
    auto mgr = MakeCapabilityManager();
    // Both providers offer crypto; preference decides which is returned.
    auto sw_first = mgr->GetProviderForCapability(
        common::ProviderCapability::kCrypto,
        {common::CryptoProviderType::SOFTWARE, common::CryptoProviderType::HARDWARE});
    ASSERT_NE(sw_first, nullptr);
    EXPECT_EQ(sw_first->GetProviderName(), "SW_PROVIDER");

    auto hw_first = mgr->GetProviderForCapability(
        common::ProviderCapability::kCrypto,
        {common::CryptoProviderType::HARDWARE, common::CryptoProviderType::SOFTWARE});
    ASSERT_NE(hw_first, nullptr);
    EXPECT_EQ(hw_first->GetProviderName(), "HW_PROVIDER");
}

TEST(ProviderManagerCapabilityTest, ReturnsNullWhenNoProviderOffersCapability)
{
    score::crypto::daemon::config::Config config;
    provider::ProviderManager mgr(config.GetProviderInitConfig());
    mgr.RegisterProvider("SW_PROVIDER",
                         std::make_shared<ConfigurableStubProvider>(
                             "SW_PROVIDER", 0, false, common::ProviderCapability::kCrypto),
                         common::CryptoProviderType::SOFTWARE);
    mgr.Initialize();

    EXPECT_EQ(mgr.GetProviderForCapability(common::ProviderCapability::kCertManagement), nullptr);
}

TEST(ProviderManagerCapabilityTest, FallsBackToCapableProviderOutsidePreference)
{
    auto mgr = MakeCapabilityManager();
    // Key management is only on HW; a SOFTWARE-only preference still finds it
    // via the lowest-id capable fallback rather than returning nullptr.
    auto key_prov =
        mgr->GetProviderForCapability(common::ProviderCapability::kKeyManagement,
                                      {common::CryptoProviderType::SOFTWARE});
    ASSERT_NE(key_prov, nullptr);
    EXPECT_EQ(key_prov->GetProviderName(), "HW_PROVIDER");
}

TEST(ProviderManagerCapabilityTest, UninitializedProviderIsNotSelected)
{
    score::crypto::daemon::config::Config config;
    provider::ProviderManager mgr(config.GetProviderInitConfig());
    // Capable on paper, but initialization fails so it must be skipped.
    mgr.RegisterProvider("FAIL_PROVIDER",
                         std::make_shared<ConfigurableStubProvider>(
                             "FAIL_PROVIDER", 0, true, common::ProviderCapability::kCertManagement),
                         common::CryptoProviderType::SOFTWARE);
    mgr.Initialize();

    EXPECT_EQ(mgr.GetProviderForCapability(common::ProviderCapability::kCertManagement), nullptr);
}

// ===========================================================================
// Default provider resolution prefers successfully-initialized providers
// ===========================================================================

TEST(ProviderManagerDefaultResolutionTest, DefaultSkipsFailedPreferredProvider)
{
    score::crypto::daemon::config::Config config;
    provider::ProviderManager mgr(config.GetProviderInitConfig());

    // Preferred category (HARDWARE) is registered but fails to initialize;
    // the SOFTWARE provider initializes successfully.
    mgr.RegisterProvider("HW_PROVIDER",
                         std::make_shared<ConfigurableStubProvider>("HW_PROVIDER", 0, /*fail_init=*/true),
                         common::CryptoProviderType::HARDWARE);
    mgr.RegisterProvider("SW_PROVIDER",
                         std::make_shared<ConfigurableStubProvider>("SW_PROVIDER", 1, /*fail_init=*/false),
                         common::CryptoProviderType::SOFTWARE);
    mgr.Initialize();

    // DEFAULT must resolve to the initialized SOFTWARE provider rather than the
    // failed HARDWARE provider that the preference order would otherwise pick.
    auto def = mgr.GetProvider(common::CryptoProviderType::DEFAULT);
    ASSERT_NE(def, nullptr);
    EXPECT_EQ(def->GetProviderName(), "SW_PROVIDER");
}
