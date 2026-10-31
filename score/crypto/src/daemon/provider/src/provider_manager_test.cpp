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
#include <cstddef>
#include <memory>
#include <string>
#include <utility>

namespace provider = score::crypto::daemon::provider;
namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;

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
        (void)ctx;
        ++m_initialization_attempts;
        if (m_fail_init)
        {
            return false;
        }
        m_initialized = true;
        return true;
    }

    void Shutdown() override
    {
        ++m_shutdown_calls;
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

    void SetInitializationFailure(bool fail_init)
    {
        m_fail_init = fail_init;
    }

    std::size_t GetInitializationAttempts() const noexcept
    {
        return m_initialization_attempts;
    }

    std::size_t GetShutdownCalls() const noexcept
    {
        return m_shutdown_calls;
    }

  private:
    std::string m_name;
    common::ProviderId m_id;
    bool m_fail_init;
    common::ProviderCapability m_capabilities;
    bool m_initialized{false};
    std::size_t m_initialization_attempts{0U};
    std::size_t m_shutdown_calls{0U};
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
        m_mgr = std::make_shared<provider::ProviderManager>(config.GetProviderRoutingPolicy());

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
    provider::ProviderManager mgr(config.GetProviderRoutingPolicy());

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
    auto mgr = std::make_shared<provider::ProviderManager>(config.GetProviderRoutingPolicy());

    mgr->RegisterProvider(
        "SW_PROVIDER",
        std::make_shared<ConfigurableStubProvider>(
            "SW_PROVIDER", 0, false, common::ProviderCapability::kCrypto | common::ProviderCapability::kCertManagement),
        common::CryptoProviderType::SOFTWARE);

    mgr->RegisterProvider(
        "HW_PROVIDER",
        std::make_shared<ConfigurableStubProvider>(
            "HW_PROVIDER", 1, false, common::ProviderCapability::kCrypto | common::ProviderCapability::kKeyManagement),
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
    auto sw_first =
        mgr->GetProviderForCapability(common::ProviderCapability::kCrypto,
                                      {common::CryptoProviderType::SOFTWARE, common::CryptoProviderType::HARDWARE});
    ASSERT_NE(sw_first, nullptr);
    EXPECT_EQ(sw_first->GetProviderName(), "SW_PROVIDER");

    auto hw_first =
        mgr->GetProviderForCapability(common::ProviderCapability::kCrypto,
                                      {common::CryptoProviderType::HARDWARE, common::CryptoProviderType::SOFTWARE});
    ASSERT_NE(hw_first, nullptr);
    EXPECT_EQ(hw_first->GetProviderName(), "HW_PROVIDER");
}

TEST(ProviderManagerCapabilityTest, ReturnsNullWhenNoProviderOffersCapability)
{
    score::crypto::daemon::config::Config config;
    provider::ProviderManager mgr(config.GetProviderRoutingPolicy());
    mgr.RegisterProvider(
        "SW_PROVIDER",
        std::make_shared<ConfigurableStubProvider>("SW_PROVIDER", 0, false, common::ProviderCapability::kCrypto),
        common::CryptoProviderType::SOFTWARE);
    mgr.Initialize();

    EXPECT_EQ(mgr.GetProviderForCapability(common::ProviderCapability::kCertManagement), nullptr);
}

TEST(ProviderManagerCapabilityTest, NoneCapabilityNeverSelectsAProvider)
{
    auto mgr = MakeCapabilityManager();

    EXPECT_EQ(mgr->GetProviderForCapability(common::ProviderCapability::kNone), nullptr);
}

TEST(ProviderManagerCapabilityTest, FallsBackToCapableProviderOutsidePreference)
{
    auto mgr = MakeCapabilityManager();
    // Key management is only on HW; a SOFTWARE-only preference still finds it
    // via the lowest-id capable fallback rather than returning nullptr.
    auto key_prov = mgr->GetProviderForCapability(common::ProviderCapability::kKeyManagement,
                                                  {common::CryptoProviderType::SOFTWARE});
    ASSERT_NE(key_prov, nullptr);
    EXPECT_EQ(key_prov->GetProviderName(), "HW_PROVIDER");
}

TEST(ProviderManagerCapabilityTest, UninitializedProviderIsNotSelected)
{
    score::crypto::daemon::config::Config config;
    provider::ProviderManager mgr(config.GetProviderRoutingPolicy());
    // Capable on paper, but initialization fails so it must be skipped.
    mgr.RegisterProvider("FAIL_PROVIDER",
                         std::make_shared<ConfigurableStubProvider>(
                             "FAIL_PROVIDER", 0, true, common::ProviderCapability::kCertManagement),
                         common::CryptoProviderType::SOFTWARE);
    mgr.Initialize();

    EXPECT_EQ(mgr.GetProviderForCapability(common::ProviderCapability::kCertManagement), nullptr);
}

TEST(ProviderManagerCapabilityTest, RoutingPolicyControlsCapabilityPreference)
{
    config::ProviderRoutingPolicy routing_policy;
    routing_policy.SetCapabilityRouting(
        common::ProviderCapability::kCrypto,
        config::CapabilityRoutingRule{{common::CryptoProviderType::SOFTWARE, common::CryptoProviderType::HARDWARE},
                                      true});
    provider::ProviderManager mgr(std::move(routing_policy));
    mgr.RegisterProvider(
        "HW_PROVIDER",
        std::make_shared<ConfigurableStubProvider>("HW_PROVIDER", 0, false, common::ProviderCapability::kCrypto),
        common::CryptoProviderType::HARDWARE);
    mgr.RegisterProvider(
        "SW_PROVIDER",
        std::make_shared<ConfigurableStubProvider>("SW_PROVIDER", 1, false, common::ProviderCapability::kCrypto),
        common::CryptoProviderType::SOFTWARE);
    ASSERT_TRUE(mgr.Initialize());

    auto selected = mgr.GetProviderForCapability(common::ProviderCapability::kCrypto);
    ASSERT_NE(selected, nullptr);
    EXPECT_EQ(selected->GetProviderName(), "SW_PROVIDER");
}

TEST(ProviderManagerCapabilityTest, ExplicitCategoryDefaultIsPreferredWithinCapabilityCategory)
{
    config::ProviderRoutingPolicy routing_policy;
    routing_policy.SetDefaultProviderForType(common::CryptoProviderType::SOFTWARE, "SECOND_SW");
    routing_policy.SetCapabilityRouting(common::ProviderCapability::kCrypto,
                                        config::CapabilityRoutingRule{{common::CryptoProviderType::SOFTWARE}, false});
    provider::ProviderManager mgr(std::move(routing_policy));
    auto first = std::make_shared<ConfigurableStubProvider>("FIRST_SW", 0, false, common::ProviderCapability::kCrypto);
    auto second =
        std::make_shared<ConfigurableStubProvider>("SECOND_SW", 1, false, common::ProviderCapability::kCrypto);
    ASSERT_TRUE(mgr.RegisterProvider("FIRST_SW", first, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(mgr.RegisterProvider("SECOND_SW", second, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(mgr.Initialize());

    EXPECT_EQ(mgr.GetProviderForCapability(common::ProviderCapability::kCrypto), second);
}

TEST(ProviderManagerCapabilityTest, RoutingPolicyCanDisableUnlistedCapabilityFallback)
{
    config::ProviderRoutingPolicy routing_policy;
    routing_policy.SetCapabilityRouting(common::ProviderCapability::kCertManagement,
                                        config::CapabilityRoutingRule{{common::CryptoProviderType::SOFTWARE}, false});
    provider::ProviderManager mgr(std::move(routing_policy));
    mgr.RegisterProvider("HW_PROVIDER",
                         std::make_shared<ConfigurableStubProvider>(
                             "HW_PROVIDER", 0, false, common::ProviderCapability::kCertManagement),
                         common::CryptoProviderType::HARDWARE);
    ASSERT_TRUE(mgr.Initialize());

    EXPECT_EQ(mgr.GetProviderForCapability(common::ProviderCapability::kCertManagement), nullptr);
}

TEST(ProviderManagerCapabilityTest, DisabledFallbackDoesNotInitializeExcludedProviderCategory)
{
    config::ProviderRoutingPolicy routing_policy;
    routing_policy.SetCapabilityRouting(common::ProviderCapability::kCrypto,
                                        config::CapabilityRoutingRule{{common::CryptoProviderType::SOFTWARE}, false});
    provider::ProviderManager mgr(std::move(routing_policy));
    auto hardware_provider =
        std::make_shared<ConfigurableStubProvider>("HW_PROVIDER", 0, false, common::ProviderCapability::kCrypto);
    auto software_provider =
        std::make_shared<ConfigurableStubProvider>("SW_PROVIDER", 1, false, common::ProviderCapability::kCrypto);
    ASSERT_TRUE(mgr.RegisterProvider("HW_PROVIDER", hardware_provider, common::CryptoProviderType::HARDWARE));
    ASSERT_TRUE(mgr.RegisterProvider("SW_PROVIDER", software_provider, common::CryptoProviderType::SOFTWARE));

    EXPECT_EQ(mgr.GetProviderForCapability(common::ProviderCapability::kCrypto), software_provider);
    EXPECT_EQ(software_provider->GetInitializationAttempts(), 1U);
    EXPECT_EQ(hardware_provider->GetInitializationAttempts(), 0U);
}

TEST(ProviderManagerCapabilityTest, CombinedCapabilityRuleRequiresEveryRequestedCapability)
{
    const auto combined_capability = common::ProviderCapability::kCrypto | common::ProviderCapability::kKeyManagement;
    config::ProviderRoutingPolicy routing_policy;
    routing_policy.SetCapabilityRouting(
        combined_capability,
        config::CapabilityRoutingRule{{common::CryptoProviderType::SOFTWARE, common::CryptoProviderType::HARDWARE},
                                      true});
    provider::ProviderManager mgr(std::move(routing_policy));
    mgr.RegisterProvider(
        "CRYPTO_ONLY",
        std::make_shared<ConfigurableStubProvider>("CRYPTO_ONLY", 0, false, common::ProviderCapability::kCrypto),
        common::CryptoProviderType::SOFTWARE);
    mgr.RegisterProvider("COMBINED",
                         std::make_shared<ConfigurableStubProvider>("COMBINED", 1, false, combined_capability),
                         common::CryptoProviderType::HARDWARE);

    const auto selected = mgr.GetProviderForCapability(combined_capability);
    ASSERT_NE(selected, nullptr);
    EXPECT_EQ(selected->GetProviderName(), "COMBINED");
}

TEST(ProviderManagerInitStateTest, RegisteredProviderCanRecoverAfterDeferredInitializationFailure)
{
    provider::ProviderManager mgr;
    auto deferred_provider = std::make_shared<ConfigurableStubProvider>("DEFERRED_HSM", 0, true);
    ASSERT_TRUE(mgr.RegisterProvider("DEFERRED_HSM", deferred_provider, common::CryptoProviderType::HARDWARE));

    ASSERT_TRUE(mgr.Initialize());
    EXPECT_TRUE(mgr.IsProviderRegistered("DEFERRED_HSM"));
    EXPECT_EQ(mgr.GetProvider("DEFERRED_HSM"), nullptr);

    deferred_provider->SetInitializationFailure(false);
    EXPECT_EQ(mgr.GetProvider("DEFERRED_HSM"), deferred_provider);
}

TEST(ProviderManagerInitStateTest, OptionalFactoryFailureIsDiagnosticOnly)
{
    provider::ProviderManager mgr;
    ASSERT_TRUE(mgr.RegisterProvider("OPENSSL",
                                     std::make_shared<ConfigurableStubProvider>("OPENSSL", 0, false),
                                     common::CryptoProviderType::SOFTWARE));
    mgr.RecordFactoryResult("Pkcs11ProviderFactory",
                            provider::ProviderFactoryResult{
                                0U,
                                {provider::ProviderFailure{"Pkcs11ProviderFactory",
                                                           "OPTIONAL_HSM",
                                                           provider::ProviderFailureReason::kProviderUnavailable,
                                                           common::DaemonErrorCode::kProviderNotAvailable}}});

    EXPECT_TRUE(mgr.Initialize());
    ASSERT_EQ(mgr.GetInitializationFailures().size(), 1U);
    EXPECT_EQ(mgr.GetInitializationFailures().front().providerName, "OPTIONAL_HSM");
}

TEST(ProviderManagerInitStateTest, ConstructionFailureDiagnosticDoesNotChangeRoutingManagerState)
{
    provider::ProviderManager mgr;
    ASSERT_TRUE(mgr.RegisterProvider("OPENSSL",
                                     std::make_shared<ConfigurableStubProvider>("OPENSSL", 0, false),
                                     common::CryptoProviderType::SOFTWARE));
    mgr.RecordFactoryResult(
        "ProviderManagerFactory",
        provider::ProviderFactoryResult{
            0U,
            {provider::ProviderFailure{"ProviderManagerFactory",
                                       "REQUIRED_HSM",
                                       provider::ProviderFailureReason::kRequiredProviderUnavailable,
                                       common::DaemonErrorCode::kProviderNotAvailable}}});

    EXPECT_TRUE(mgr.Initialize());
    ASSERT_EQ(mgr.GetInitializationFailures().size(), 1U);
    EXPECT_EQ(mgr.GetInitializationFailures().front().providerName, "REQUIRED_HSM");
}

// ===========================================================================
// Default provider resolution prefers successfully-initialized providers
// ===========================================================================

TEST(ProviderManagerDefaultResolutionTest, DefaultSkipsFailedPreferredProvider)
{
    score::crypto::daemon::config::Config config;
    provider::ProviderManager mgr(config.GetProviderRoutingPolicy());

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

TEST(ProviderManagerDefaultResolutionTest, DefaultUsesAnotherProviderInPreferredCategoryBeforeNextCategory)
{
    provider::ProviderManager mgr;
    auto failed_hardware = std::make_shared<ConfigurableStubProvider>("FAILED_HW", 0, true);
    auto available_hardware = std::make_shared<ConfigurableStubProvider>("AVAILABLE_HW", 1, false);
    auto software = std::make_shared<ConfigurableStubProvider>("SW_PROVIDER", 2, false);
    ASSERT_TRUE(mgr.RegisterProvider("FAILED_HW", failed_hardware, common::CryptoProviderType::HARDWARE));
    ASSERT_TRUE(mgr.RegisterProvider("AVAILABLE_HW", available_hardware, common::CryptoProviderType::HARDWARE));
    ASSERT_TRUE(mgr.RegisterProvider("SW_PROVIDER", software, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(mgr.Initialize());

    EXPECT_EQ(mgr.GetProvider(common::CryptoProviderType::DEFAULT), available_hardware);
}

TEST(ProviderManagerDefaultResolutionTest, ExplicitRoutingPolicyOverridesDefaultPreference)
{
    config::ProviderRoutingPolicy routing_policy;
    routing_policy.SetDefaultProviderForType(common::CryptoProviderType::DEFAULT, "SW_PROVIDER");
    provider::ProviderManager mgr(std::move(routing_policy));

    mgr.RegisterProvider("HW_PROVIDER",
                         std::make_shared<ConfigurableStubProvider>("HW_PROVIDER", 0, false),
                         common::CryptoProviderType::HARDWARE);
    mgr.RegisterProvider("SW_PROVIDER",
                         std::make_shared<ConfigurableStubProvider>("SW_PROVIDER", 1, false),
                         common::CryptoProviderType::SOFTWARE);
    ASSERT_TRUE(mgr.Initialize());

    auto selected = mgr.GetProvider(common::CryptoProviderType::DEFAULT);
    ASSERT_NE(selected, nullptr);
    EXPECT_EQ(selected->GetProviderName(), "SW_PROVIDER");
}

TEST(ProviderManagerDefaultResolutionTest, ProviderCategoryMappingUsesRegistrationOrder)
{
    provider::ProviderManager mgr;
    auto first = std::make_shared<ConfigurableStubProvider>("FIRST_SW", 0, false);
    auto second = std::make_shared<ConfigurableStubProvider>("SECOND_SW", 1, false);
    ASSERT_TRUE(mgr.RegisterProvider("FIRST_SW", first, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(mgr.RegisterProvider("SECOND_SW", second, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(mgr.Initialize());

    EXPECT_EQ(mgr.GetProvider(common::CryptoProviderType::SOFTWARE), first);
}

TEST(ProviderManagerDefaultResolutionTest, ExplicitCategoryMappingControlsImplicitDefault)
{
    config::ProviderRoutingPolicy routing_policy;
    routing_policy.SetDefaultProviderForType(common::CryptoProviderType::SOFTWARE, "SECOND_SW");
    routing_policy.defaultProviderPreference = {common::CryptoProviderType::SOFTWARE};
    provider::ProviderManager mgr(std::move(routing_policy));
    auto first = std::make_shared<ConfigurableStubProvider>("FIRST_SW", 0, false);
    auto second = std::make_shared<ConfigurableStubProvider>("SECOND_SW", 1, false);
    ASSERT_TRUE(mgr.RegisterProvider("FIRST_SW", first, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(mgr.RegisterProvider("SECOND_SW", second, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(mgr.Initialize());

    EXPECT_EQ(mgr.GetProvider(common::CryptoProviderType::SOFTWARE), second);
    EXPECT_EQ(mgr.GetProvider(common::CryptoProviderType::DEFAULT), second);
}

TEST(ProviderManagerDefaultResolutionTest, ExplicitCategoryMappingRejectsProviderTypeMismatch)
{
    config::ProviderRoutingPolicy routing_policy;
    routing_policy.SetDefaultProviderForType(common::CryptoProviderType::HARDWARE, "SW_PROVIDER");
    provider::ProviderManager mgr(std::move(routing_policy));
    ASSERT_TRUE(mgr.RegisterProvider("SW_PROVIDER",
                                     std::make_shared<ConfigurableStubProvider>("SW_PROVIDER", 0, false),
                                     common::CryptoProviderType::SOFTWARE));

    EXPECT_FALSE(mgr.Initialize());
}

TEST(ProviderManagerDefaultResolutionTest, RuntimeCategoryOverrideRejectsProviderTypeMismatch)
{
    provider::ProviderManager mgr;
    ASSERT_TRUE(mgr.RegisterProvider("SW_PROVIDER",
                                     std::make_shared<ConfigurableStubProvider>("SW_PROVIDER", 0, false),
                                     common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(mgr.Initialize());

    EXPECT_FALSE(mgr.SetDefaultProviderForType(common::CryptoProviderType::HARDWARE, 0U));
    EXPECT_TRUE(mgr.SetDefaultProviderForType(common::CryptoProviderType::DEFAULT, 0U));
}

TEST(ProviderManagerLifecycleTest, ShutdownIsIdempotent)
{
    provider::ProviderManager mgr;
    auto provider_instance = std::make_shared<ConfigurableStubProvider>("OPENSSL", 0, false);
    ASSERT_TRUE(mgr.RegisterProvider("OPENSSL", provider_instance, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(mgr.Initialize());

    mgr.Shutdown();
    mgr.Shutdown();

    EXPECT_EQ(provider_instance->GetShutdownCalls(), 1U);
}

TEST(ProviderManagerLifecycleTest, ShutdownPreventsProviderReinitialization)
{
    provider::ProviderManager mgr;
    auto provider_instance = std::make_shared<ConfigurableStubProvider>("OPENSSL", 0, false);
    ASSERT_TRUE(mgr.RegisterProvider("OPENSSL", provider_instance, common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(mgr.Initialize());
    ASSERT_EQ(provider_instance->GetInitializationAttempts(), 1U);

    mgr.Shutdown();

    EXPECT_EQ(mgr.GetProvider("OPENSSL"), nullptr);
    EXPECT_FALSE(mgr.Initialize());
    EXPECT_FALSE(mgr.RegisterProvider("SECOND_PROVIDER",
                                      std::make_shared<ConfigurableStubProvider>("SECOND_PROVIDER", 1, false),
                                      common::CryptoProviderType::SOFTWARE));
    EXPECT_EQ(provider_instance->GetInitializationAttempts(), 1U);
    EXPECT_EQ(provider_instance->GetShutdownCalls(), 1U);
}
