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

#include "score/crypto/src/daemon/provider/provider_manager_factory.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <memory>
#include <string>
#include <utility>

namespace score::crypto::daemon::provider
{
class ProviderManagerFactoryTestPeer
{
  public:
    static score::crypto::Expected<std::shared_ptr<ProviderManager>, common::DaemonErrorCode> Finalize(
        std::shared_ptr<ProviderManager> provider_manager,
        const config::ProviderConstructionPolicy& construction_policy)
    {
        return ProviderManagerFactory::FinalizeProviderManager(std::move(provider_manager), construction_policy);
    }
};
}  // namespace score::crypto::daemon::provider

namespace provider = score::crypto::daemon::provider;
namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;

namespace
{
class StartupStubProvider final : public provider::IProvider
{
  public:
    StartupStubProvider(std::string name, bool fail_initialization)
        : m_name{std::move(name)}, m_fail_initialization{fail_initialization}
    {
    }

    bool Initialize(const provider::ProviderInitContext& context) override
    {
        (void)context;
        if (m_fail_initialization)
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
        return 0U;
    }

    const common::ProviderName& GetProviderName() const override
    {
        return m_name;
    }

    std::size_t GetShutdownCalls() const noexcept
    {
        return m_shutdown_calls;
    }

  private:
    common::ProviderName m_name;
    bool m_fail_initialization;
    bool m_initialized{false};
    std::size_t m_shutdown_calls{0U};
};
}  // namespace

TEST(ProviderManagerFactoryTest, InvalidProviderPolicyReturnsInvalidArgument)
{
    config::Config daemon_config;
    daemon_config.GetProviderConstructionPolicy().AddProvider(
        config::ProviderConstructionEntry{"REQUIRED_HSM", false, true});

    const auto result = provider::ProviderManagerFactory::Create(daemon_config);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

TEST(ProviderManagerFactoryTest, EmptyRegistryReturnsProviderNotAvailable)
{
    auto manager = std::make_shared<provider::ProviderManager>();

    const auto result =
        provider::ProviderManagerFactoryTestPeer::Finalize(manager, config::ProviderConstructionPolicy{});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kProviderNotAvailable);
}

TEST(ProviderManagerFactoryTest, MissingRequiredProviderIsFatalAndCleansUpPartialRegistration)
{
    config::ProviderConstructionPolicy construction_policy;
    construction_policy.AddProvider(config::ProviderConstructionEntry{"OPENSSL", true, false});
    construction_policy.AddProvider(config::ProviderConstructionEntry{"REQUIRED_HSM", true, true});
    auto manager = std::make_shared<provider::ProviderManager>();
    auto openssl = std::make_shared<StartupStubProvider>("OPENSSL", false);
    ASSERT_TRUE(manager->RegisterProvider("OPENSSL", openssl, common::CryptoProviderType::SOFTWARE));

    const auto result = provider::ProviderManagerFactoryTestPeer::Finalize(manager, construction_policy);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kProviderNotAvailable);
    EXPECT_EQ(openssl->GetShutdownCalls(), 1U);
}

TEST(ProviderManagerFactoryTest, RequiredProviderNeedsRegistrationButMayUseDeferredInitialization)
{
    config::ProviderConstructionPolicy construction_policy;
    construction_policy.AddProvider(config::ProviderConstructionEntry{"DEFERRED_HSM", true, true});
    auto manager = std::make_shared<provider::ProviderManager>();
    ASSERT_TRUE(manager->RegisterProvider("DEFERRED_HSM",
                                          std::make_shared<StartupStubProvider>("DEFERRED_HSM", true),
                                          common::CryptoProviderType::HARDWARE));

    const auto result = provider::ProviderManagerFactoryTestPeer::Finalize(manager, construction_policy);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value()->IsProviderRegistered("DEFERRED_HSM"));
    EXPECT_EQ(result.value()->GetProvider("DEFERRED_HSM"), nullptr);
}

TEST(ProviderManagerFactoryTest, UnsatisfiedExplicitMappingReturnsProviderNotAvailable)
{
    config::ProviderRoutingPolicy routing_policy;
    routing_policy.SetDefaultProviderForType(common::CryptoProviderType::HARDWARE, "MISSING_HSM");
    auto manager = std::make_shared<provider::ProviderManager>(std::move(routing_policy));
    auto openssl = std::make_shared<StartupStubProvider>("OPENSSL", false);
    ASSERT_TRUE(manager->RegisterProvider("OPENSSL", openssl, common::CryptoProviderType::SOFTWARE));

    const auto result =
        provider::ProviderManagerFactoryTestPeer::Finalize(manager, config::ProviderConstructionPolicy{});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kProviderNotAvailable);
    EXPECT_EQ(openssl->GetShutdownCalls(), 1U);
}

TEST(ProviderManagerFactoryTest, ProviderCategoryMismatchReturnsInvalidArgument)
{
    config::ProviderRoutingPolicy routing_policy;
    routing_policy.SetDefaultProviderForType(common::CryptoProviderType::HARDWARE, "OPENSSL");
    auto manager = std::make_shared<provider::ProviderManager>(std::move(routing_policy));
    auto openssl = std::make_shared<StartupStubProvider>("OPENSSL", false);
    ASSERT_TRUE(manager->RegisterProvider("OPENSSL", openssl, common::CryptoProviderType::SOFTWARE));

    const auto result =
        provider::ProviderManagerFactoryTestPeer::Finalize(manager, config::ProviderConstructionPolicy{});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(openssl->GetShutdownCalls(), 1U);
}

TEST(ProviderManagerFactoryTest, OptionalFactoryFailureDoesNotBlockUsableProvider)
{
    auto manager = std::make_shared<provider::ProviderManager>();
    ASSERT_TRUE(manager->RegisterProvider(
        "OPENSSL", std::make_shared<StartupStubProvider>("OPENSSL", false), common::CryptoProviderType::SOFTWARE));
    manager->RecordFactoryResult("Pkcs11ProviderFactory",
                                 provider::ProviderFactoryResult{
                                     0U,
                                     {provider::ProviderFailure{"Pkcs11ProviderFactory",
                                                                "OPTIONAL_HSM",
                                                                provider::ProviderFailureReason::kProviderUnavailable,
                                                                common::DaemonErrorCode::kProviderNotAvailable}}});

    const auto result =
        provider::ProviderManagerFactoryTestPeer::Finalize(manager, config::ProviderConstructionPolicy{});

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value()->GetInitializationFailures().size(), 1U);
    EXPECT_EQ(result.value()->GetInitializationFailures().front().providerName, "OPTIONAL_HSM");
}
