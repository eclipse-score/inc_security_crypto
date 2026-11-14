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

#include "score/crypto/src/daemon/mediator/src/handler_selector.hpp"

#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/mediator/context_algorithm.hpp"
#include "score/crypto/src/daemon/mediator/src/mediator_test_doubles.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace score::crypto::daemon::mediator
{
namespace
{

using common::CryptoProviderType;
using common::ProviderCapability;
using test_doubles::StubContextFactory;
using test_doubles::StubProvider;
using CryptoError = score::crypto::CryptoErrorCode;

constexpr std::uint64_t kClient = 7U;
constexpr std::string_view kSubsystemType = "HASH";

class HandlerSelectorTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_context_factories = std::make_shared<common::ContextFactoryRegistry>();
        m_provider_manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
    }

    // Builds the selector after the test has registered its factories and providers.
    HandlerSelector MakeSelector()
    {
        m_provider_manager->Initialize();
        return HandlerSelector{std::make_shared<ProviderArbiter>(m_provider_manager, nullptr), m_context_factories};
    }

    static common::ContextCreationRequest ProviderRequest(const std::string_view context_type)
    {
        common::ContextCreationRequest request{};
        request.context_type = context_type;
        request.algorithm = "SHA256";
        request.provider_type_preference = common::ProviderTypePreference{CryptoProviderType::DEFAULT, std::nullopt};
        request.algorithm_descriptor = ::score::crypto::GetAlgorithmDescriptor("SHA256");
        request.required_capability = common::RequiredProviderCapability(context_type);
        return request;
    }

    std::shared_ptr<common::ContextFactoryRegistry> m_context_factories;
    provider::ProviderManager::Sptr m_provider_manager;
};

TEST_F(HandlerSelectorTest, FactoryServedTypeIsCreatedByItsFactoryWithoutAProvider)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__context_factory");
    RecordProperty("Description",
                   "A context type with a registered factory is created by that factory and no provider is selected.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto factory = std::make_shared<StubContextFactory>();
    ASSERT_TRUE(m_context_factories->Register(std::string{kSubsystemType}, factory));
    const auto selector = MakeSelector();

    const auto selection = selector.Select(kClient, ProviderRequest(kSubsystemType));

    ASSERT_TRUE(selection.has_value());
    EXPECT_NE(selection.value().handler, nullptr);
    EXPECT_EQ(selection.value().provider, nullptr);
    EXPECT_FALSE(selection.value().used_fallback);
    EXPECT_EQ(factory->CreateCalls(), 1);
}

TEST_F(HandlerSelectorTest, FactoryServedTypeThatReferencesAKeyIsRefusedBeforeTheFactoryRuns)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__context_factory");
    RecordProperty("Description",
                   "A factory-served context type that references a key is refused as not permitted, and its factory "
                   "is not called.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto factory = std::make_shared<StubContextFactory>();
    ASSERT_TRUE(m_context_factories->Register(std::string{kSubsystemType}, factory));
    const auto selector = MakeSelector();
    auto request = ProviderRequest(kSubsystemType);
    request.key_node_id = 5U;

    const auto selection = selector.Select(kClient, request);

    ASSERT_FALSE(selection.has_value());
    EXPECT_EQ(selection.error(), CryptoError::kKeyOperationNotPermitted);
    EXPECT_EQ(factory->CreateCalls(), 0);
}

TEST_F(HandlerSelectorTest, FactoryErrorIsReturnedAsThePublicCode)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__error_mapping");
    RecordProperty("Description", "A factory error reaches the caller as its public counterpart.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto factory = std::make_shared<StubContextFactory>();
    factory->FailWith(common::DaemonErrorCode::kInvalidArgument);
    ASSERT_TRUE(m_context_factories->Register(std::string{kSubsystemType}, factory));
    const auto selector = MakeSelector();

    const auto selection = selector.Select(kClient, ProviderRequest(kSubsystemType));

    ASSERT_FALSE(selection.has_value());
    EXPECT_EQ(selection.error(), CryptoError::kInvalidArgument);
}

TEST_F(HandlerSelectorTest, TypeWithoutAFactoryIsServedByAProvider)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__arbitration");
    RecordProperty("Description",
                   "A context type with no registered factory is served by a provider chosen by the arbiter.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    auto provider = std::make_shared<StubProvider>("SW", ProviderCapability::kCrypto);
    ASSERT_TRUE(m_provider_manager->RegisterProvider("SW", provider, CryptoProviderType::SOFTWARE));
    const auto selector = MakeSelector();

    const auto selection = selector.Select(kClient, ProviderRequest("SIGN"));

    ASSERT_TRUE(selection.has_value());
    EXPECT_NE(selection.value().handler, nullptr);
    ASSERT_NE(selection.value().provider, nullptr);
    EXPECT_EQ(selection.value().provider->GetProviderId(), provider->GetProviderId());
    EXPECT_EQ(provider->Factory()->CreateCalls(), 1);
}

}  // namespace
}  // namespace score::crypto::daemon::mediator
