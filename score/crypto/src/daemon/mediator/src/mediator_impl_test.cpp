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

#include "score/crypto/src/daemon/mediator/src/mediator_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace score::crypto::daemon::mediator
{
namespace
{

namespace protocol = control_plane::protocol;

class StubHandler final : public provider::handler::Handler
{
  public:
    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const provider::handler::InitializationParams& init_params) override
    {
        provider_id = init_params.provider_id;
        return std::monostate{};
    }

    Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& /*operation_id*/,
        common::RequestParameters& /*request*/) override
    {
        return common::ResponseParameters{};
    }

    Expected<std::monostate, common::DaemonErrorCode> Reset() override
    {
        return std::monostate{};
    }

    common::ProviderId provider_id{common::kInvalidProviderId};
};

class StubHandlerFactory final : public provider::handler::ICryptoHandlerFactory
{
  public:
    explicit StubHandlerFactory(const bool supports_algorithm) : m_supports_algorithm{supports_algorithm} {}

    score::Result<provider::handler::Handler::Sptr> CreateHandler(const common::HandlerId& handler_id,
                                                                  const common::AlgorithmId& algorithm) override
    {
        ++calls;
        if (!m_supports_algorithm || (handler_id != "HASH") || (algorithm != "SHA256"))
        {
            return score::Result<provider::handler::Handler::Sptr>{
                score::unexpect,
                MakeError(CryptoErrorCode::kUnsupportedAlgorithm, "Algorithm intentionally unsupported by stub")};
        }
        handler = std::make_shared<StubHandler>();
        return std::static_pointer_cast<provider::handler::Handler>(handler);
    }

    std::size_t calls{0U};
    std::shared_ptr<StubHandler> handler{};

  private:
    bool m_supports_algorithm;
};

class StubProvider final : public provider::IProvider
{
  public:
    explicit StubProvider(std::shared_ptr<StubHandlerFactory> factory) : m_factory{std::move(factory)} {}

    bool Initialize(const provider::ProviderInitContext& ctx) override
    {
        m_id = ctx.numeric_id;
        m_name = ctx.name;
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

    std::shared_ptr<provider::handler::ICryptoHandlerFactory> GetCryptoHandlerFactory() override
    {
        return m_factory;
    }

  private:
    common::ProviderId m_id{common::kInvalidProviderId};
    common::ProviderName m_name{};
    bool m_initialized{false};
    std::shared_ptr<StubHandlerFactory> m_factory;
};

control_plane::ControlResponse ProcessContextCreation(common::RequestParameters parameters)
{
    MediatorImpl mediator{MediatorDependencies{nullptr, nullptr, nullptr, nullptr}};
    control_plane::ControlRequest request{};
    request.request_id = 1U;
    request.client_id = 1U;
    request.data_node_id = 1U;
    request.operation.operations.push_back(
        control_plane::SingleOperationRequest{operations::CreateContext(), std::move(parameters)});
    return mediator.processRequest(request);
}

void ExpectInvalidContextCreation(common::RequestParameters parameters)
{
    const auto response = ProcessContextCreation(std::move(parameters));
    ASSERT_EQ(response.operation.operations.size(), 1U);
    EXPECT_EQ(response.operation.operations.front().result,
              static_cast<protocol::OperationResult>(CryptoErrorCode::kInvalidArgument));
}

TEST(MediatorContextSchemaTest, RejectsKeyAndOperationModeForHash)
{
    ExpectInvalidContextCreation(
        {std::string_view{"HASH"}, std::string_view{"SHA256"}, common::NoParam{}, std::uint64_t{7U}, std::uint8_t{0U}});
}

TEST(MediatorContextSchemaTest, RejectsKeyAndOperationModeForKeyManagement)
{
    ExpectInvalidContextCreation({std::string_view{"KEY_MANAGEMENT"},
                                  std::string_view{""},
                                  common::NoParam{},
                                  std::uint64_t{7U},
                                  std::uint8_t{0U}});
}

TEST(MediatorContextSchemaTest, RejectsMacWithoutKey)
{
    ExpectInvalidContextCreation({std::string_view{"MAC"},
                                  std::string_view{"HMAC-SHA256"},
                                  common::NoParam{},
                                  common::NoParam{},
                                  std::uint8_t{0U}});
}

TEST(MediatorContextSchemaTest, RejectsMacWithoutOperationMode)
{
    ExpectInvalidContextCreation(
        {std::string_view{"MAC"}, std::string_view{"HMAC-SHA256"}, common::NoParam{}, std::uint64_t{7U}});
}

TEST(MediatorContextSchemaTest, RejectsMacWithUnknownOperationMode)
{
    ExpectInvalidContextCreation({std::string_view{"MAC"},
                                  std::string_view{"HMAC-SHA256"},
                                  common::NoParam{},
                                  std::uint64_t{7U},
                                  std::uint8_t{2U}});
}

TEST(MediatorProviderSelectionTest, FallsBackWhenPreferredProviderRejectsAlgorithm)
{
    config::Config config;
    auto provider_manager = std::make_shared<provider::ProviderManager>(config.GetProviderInitConfig());
    auto hardware_factory = std::make_shared<StubHandlerFactory>(false);
    auto software_factory = std::make_shared<StubHandlerFactory>(true);

    ASSERT_TRUE(provider_manager->RegisterProvider(
        "HW_STUB", std::make_shared<StubProvider>(hardware_factory), common::CryptoProviderType::HARDWARE));
    ASSERT_TRUE(provider_manager->RegisterProvider(
        "SW_STUB", std::make_shared<StubProvider>(software_factory), common::CryptoProviderType::SOFTWARE));
    ASSERT_TRUE(provider_manager->Initialize());

    auto data_manager = std::make_shared<data_manager::DataManager>();
    constexpr data_manager::ClientId kClientId = 42U;
    const auto parent_result = data_manager->addNode(kClientId, std::make_shared<data_manager::DataNode>(false));
    ASSERT_TRUE(parent_result.has_value());

    MediatorImpl mediator{MediatorDependencies{data_manager, provider_manager, nullptr, nullptr}};
    const auto operation = protocol::OperationRequestBuilder()
                               .operation(operations::CreateContext())
                               .with_in_string("HASH")
                               .with_in_string("SHA256")
                               .with_in_val_uint8(static_cast<std::uint8_t>(ProviderType::kHardwarePreferred))
                               .with_no_param()
                               .with_no_param()
                               .with_no_param()
                               .build();
    ASSERT_TRUE(operation.has_value());

    control_plane::ControlRequest request{};
    request.request_id = 1U;
    request.client_id = kClientId;
    request.data_node_id = parent_result.value();
    request.operation = operation.value();

    const auto response = mediator.processRequest(request);
    ASSERT_EQ(response.operation.operations.size(), 1U);
    EXPECT_EQ(response.operation.operations.front().result, protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(hardware_factory->calls, 1U);
    EXPECT_EQ(software_factory->calls, 1U);
    ASSERT_NE(software_factory->handler, nullptr);
    EXPECT_EQ(software_factory->handler->provider_id, 1U);
}

TEST(MediatorProviderIdentityTest, UnboundSentinelDoesNotCollideWithFirstProvider)
{
    EXPECT_EQ(operations::SHM_WIRE_PROVIDER_ID_UNBOUND, static_cast<std::uint64_t>(common::kInvalidProviderId));
    EXPECT_NE(operations::SHM_WIRE_PROVIDER_ID_UNBOUND, 0U);
    EXPECT_EQ(CryptoResourceId{}.primary_provider, kUnboundProviderId);
}

}  // namespace
}  // namespace score::crypto::daemon::mediator
