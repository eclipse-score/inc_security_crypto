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

// Unit tests for the PROVIDER_INFO, QUERY_CAPABILITIES and SYSTEM_CAPABILITIES
// mediator operations, driven through processRequest() with stub providers.

#include "score/crypto/src/daemon/mediator/src/mediator_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace score::crypto::daemon::mediator
{
namespace
{

namespace protocol = control_plane::protocol;
using score::crypto::Algorithm;

constexpr auto kInvalidArgument = static_cast<protocol::OperationResult>(CryptoErrorCode::kInvalidArgument);

/// Reports support for a fixed set of (context type, algorithm) pairs.
class FakeHandlerFactory final : public provider::handler::ICryptoHandlerFactory
{
  public:
    explicit FakeHandlerFactory(std::set<std::pair<std::string, Algorithm>> supported)
        : m_supported{std::move(supported)}
    {
    }

    ::score::Result<provider::handler::Handler::Sptr> CreateHandler(const common::HandlerId& /*handlerId*/,
                                                                    const AlgorithmDescriptor& /*algorithm*/) override
    {
        return ::score::Result<provider::handler::Handler::Sptr>{::score::unexpect,
                                                                 MakeError(CryptoErrorCode::kUnsupportedOperation)};
    }

    ::score::Result<provider::handler::Handler::Sptr> CreateKeyManagementHandler() override
    {
        return ::score::Result<provider::handler::Handler::Sptr>{::score::unexpect,
                                                                 MakeError(CryptoErrorCode::kUnsupportedOperation)};
    }

    bool IsAlgorithmSupported(const common::HandlerId& handlerId, const AlgorithmDescriptor& algorithm) const override
    {
        return m_supported.count({std::string{handlerId}, algorithm.id}) != 0U;
    }

  private:
    std::set<std::pair<std::string, Algorithm>> m_supported;
};

/// Reports key generation support for a fixed set of algorithms.
class FakeKeyFactory final : public key_management::IKeyFactory
{
  public:
    explicit FakeKeyFactory(std::set<Algorithm> supported) : m_supported{std::move(supported)} {}

    bool IsKeyGenerationSupported(const AlgorithmDescriptor& algorithm) const override
    {
        return m_supported.count(algorithm.id) != 0U;
    }

  private:
    std::set<Algorithm> m_supported;
};

class StubProvider final : public provider::IProvider
{
  public:
    StubProvider(std::string name,
                 common::ProviderId id,
                 std::shared_ptr<provider::handler::ICryptoHandlerFactory> handler_factory,
                 std::shared_ptr<key_management::IKeyFactory> key_factory = nullptr,
                 bool fail_init = false)
        : m_name{std::move(name)},
          m_id{id},
          m_handler_factory{std::move(handler_factory)},
          m_key_factory{std::move(key_factory)},
          m_fail_init{fail_init}
    {
    }

    bool Initialize(const provider::ProviderInitContext& /*ctx*/) override
    {
        m_initialized = !m_fail_init;
        return m_initialized;
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
        return common::ProviderCapability::kNone;
    }

    std::shared_ptr<provider::handler::ICryptoHandlerFactory> GetCryptoHandlerFactory() override
    {
        return m_handler_factory;
    }

    std::shared_ptr<key_management::IKeyFactory> GetKeyFactory() override
    {
        return m_key_factory;
    }

  private:
    std::string m_name;
    common::ProviderId m_id;
    std::shared_ptr<provider::handler::ICryptoHandlerFactory> m_handler_factory;
    std::shared_ptr<key_management::IKeyFactory> m_key_factory;
    bool m_fail_init;
    bool m_initialized{false};
};

std::string ToString(const common::ResponseParameter& parameter)
{
    const auto& bytes = std::get<common::OwnedBuffer>(parameter);
    return std::string{bytes.begin(), bytes.end()};
}

class MediatorCapabilitiesTest : public ::testing::Test
{
  protected:
    /// Registers a provider; the manager assigns ids in registration order.
    void Register(const std::string& name,
                  common::CryptoProviderType type,
                  std::shared_ptr<provider::handler::ICryptoHandlerFactory> handler_factory,
                  std::shared_ptr<key_management::IKeyFactory> key_factory = nullptr,
                  bool fail_init = false)
    {
        const auto id = m_next_id++;
        ASSERT_TRUE(m_manager->RegisterProvider(
            name,
            std::make_shared<StubProvider>(name, id, std::move(handler_factory), std::move(key_factory), fail_init),
            type));
    }

    MediatorImpl MakeMediator(bool with_manager = true)
    {
        if (with_manager)
        {
            (void)m_manager->Initialize();
        }
        return MediatorImpl{MediatorDependencies{nullptr, with_manager ? m_manager : nullptr, nullptr, nullptr}};
    }

    template <typename BuildOperation>
    static protocol::ControlResponse Send(MediatorImpl& mediator, BuildOperation&& build_operation)
    {
        protocol::ControlRequestBuilder builder;
        builder.forDataNodeId(1U);
        build_operation(builder);
        auto request = builder.build();
        EXPECT_TRUE(request.has_value());
        return mediator.processRequest(request.value());
    }

    static protocol::ControlResponse ProviderInfo(MediatorImpl& mediator, std::uint64_t id)
    {
        return Send(mediator, [id](auto& b) {
            b.operation(operations::GetProviderInfo()).with_in_val_uint64(id);
        });
    }

    static protocol::ControlResponse QueryCapabilities(MediatorImpl& mediator, std::string_view name)
    {
        return Send(mediator, [name](auto& b) {
            b.operation(operations::QueryCapabilities()).with_in_string(name);
        });
    }

    static protocol::ControlResponse SystemCapabilities(MediatorImpl& mediator)
    {
        return Send(mediator, [](auto& b) {
            b.operation(operations::QuerySystemCapabilities());
        });
    }

    /// Reads an operation count and that many names, starting at @p index.
    static std::vector<std::string> ReadOperations(const protocol::SingleOperationResponse& op, std::size_t& index)
    {
        std::vector<std::string> names;
        const auto count = std::get<std::uint16_t>(op.parameters.at(index++));
        for (std::uint16_t n = 0U; n < count; ++n)
        {
            names.push_back(ToString(op.parameters.at(index++)));
        }
        return names;
    }

    static std::vector<std::string> OnlyOperations(const protocol::SingleOperationResponse& op)
    {
        std::size_t index = 0U;
        auto names = ReadOperations(op, index);
        EXPECT_EQ(index, op.parameters.size());
        return names;
    }

    static const protocol::SingleOperationResponse& OnlyOperation(const protocol::ControlResponse& response)
    {
        EXPECT_EQ(response.operation.operations.size(), 1U);
        return response.operation.operations.front();
    }

    std::shared_ptr<provider::ProviderManager> m_manager{
        std::make_shared<provider::ProviderManager>(config::Config{}.GetProviderInitConfig())};
    common::ProviderId m_next_id{0U};
};

// ---------------------------------------------------------------------------
// PROVIDER_INFO
// ---------------------------------------------------------------------------

TEST_F(MediatorCapabilitiesTest, ProviderInfoReportsIdWireTypeAndName)
{
    Register("SW_PROV", common::CryptoProviderType::SOFTWARE, nullptr);
    Register("HW_PROV", common::CryptoProviderType::HARDWARE, nullptr);
    Register("SPECIAL_PROV", common::CryptoProviderType::SPECIALIZED, nullptr);
    auto mediator = MakeMediator();

    const std::vector<std::tuple<std::uint16_t, std::uint8_t, std::string>> expected{
        {0U, 2U, "SW_PROV"}, {1U, 1U, "HW_PROV"}, {2U, 0U, "SPECIAL_PROV"}};
    for (const auto& [id, wire_type, name] : expected)
    {
        const auto response = ProviderInfo(mediator, id);
        const auto& op = OnlyOperation(response);
        ASSERT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS) << name;
        ASSERT_EQ(op.parameters.size(), 3U);
        EXPECT_EQ(std::get<std::uint16_t>(op.parameters[0]), id);
        EXPECT_EQ(std::get<std::uint8_t>(op.parameters[1]), wire_type);
        EXPECT_EQ(ToString(op.parameters[2]), name);
    }
}

TEST_F(MediatorCapabilitiesTest, ProviderInfoRejectsUnknownAndOutOfRangeIds)
{
    Register("SW_PROV", common::CryptoProviderType::SOFTWARE, nullptr);
    auto mediator = MakeMediator();

    for (const std::uint64_t id : {std::uint64_t{1U},
                                   std::uint64_t{common::kInvalidProviderId},
                                   std::uint64_t{0x10000U},  // would alias id 0 if truncated to 16 bits
                                   std::numeric_limits<std::uint64_t>::max()})
    {
        const auto response = ProviderInfo(mediator, id);
        const auto& op = OnlyOperation(response);
        EXPECT_EQ(op.result, kInvalidArgument) << id;
        EXPECT_TRUE(op.parameters.empty()) << id;
    }
}

TEST_F(MediatorCapabilitiesTest, ProviderInfoRejectsProviderThatFailedToInitialize)
{
    Register("SW_PROV", common::CryptoProviderType::SOFTWARE, nullptr);
    Register("BROKEN", common::CryptoProviderType::HARDWARE, nullptr, nullptr, /*fail_init=*/true);
    auto mediator = MakeMediator();

    const auto response = ProviderInfo(mediator, 1U);
    EXPECT_EQ(OnlyOperation(response).result, kInvalidArgument);
}

TEST_F(MediatorCapabilitiesTest, ProviderInfoRejectsMissingOrMistypedId)
{
    Register("SW_PROV", common::CryptoProviderType::SOFTWARE, nullptr);
    auto mediator = MakeMediator();

    const auto missing = Send(mediator, [](auto& b) {
        b.operation(operations::GetProviderInfo());
    });
    EXPECT_EQ(OnlyOperation(missing).result, kInvalidArgument);

    const auto as_uint16 = Send(mediator, [](auto& b) {
        b.operation(operations::GetProviderInfo()).with_in_val_uint16(0U);
    });
    EXPECT_EQ(OnlyOperation(as_uint16).result, kInvalidArgument);
}

TEST_F(MediatorCapabilitiesTest, ProviderInfoRejectsRequestWithoutProviderManager)
{
    auto mediator = MakeMediator(/*with_manager=*/false);
    const auto response = ProviderInfo(mediator, 0U);
    EXPECT_EQ(OnlyOperation(response).result, kInvalidArgument);
}

TEST_F(MediatorCapabilitiesTest, FailedProviderInfoStopsTheBatch)
{
    Register("SW_PROV", common::CryptoProviderType::SOFTWARE, nullptr);
    auto mediator = MakeMediator();

    const auto response = Send(mediator, [](auto& b) {
        b.operation(operations::GetProviderInfo())
            .with_in_val_uint64(7U)
            .operation(operations::QuerySystemCapabilities());
    });
    ASSERT_EQ(response.operation.operations.size(), 1U);
    EXPECT_EQ(response.operation.operations[0].result, kInvalidArgument);
}

// ---------------------------------------------------------------------------
// QUERY_CAPABILITIES
// ---------------------------------------------------------------------------

TEST_F(MediatorCapabilitiesTest, QueryCapabilitiesUnionsOperationsAcrossProviders)
{
    Register("MAC_PROV",
             common::CryptoProviderType::SOFTWARE,
             std::make_shared<FakeHandlerFactory>(
                 std::set<std::pair<std::string, Algorithm>>{{"MAC", Algorithm::kHmacSha256}}));
    Register("KEYGEN_PROV",
             common::CryptoProviderType::HARDWARE,
             nullptr,
             std::make_shared<FakeKeyFactory>(std::set<Algorithm>{Algorithm::kHmacSha256}));
    auto mediator = MakeMediator();

    const auto response = QueryCapabilities(mediator, "HMAC-SHA256");
    const auto& op = OnlyOperation(response);
    ASSERT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(OnlyOperations(op), (std::vector<std::string>{"MAC", "GENERATE_KEY"}));
}

TEST_F(MediatorCapabilitiesTest, QueryCapabilitiesReportsEveryContextTypeInFixedOrder)
{
    const std::vector<std::string> contexts{"HASH", "MAC", "CIPHER", "SIGN", "VERIFY", "RANDOM"};
    std::set<std::pair<std::string, Algorithm>> supported;
    for (const auto& context : contexts)
    {
        supported.insert({context, Algorithm::kSha256});
    }
    Register("ALL", common::CryptoProviderType::SOFTWARE, std::make_shared<FakeHandlerFactory>(supported));
    auto mediator = MakeMediator();

    const auto response = QueryCapabilities(mediator, "SHA256");
    const auto& op = OnlyOperation(response);
    ASSERT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(OnlyOperations(op), contexts);
}

TEST_F(MediatorCapabilitiesTest, QueryCapabilitiesWithEmptyNameAsksForDefaultGenerator)
{
    Register("RNG",
             common::CryptoProviderType::SOFTWARE,
             std::make_shared<FakeHandlerFactory>(
                 std::set<std::pair<std::string, Algorithm>>{{"RANDOM", Algorithm::kCtrDrbg}}));
    auto mediator = MakeMediator();

    const auto response = QueryCapabilities(mediator, "");
    const auto& op = OnlyOperation(response);
    ASSERT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(OnlyOperations(op), (std::vector<std::string>{"RANDOM"}));
}

TEST_F(MediatorCapabilitiesTest, QueryCapabilitiesReportsNoOperationsForUnknownOrUnservedAlgorithm)
{
    Register("HASH_PROV",
             common::CryptoProviderType::SOFTWARE,
             std::make_shared<FakeHandlerFactory>(
                 std::set<std::pair<std::string, Algorithm>>{{"HASH", Algorithm::kSha256}}));
    auto mediator = MakeMediator();

    for (const std::string_view name : {"NOT-AN-ALGORITHM", "SHA512"})
    {
        const auto response = QueryCapabilities(mediator, name);
        const auto& op = OnlyOperation(response);
        ASSERT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS) << name;
        EXPECT_TRUE(OnlyOperations(op).empty()) << name;
    }
}

TEST_F(MediatorCapabilitiesTest, QueryCapabilitiesIgnoresProviderThatFailedToInitialize)
{
    Register(
        "BROKEN",
        common::CryptoProviderType::HARDWARE,
        std::make_shared<FakeHandlerFactory>(std::set<std::pair<std::string, Algorithm>>{{"HASH", Algorithm::kSha256}}),
        nullptr,
        /*fail_init=*/true);
    auto mediator = MakeMediator();

    const auto response = QueryCapabilities(mediator, "SHA256");
    EXPECT_TRUE(OnlyOperations(OnlyOperation(response)).empty());
}

TEST_F(MediatorCapabilitiesTest, QueryCapabilitiesRejectsMissingOrMistypedName)
{
    auto mediator = MakeMediator();

    const auto missing = Send(mediator, [](auto& b) {
        b.operation(operations::QueryCapabilities());
    });
    EXPECT_EQ(OnlyOperation(missing).result, kInvalidArgument);
    EXPECT_TRUE(OnlyOperation(missing).parameters.empty());

    const auto as_number = Send(mediator, [](auto& b) {
        b.operation(operations::QueryCapabilities()).with_in_val_uint64(4U);
    });
    EXPECT_EQ(OnlyOperation(as_number).result, kInvalidArgument);
}

// ---------------------------------------------------------------------------
// SYSTEM_CAPABILITIES
// ---------------------------------------------------------------------------

TEST_F(MediatorCapabilitiesTest, SystemCapabilitiesListsProvidersByIdThenSupportedCatalogRows)
{
    Register("ZETA",
             common::CryptoProviderType::SOFTWARE,
             std::make_shared<FakeHandlerFactory>(std::set<std::pair<std::string, Algorithm>>{
                 {"HASH", Algorithm::kSha256}, {"RANDOM", Algorithm::kCtrDrbg}}));
    Register("ALPHA",
             common::CryptoProviderType::HARDWARE,
             nullptr,
             std::make_shared<FakeKeyFactory>(std::set<Algorithm>{Algorithm::kHmacSha256}));
    Register("MIDDLE", common::CryptoProviderType::SPECIALIZED, nullptr);
    auto mediator = MakeMediator();

    const auto response = SystemCapabilities(mediator);
    const auto& op = OnlyOperation(response);
    ASSERT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS);

    std::size_t i = 0U;
    EXPECT_EQ(std::get<std::uint16_t>(op.parameters[i++]), 3U);
    const std::vector<std::tuple<std::uint16_t, std::uint8_t, std::string>> providers{
        {0U, 2U, "ZETA"}, {1U, 1U, "ALPHA"}, {2U, 0U, "MIDDLE"}};
    for (const auto& [id, wire_type, name] : providers)
    {
        EXPECT_EQ(std::get<std::uint16_t>(op.parameters[i++]), id);
        EXPECT_EQ(std::get<std::uint8_t>(op.parameters[i++]), wire_type);
        EXPECT_EQ(ToString(op.parameters[i++]), name);
    }

    // Catalog order; rows no provider serves are omitted.
    EXPECT_EQ(std::get<std::uint16_t>(op.parameters[i++]), 3U);
    const std::vector<std::pair<std::string, std::vector<std::string>>> algorithms{
        {"SHA256", {"HASH"}}, {"HMAC-SHA256", {"GENERATE_KEY"}}, {"CTR-DRBG", {"RANDOM"}}};
    for (const auto& [name, ops] : algorithms)
    {
        EXPECT_EQ(ToString(op.parameters.at(i++)), name);
        EXPECT_EQ(ReadOperations(op, i), ops) << name;
    }
    EXPECT_EQ(i, op.parameters.size());
}

TEST_F(MediatorCapabilitiesTest, SystemCapabilitiesLeavesOutProviderThatFailedToInitialize)
{
    Register("SW_PROV", common::CryptoProviderType::SOFTWARE, nullptr);
    Register(
        "BROKEN",
        common::CryptoProviderType::HARDWARE,
        std::make_shared<FakeHandlerFactory>(std::set<std::pair<std::string, Algorithm>>{{"HASH", Algorithm::kSha256}}),
        nullptr,
        /*fail_init=*/true);
    auto mediator = MakeMediator();

    const auto response = SystemCapabilities(mediator);
    const auto& op = OnlyOperation(response);
    ASSERT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(op.parameters.size(), 1U + 3U + 1U);
    EXPECT_EQ(std::get<std::uint16_t>(op.parameters[0]), 1U);
    EXPECT_EQ(ToString(op.parameters[3]), "SW_PROV");
    EXPECT_EQ(std::get<std::uint16_t>(op.parameters[4]), 0U);
}

TEST_F(MediatorCapabilitiesTest, SystemCapabilitiesRefusesMoreProvidersThanTheClientHolds)
{
    for (std::size_t i = 0U; i <= ::score::crypto::SystemCapabilities::kMaxProviders; ++i)
    {
        Register("P" + std::to_string(i), common::CryptoProviderType::SOFTWARE, nullptr);
    }
    auto mediator = MakeMediator();

    const auto response = SystemCapabilities(mediator);
    const auto& op = OnlyOperation(response);
    EXPECT_EQ(op.result, static_cast<protocol::OperationResult>(CryptoErrorCode::kInsufficientBufferSize));
    EXPECT_TRUE(op.parameters.empty());
}

TEST_F(MediatorCapabilitiesTest, SystemCapabilitiesIsEmptyWithoutProviderManager)
{
    auto mediator = MakeMediator(/*with_manager=*/false);

    const auto response = SystemCapabilities(mediator);
    const auto& op = OnlyOperation(response);
    ASSERT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(op.parameters.size(), 2U);
    EXPECT_EQ(std::get<std::uint16_t>(op.parameters[0]), 0U);
    EXPECT_EQ(std::get<std::uint16_t>(op.parameters[1]), 0U);
}

}  // namespace
}  // namespace score::crypto::daemon::mediator
