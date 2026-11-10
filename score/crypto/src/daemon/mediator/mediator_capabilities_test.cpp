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
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
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
namespace flags = operations::capability_flags;
using score::crypto::Algorithm;

constexpr auto kInvalidArgument = static_cast<protocol::OperationResult>(CryptoErrorCode::kInvalidArgument);
constexpr auto kInvalidResourceId = static_cast<protocol::OperationResult>(CryptoErrorCode::kInvalidResourceId);
constexpr auto kProviderType = static_cast<std::uint64_t>(score::crypto::ResourceType::kProvider);

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

    static const protocol::SingleOperationResponse& OnlyOperation(const protocol::ControlResponse& response)
    {
        EXPECT_EQ(response.operation.operations.size(), 1U);
        return response.operation.operations.front();
    }

    std::shared_ptr<provider::ProviderManager> m_manager{
        std::make_shared<provider::ProviderManager>(config::Config{}.GetProviderInitConfig())};
    common::ProviderId m_next_id{0U};
};

/// Fixture for application-scoped provider resources (issue #290): a real
/// DataManager plus requests sent on behalf of a given uid/pid.
class MediatorProviderResourceTest : public MediatorCapabilitiesTest
{
  protected:
    static constexpr std::uint32_t kAppUid{1000U};
    static constexpr std::uint32_t kOtherUid{1001U};

    void SetUp() override
    {
        Register("OPENSSL", common::CryptoProviderType::SOFTWARE, nullptr);
        Register("PKCS11_ENGINE", common::CryptoProviderType::HARDWARE, nullptr);
        (void)m_manager->Initialize();
        ASSERT_TRUE(m_manager->RegisterAppProvider(kAppUid, "app/sw", "OPENSSL"));
        ASSERT_TRUE(m_manager->RegisterAppProvider(kAppUid, "app/hw", "PKCS11_ENGINE"));
        ASSERT_TRUE(m_manager->RegisterAppProvider(kOtherUid, "other/hw", "PKCS11_ENGINE"));
    }

    MediatorImpl MakeResourceMediator(bool with_manager = true)
    {
        return MediatorImpl{MediatorDependencies{m_data_manager, with_manager ? m_manager : nullptr, nullptr, nullptr}};
    }

    static std::uint64_t ClientOf(std::uint32_t uid, std::uint32_t pid = 42U)
    {
        return (static_cast<std::uint64_t>(uid) << 32U) | pid;
    }

    template <typename BuildOperation>
    static protocol::ControlResponse SendAs(MediatorImpl& mediator,
                                            std::uint64_t client_id,
                                            BuildOperation&& build_operation)
    {
        protocol::ControlRequestBuilder builder;
        builder.forDataNodeId(1U);
        build_operation(builder);
        auto request = builder.build();
        EXPECT_TRUE(request.has_value());
        request.value().client_id = client_id;
        return mediator.processRequest(request.value());
    }

    static protocol::ControlResponse Resolve(MediatorImpl& mediator, std::uint64_t client_id, std::string_view name)
    {
        return SendAs(mediator, client_id, [name](auto& b) {
            b.operation(operations::ResolveResource()).with_in_string(name).with_in_val_uint64(kProviderType);
        });
    }

    static protocol::ControlResponse ProviderInfoByHandle(MediatorImpl& mediator,
                                                          std::uint64_t client_id,
                                                          std::uint64_t handle)
    {
        return SendAs(mediator, client_id, [handle](auto& b) {
            b.operation(operations::GetProviderInfo()).with_in_val_uint64(handle).with_in_val_uint64(kProviderType);
        });
    }

    /// Resolves @p name and returns the handle; fails the test if resolution fails.
    std::uint64_t ResolveHandle(MediatorImpl& mediator, std::uint64_t client_id, std::string_view name)
    {
        const auto response = Resolve(mediator, client_id, name);
        const auto& op = OnlyOperation(response);
        EXPECT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS) << name;
        return op.parameters.empty() ? 0U : std::get<std::uint64_t>(op.parameters[0]);
    }

    std::shared_ptr<data_manager::DataManager> m_data_manager{std::make_shared<data_manager::DataManager>()};
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

TEST_F(MediatorCapabilitiesTest, QueryCapabilitiesUnionsFlagsAcrossProviders)
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
    ASSERT_EQ(op.parameters.size(), 1U);
    EXPECT_EQ(std::get<std::uint8_t>(op.parameters[0]), flags::kMac | flags::kGenerateKey);
}

TEST_F(MediatorCapabilitiesTest, QueryCapabilitiesMapsEveryContextTypeToItsFlag)
{
    const std::vector<std::pair<std::string, std::uint8_t>> context_flags{{"HASH", flags::kHash},
                                                                          {"MAC", flags::kMac},
                                                                          {"CIPHER", flags::kCipher},
                                                                          {"SIGN", flags::kSign},
                                                                          {"VERIFY", flags::kVerify},
                                                                          {"RANDOM", flags::kRandom}};
    std::set<std::pair<std::string, Algorithm>> supported;
    for (const auto& [context, flag] : context_flags)
    {
        supported.insert({context, Algorithm::kSha256});
    }
    Register("ALL", common::CryptoProviderType::SOFTWARE, std::make_shared<FakeHandlerFactory>(supported));
    auto mediator = MakeMediator();

    const auto response = QueryCapabilities(mediator, "SHA256");
    const auto& op = OnlyOperation(response);
    ASSERT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(std::get<std::uint8_t>(op.parameters[0]),
              flags::kHash | flags::kMac | flags::kCipher | flags::kSign | flags::kVerify | flags::kRandom);
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
    EXPECT_EQ(std::get<std::uint8_t>(op.parameters[0]), flags::kRandom);
}

TEST_F(MediatorCapabilitiesTest, QueryCapabilitiesReportsZeroForUnknownOrUnservedAlgorithm)
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
        EXPECT_EQ(std::get<std::uint8_t>(op.parameters[0]), 0U) << name;
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
    EXPECT_EQ(std::get<std::uint8_t>(OnlyOperation(response).parameters[0]), 0U);
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

    // 1 count + 3 x (id, type, name) + 1 count + 3 x (name, flags)
    ASSERT_EQ(op.parameters.size(), 1U + 9U + 1U + 6U);
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
    const std::vector<std::pair<std::string, std::uint8_t>> algorithms{
        {"SHA256", flags::kHash}, {"HMAC-SHA256", flags::kGenerateKey}, {"CTR-DRBG", flags::kRandom}};
    for (const auto& [name, ops] : algorithms)
    {
        EXPECT_EQ(ToString(op.parameters[i++]), name);
        EXPECT_EQ(std::get<std::uint8_t>(op.parameters[i++]), ops);
    }
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

// ---------------------------------------------------------------------------
// RESOLVE_RESOURCE (kProvider) and PROVIDER_INFO by handle
// ---------------------------------------------------------------------------

TEST_F(MediatorProviderResourceTest, ResolvesMappedNameToOpaqueProviderHandle)
{
    auto mediator = MakeResourceMediator();

    const auto response = Resolve(mediator, ClientOf(kAppUid), "app/hw");
    const auto& op = OnlyOperation(response);
    ASSERT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(op.parameters.size(), 4U);
    const auto handle = std::get<std::uint64_t>(op.parameters[0]);
    EXPECT_EQ(std::get<std::uint8_t>(op.parameters[1]), static_cast<std::uint8_t>(kProviderType));
    EXPECT_TRUE(std::get<bool>(op.parameters[2]));
    EXPECT_EQ(std::get<std::uint16_t>(op.parameters[3]), common::kInvalidProviderId);

    auto accessor = m_data_manager->getNodeAccessor(ClientOf(kAppUid), handle);
    ASSERT_TRUE(accessor.has_value());
    EXPECT_EQ(accessor.value()->GetNodeType(), data_manager::DataNodeType::kProvider);
}

TEST_F(MediatorProviderResourceTest, ResolutionFailsAlikeForUnmappedForeignAndProviderNames)
{
    auto mediator = MakeResourceMediator();

    // Unknown name, another uid's name, and configured provider names all fail
    // with the same code, so a client cannot probe which names exist.
    for (const std::string_view name : {"app/unknown", "other/hw", "OPENSSL", "PKCS11_ENGINE", ""})
    {
        const auto response = Resolve(mediator, ClientOf(kAppUid), name);
        const auto& op = OnlyOperation(response);
        EXPECT_EQ(op.result, kInvalidResourceId) << name;
        EXPECT_TRUE(op.parameters.empty()) << name;
    }
}

TEST_F(MediatorProviderResourceTest, SameNameResolvesPerUid)
{
    ASSERT_TRUE(m_manager->RegisterAppProvider(kOtherUid, "app/hw", "OPENSSL"));
    auto mediator = MakeResourceMediator();

    const auto app_handle = ResolveHandle(mediator, ClientOf(kAppUid), "app/hw");
    const auto other_handle = ResolveHandle(mediator, ClientOf(kOtherUid), "app/hw");

    const auto app_info = ProviderInfoByHandle(mediator, ClientOf(kAppUid), app_handle);
    const auto other_info = ProviderInfoByHandle(mediator, ClientOf(kOtherUid), other_handle);
    ASSERT_EQ(OnlyOperation(app_info).result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(OnlyOperation(other_info).result, protocol::OPERATION_RESULT_SUCCESS);
    EXPECT_EQ(ToString(OnlyOperation(app_info).parameters[2]), "PKCS11_ENGINE");
    EXPECT_EQ(ToString(OnlyOperation(other_info).parameters[2]), "OPENSSL");
}

TEST_F(MediatorProviderResourceTest, ResolutionFailsWithoutProviderManager)
{
    auto mediator = MakeResourceMediator(/*with_manager=*/false);
    const auto response = Resolve(mediator, ClientOf(kAppUid), "app/sw");
    EXPECT_EQ(OnlyOperation(response).result, kInvalidResourceId);
}

TEST_F(MediatorProviderResourceTest, ResolutionFailsWithoutDataManager)
{
    auto mediator = MakeMediator();
    const auto response = Resolve(mediator, ClientOf(kAppUid), "app/sw");
    EXPECT_EQ(OnlyOperation(response).result, kInvalidResourceId);
}

TEST_F(MediatorProviderResourceTest, ProviderInfoByHandleReportsMappedProvider)
{
    auto mediator = MakeResourceMediator();
    const auto handle = ResolveHandle(mediator, ClientOf(kAppUid), "app/hw");

    const auto response = ProviderInfoByHandle(mediator, ClientOf(kAppUid), handle);
    const auto& op = OnlyOperation(response);
    ASSERT_EQ(op.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(op.parameters.size(), 3U);
    EXPECT_EQ(std::get<std::uint16_t>(op.parameters[0]), 1U);
    EXPECT_EQ(std::get<std::uint8_t>(op.parameters[1]), 1U);
    EXPECT_EQ(ToString(op.parameters[2]), "PKCS11_ENGINE");
}

TEST_F(MediatorProviderResourceTest, ProviderInfoByHandleRejectsHandleOfAnotherClient)
{
    auto mediator = MakeResourceMediator();
    const auto handle = ResolveHandle(mediator, ClientOf(kAppUid), "app/hw");

    for (const auto client : {ClientOf(kOtherUid), ClientOf(kAppUid, 43U)})
    {
        const auto response = ProviderInfoByHandle(mediator, client, handle);
        const auto& op = OnlyOperation(response);
        EXPECT_EQ(op.result, kInvalidResourceId) << client;
        EXPECT_TRUE(op.parameters.empty()) << client;
    }
}

TEST_F(MediatorProviderResourceTest, ProviderInfoByHandleRejectsUnknownOrNonProviderNode)
{
    auto mediator = MakeResourceMediator();
    const auto handle = ResolveHandle(mediator, ClientOf(kAppUid), "app/hw");

    class OtherNode final : public data_manager::DataNode
    {
      public:
        OtherNode() : DataNode(false) {}
        data_manager::DataNodeType GetNodeType() const noexcept override
        {
            return data_manager::DataNodeType::kKeySlot;
        }
    };
    const auto other = m_data_manager->addNode(ClientOf(kAppUid), std::make_shared<OtherNode>());
    ASSERT_TRUE(other.has_value());

    for (const std::uint64_t id : {handle + 100U, static_cast<std::uint64_t>(other.value())})
    {
        const auto response = ProviderInfoByHandle(mediator, ClientOf(kAppUid), id);
        EXPECT_EQ(OnlyOperation(response).result, kInvalidResourceId) << id;
    }
}

TEST_F(MediatorProviderResourceTest, ProviderInfoRejectsUnknownResourceTypeSelector)
{
    auto mediator = MakeResourceMediator();
    const auto handle = ResolveHandle(mediator, ClientOf(kAppUid), "app/hw");

    const auto response = SendAs(mediator, ClientOf(kAppUid), [handle](auto& b) {
        b.operation(operations::GetProviderInfo())
            .with_in_val_uint64(handle)
            .with_in_val_uint64(static_cast<std::uint64_t>(score::crypto::ResourceType::kKeySlot));
    });
    EXPECT_EQ(OnlyOperation(response).result, kInvalidArgument);
}

TEST_F(MediatorProviderResourceTest, ProviderInfoByHandleWithoutDataManagerIsRejected)
{
    auto mediator = MakeMediator();
    const auto response = ProviderInfoByHandle(mediator, ClientOf(kAppUid), 1U);
    EXPECT_EQ(OnlyOperation(response).result, kInvalidResourceId);
}

}  // namespace
}  // namespace score::crypto::daemon::mediator
