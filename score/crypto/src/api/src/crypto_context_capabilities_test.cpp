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

// Unit tests for how CryptoContextImpl encodes the provider and capability
// queries and decodes the daemon's replies, using a scripted connection.

#include "score/crypto/src/api/src/crypto_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace score::crypto
{
namespace
{

namespace protocol = daemon::control_plane::protocol;
namespace med_ops = daemon::mediator::operations;
namespace flags = med_ops::capability_flags;

/// Replies with a prepared response and records the request it was sent.
class ScriptedConnection final : public api::control_plane::IConnection
{
  public:
    Expected<protocol::ControlResponse, CryptoErrorCode> SendRequest(const protocol::ControlRequest& request) override
    {
        m_last_request = request;
        if (m_transport_error.has_value())
        {
            return make_unexpected(m_transport_error.value());
        }
        protocol::ControlResponse response{};
        response.operation.operations.push_back(m_reply);
        return response;
    }

    protocol::DataNodeId GetConnectionNodeId() const override
    {
        return 1U;
    }

    void Reply(const protocol::OperationIdentifier& op, daemon::common::ResponseParameters parameters)
    {
        m_reply = protocol::SingleOperationResponse{op, protocol::OPERATION_RESULT_SUCCESS, std::move(parameters)};
    }

    void Fail(const protocol::OperationIdentifier& op, CryptoErrorCode code)
    {
        m_reply = protocol::SingleOperationResponse{op, static_cast<protocol::OperationResult>(code), {}};
    }

    void FailTransport(CryptoErrorCode code)
    {
        m_transport_error = code;
    }

    const protocol::SingleOperationRequest& LastOperation() const
    {
        EXPECT_TRUE(m_last_request.has_value());
        EXPECT_EQ(m_last_request->operation.operations.size(), 1U);
        return m_last_request->operation.operations.front();
    }

  private:
    protocol::SingleOperationResponse m_reply{};
    std::optional<protocol::ControlRequest> m_last_request{};
    std::optional<CryptoErrorCode> m_transport_error{};
};

daemon::common::OwnedBuffer Bytes(std::string_view text)
{
    return daemon::common::OwnedBuffer(text.begin(), text.end());
}

template <std::size_t N>
std::string_view View(const FixedCapacityString<N>& text)
{
    return std::string_view{text.c_str(), text.size()};
}

bool IsOperation(const protocol::OperationIdentifier& actual, const protocol::OperationIdentifier& expected)
{
    return (actual.operationActor == expected.operationActor) && (actual.operationAction == expected.operationAction);
}

score::result::ErrorCode Code(CryptoErrorCode code)
{
    return static_cast<score::result::ErrorCode>(code);
}

class CryptoContextCapabilitiesTest : public ::testing::Test
{
  protected:
    std::shared_ptr<ScriptedConnection> m_connection{std::make_shared<ScriptedConnection>()};
    CryptoContextImpl m_context{m_connection, nullptr};
};

// ---------------------------------------------------------------------------
// GetProviderInfo
// ---------------------------------------------------------------------------

TEST_F(CryptoContextCapabilitiesTest, GetProviderInfoSendsIdAndDecodesReply)
{
    // The daemon sends no name for a lookup by id.
    m_connection->Reply(med_ops::GetProviderInfo(), {std::uint16_t{1U}, std::uint8_t{1U}, Bytes("")});

    const auto info = m_context.GetProviderInfo(std::uint16_t{1U});

    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->id, 1U);
    EXPECT_EQ(info->type, ProviderType::kHardware);
    EXPECT_EQ(View(info->name), "");

    const auto& sent = m_connection->LastOperation();
    EXPECT_TRUE(IsOperation(sent.operationId, med_ops::GetProviderInfo()));
    ASSERT_EQ(sent.parameters.size(), 1U);
    EXPECT_EQ(std::get<std::uint64_t>(sent.parameters[0]), 1U);
}

TEST_F(CryptoContextCapabilitiesTest, GetProviderInfoByResourceAsksForItsPrimaryProvider)
{
    m_connection->Reply(med_ops::GetProviderInfo(), {std::uint16_t{3U}, std::uint8_t{2U}, Bytes("")});
    CryptoResourceId resource{};
    resource.id = 99U;
    resource.primary_provider = 3U;

    const auto info = m_context.GetProviderInfo(resource);

    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->type, ProviderType::kSoftware);
    ASSERT_EQ(m_connection->LastOperation().parameters.size(), 1U);
    EXPECT_EQ(std::get<std::uint64_t>(m_connection->LastOperation().parameters[0]), 3U);
}

TEST_F(CryptoContextCapabilitiesTest, GetProviderInfoByProviderHandleSendsHandleAndType)
{
    m_connection->Reply(med_ops::GetProviderInfo(), {std::uint16_t{1U}, std::uint8_t{1U}, Bytes("app/hw")});
    CryptoResourceId handle{};
    handle.id = 7U;
    handle.type = ResourceType::kProvider;
    handle.persistence = ResourcePersistence::kPersistent;
    handle.primary_provider = 0xFFFFU;

    const auto info = m_context.GetProviderInfo(handle);

    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->id, 1U);
    EXPECT_EQ(View(info->name), "app/hw");
    const auto& sent = m_connection->LastOperation();
    ASSERT_EQ(sent.parameters.size(), 2U);
    EXPECT_EQ(std::get<std::uint64_t>(sent.parameters[0]), 7U);
    EXPECT_EQ(std::get<std::uint64_t>(sent.parameters[1]), static_cast<std::uint64_t>(ResourceType::kProvider));
}

TEST_F(CryptoContextCapabilitiesTest, GetProviderInfoKeepsAnAppNameAsLongAsAResourceId)
{
    // The name of a provider resource is the app_resource_id it was resolved by.
    const std::string longest(ResourceId{}.capacity(), 'n');
    m_connection->Reply(med_ops::GetProviderInfo(), {std::uint16_t{1U}, std::uint8_t{1U}, Bytes(longest)});
    CryptoResourceId handle{};
    handle.id = 7U;
    handle.type = ResourceType::kProvider;

    const auto info = m_context.GetProviderInfo(handle);

    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(View(info->name), longest);
    EXPECT_FALSE(info->name.truncated());
}

TEST_F(CryptoContextCapabilitiesTest, GetProviderInfoMapsUnknownWireTypeToDefault)
{
    for (const std::uint8_t wire_type : {std::uint8_t{0U}, std::uint8_t{5U}, std::uint8_t{0xFFU}})
    {
        m_connection->Reply(med_ops::GetProviderInfo(), {std::uint16_t{0U}, wire_type, Bytes("X")});
        const auto info = m_context.GetProviderInfo(std::uint16_t{0U});
        ASSERT_TRUE(info.has_value());
        EXPECT_EQ(info->type, ProviderType::kDefault) << static_cast<int>(wire_type);
    }
}

TEST_F(CryptoContextCapabilitiesTest, GetProviderInfoForwardsDaemonError)
{
    m_connection->Fail(med_ops::GetProviderInfo(), CryptoErrorCode::kInvalidArgument);

    const auto info = m_context.GetProviderInfo(std::uint16_t{42U});

    ASSERT_FALSE(info.has_value());
    EXPECT_EQ(*info.error(), Code(CryptoErrorCode::kInvalidArgument));
}

TEST_F(CryptoContextCapabilitiesTest, GetProviderInfoReportsInternalErrorForBrokenReplies)
{
    // Transport failure: no daemon verdict.
    {
        auto connection = std::make_shared<ScriptedConnection>();
        connection->FailTransport(CryptoErrorCode::kConnectionFailed);
        CryptoContextImpl context{connection, nullptr};
        const auto info = context.GetProviderInfo(std::uint16_t{0U});
        ASSERT_FALSE(info.has_value());
        EXPECT_EQ(*info.error(), Code(CryptoErrorCode::kInternalError));
    }
    // Reply for a different operation.
    m_connection->Reply(med_ops::QueryCapabilities(), {std::uint16_t{0U}, std::uint8_t{2U}, Bytes("OPENSSL")});
    EXPECT_EQ(*m_context.GetProviderInfo(std::uint16_t{0U}).error(), Code(CryptoErrorCode::kInternalError));
    // Missing name.
    m_connection->Reply(med_ops::GetProviderInfo(), {std::uint16_t{0U}, std::uint8_t{2U}});
    EXPECT_EQ(*m_context.GetProviderInfo(std::uint16_t{0U}).error(), Code(CryptoErrorCode::kInternalError));
    // Id sent with the wrong width.
    m_connection->Reply(med_ops::GetProviderInfo(), {std::uint64_t{0U}, std::uint8_t{2U}, Bytes("OPENSSL")});
    EXPECT_EQ(*m_context.GetProviderInfo(std::uint16_t{0U}).error(), Code(CryptoErrorCode::kInternalError));
}

// ---------------------------------------------------------------------------
// QueryCapabilities(algorithm)
// ---------------------------------------------------------------------------

TEST_F(CryptoContextCapabilitiesTest, QueryCapabilitiesSendsNameAndListsModesInFlagOrder)
{
    m_connection->Reply(med_ops::QueryCapabilities(),
                        {std::uint8_t{flags::kGenerateKey | flags::kVerify | flags::kSign}});

    const auto caps = m_context.QueryCapabilities(AlgorithmId{"ECDSA-P256-SHA256"});

    ASSERT_TRUE(caps.has_value());
    EXPECT_EQ(View(caps->id), "ECDSA-P256-SHA256");
    EXPECT_TRUE(caps->supported);
    ASSERT_EQ(caps->mode_count, 3U);
    EXPECT_EQ(View(caps->modes[0]), "SIGN");
    EXPECT_EQ(View(caps->modes[1]), "VERIFY");
    EXPECT_EQ(View(caps->modes[2]), "GENERATE_KEY");

    const auto& sent = m_connection->LastOperation();
    EXPECT_TRUE(IsOperation(sent.operationId, med_ops::QueryCapabilities()));
    ASSERT_EQ(sent.parameters.size(), 1U);
    EXPECT_EQ(std::get<std::string_view>(sent.parameters[0]), "ECDSA-P256-SHA256");
}

TEST_F(CryptoContextCapabilitiesTest, QueryCapabilitiesNamesEveryFlag)
{
    m_connection->Reply(med_ops::QueryCapabilities(), {std::uint8_t{0x7FU}});

    const auto caps = m_context.QueryCapabilities(AlgorithmId{"SHA256"});

    ASSERT_TRUE(caps.has_value());
    const std::vector<std::string_view> expected{"HASH", "MAC", "CIPHER", "SIGN", "VERIFY", "RANDOM", "GENERATE_KEY"};
    ASSERT_EQ(caps->mode_count, expected.size());
    for (std::size_t i = 0U; i < expected.size(); ++i)
    {
        EXPECT_EQ(View(caps->modes[i]), expected[i]);
    }
}

TEST_F(CryptoContextCapabilitiesTest, QueryCapabilitiesReportsUnsupportedForZeroFlags)
{
    m_connection->Reply(med_ops::QueryCapabilities(), {std::uint8_t{0U}});

    const auto caps = m_context.QueryCapabilities(AlgorithmId{"NOT-AN-ALGORITHM"});

    ASSERT_TRUE(caps.has_value());
    EXPECT_FALSE(caps->supported);
    EXPECT_EQ(caps->mode_count, 0U);
}

TEST_F(CryptoContextCapabilitiesTest, QueryCapabilitiesForwardsDaemonErrorAndRejectsMissingFlags)
{
    m_connection->Fail(med_ops::QueryCapabilities(), CryptoErrorCode::kInvalidArgument);
    EXPECT_EQ(*m_context.QueryCapabilities(AlgorithmId{"SHA256"}).error(), Code(CryptoErrorCode::kInvalidArgument));

    m_connection->Reply(med_ops::QueryCapabilities(), {});
    EXPECT_EQ(*m_context.QueryCapabilities(AlgorithmId{"SHA256"}).error(), Code(CryptoErrorCode::kInternalError));
}

// ---------------------------------------------------------------------------
// QueryCapabilities() - system snapshot
// ---------------------------------------------------------------------------

TEST_F(CryptoContextCapabilitiesTest, SystemCapabilitiesDecodesProvidersAndAlgorithms)
{
    m_connection->Reply(med_ops::QuerySystemCapabilities(),
                        {std::uint16_t{2U},
                         std::uint16_t{0U},
                         std::uint8_t{2U},
                         Bytes(""),
                         std::uint16_t{1U},
                         std::uint8_t{1U},
                         Bytes(""),
                         std::uint16_t{2U},
                         Bytes("HMAC-SHA256"),
                         std::uint8_t{flags::kMac | flags::kGenerateKey},
                         Bytes("CTR-DRBG"),
                         std::uint8_t{flags::kRandom}});

    const auto caps = m_context.QueryCapabilities();

    ASSERT_TRUE(caps.has_value());
    EXPECT_TRUE(IsOperation(m_connection->LastOperation().operationId, med_ops::QuerySystemCapabilities()));
    EXPECT_TRUE(m_connection->LastOperation().parameters.empty());

    ASSERT_EQ(caps->provider_count, 2U);
    EXPECT_EQ(caps->providers[0].id, 0U);
    EXPECT_EQ(caps->providers[0].type, ProviderType::kSoftware);
    EXPECT_EQ(View(caps->providers[0].name), "");
    EXPECT_EQ(caps->providers[1].id, 1U);
    EXPECT_EQ(caps->providers[1].type, ProviderType::kHardware);
    EXPECT_EQ(View(caps->providers[1].name), "");

    ASSERT_EQ(caps->algorithm_count, 2U);
    EXPECT_EQ(View(caps->algorithms[0].id), "HMAC-SHA256");
    ASSERT_EQ(caps->algorithms[0].mode_count, 2U);
    EXPECT_EQ(View(caps->algorithms[0].modes[0]), "MAC");
    EXPECT_EQ(View(caps->algorithms[0].modes[1]), "GENERATE_KEY");
    EXPECT_EQ(View(caps->algorithms[1].id), "CTR-DRBG");
    EXPECT_EQ(View(caps->algorithms[1].modes[0]), "RANDOM");
}

TEST_F(CryptoContextCapabilitiesTest, SystemCapabilitiesKeepsTheFirstEntriesThatFit)
{
    const std::size_t providers = SystemCapabilities::kMaxProviders + 1U;
    const std::size_t algorithms = SystemCapabilities::kMaxAlgorithms + 1U;
    daemon::common::ResponseParameters reply{static_cast<std::uint16_t>(providers)};
    for (std::size_t i = 0U; i < providers; ++i)
    {
        reply.emplace_back(static_cast<std::uint16_t>(i));
        reply.emplace_back(std::uint8_t{2U});
        reply.emplace_back(Bytes(""));
    }
    reply.emplace_back(static_cast<std::uint16_t>(algorithms));
    for (std::size_t i = 0U; i < algorithms; ++i)
    {
        reply.emplace_back(Bytes("A" + std::to_string(i)));
        reply.emplace_back(std::uint8_t{flags::kHash});
    }
    m_connection->Reply(med_ops::QuerySystemCapabilities(), std::move(reply));

    const auto caps = m_context.QueryCapabilities();

    ASSERT_TRUE(caps.has_value());
    EXPECT_EQ(caps->provider_count, SystemCapabilities::kMaxProviders);
    EXPECT_EQ(caps->providers[SystemCapabilities::kMaxProviders - 1U].id, SystemCapabilities::kMaxProviders - 1U);
    EXPECT_EQ(caps->algorithm_count, SystemCapabilities::kMaxAlgorithms);
    EXPECT_EQ(View(caps->algorithms[SystemCapabilities::kMaxAlgorithms - 1U].id),
              "A" + std::to_string(SystemCapabilities::kMaxAlgorithms - 1U));
}

TEST_F(CryptoContextCapabilitiesTest, SystemCapabilitiesRejectsMalformedReplies)
{
    const std::vector<std::pair<std::string, daemon::common::ResponseParameters>> malformed{
        {"empty", {}},
        {"provider count larger than entries", {std::uint16_t{2U}, std::uint16_t{0U}, std::uint8_t{2U}, Bytes("A")}},
        {"provider entry mistyped", {std::uint16_t{1U}, std::uint16_t{0U}, std::uint16_t{2U}, Bytes("A")}},
        {"algorithm count missing", {std::uint16_t{0U}}},
        {"algorithm count larger than entries", {std::uint16_t{0U}, std::uint16_t{1U}, Bytes("SHA256")}},
        {"algorithm flags mistyped", {std::uint16_t{0U}, std::uint16_t{1U}, Bytes("SHA256"), std::uint16_t{1U}}},
    };
    for (const auto& [label, reply] : malformed)
    {
        m_connection->Reply(med_ops::QuerySystemCapabilities(), reply);
        const auto caps = m_context.QueryCapabilities();
        ASSERT_FALSE(caps.has_value()) << label;
        EXPECT_EQ(*caps.error(), Code(CryptoErrorCode::kInternalError)) << label;
    }
}

TEST_F(CryptoContextCapabilitiesTest, SystemCapabilitiesForwardsDaemonError)
{
    m_connection->Fail(med_ops::QuerySystemCapabilities(), CryptoErrorCode::kQuotaExceeded);

    const auto caps = m_context.QueryCapabilities();

    ASSERT_FALSE(caps.has_value());
    EXPECT_EQ(*caps.error(), Code(CryptoErrorCode::kQuotaExceeded));
}

}  // namespace
}  // namespace score::crypto
