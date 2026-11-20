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

// Unit tests for ProviderCapabilityQuery used on its own, without a mediator.
// The answers themselves are covered through the mediator in mediator_capabilities_test.

#include "score/crypto/src/daemon/provider/provider_capability_query.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <utility>

namespace score::crypto::daemon::provider
{
namespace
{

namespace protocol = control_plane::protocol;
namespace mediator_ops = mediator::operations;

constexpr auto kUnsupportedOperation =
    static_cast<protocol::OperationResult>(score::crypto::CryptoErrorCode::kUnsupportedOperation);
constexpr auto kInvalidArgument =
    static_cast<protocol::OperationResult>(score::crypto::CryptoErrorCode::kInvalidArgument);

/// Builds a one-operation request, hands it to @p query and returns the operation's response.
template <typename BuildOperation>
protocol::SingleOperationResponse RunQuery(const ProviderCapabilityQuery& query, BuildOperation&& build_operation)
{
    protocol::ControlRequestBuilder builder;
    builder.forDataNodeId(1U);
    build_operation(builder);
    auto request = builder.build();
    EXPECT_TRUE(request.has_value());
    EXPECT_EQ(request.value().operation.operations.size(), 1U);

    protocol::OperationResponseBuilder response_builder;
    (void)query.Handle(request.value(), request.value().operation.operations.front(), response_builder);
    const auto response = response_builder.build();
    EXPECT_TRUE(response.has_value());
    EXPECT_EQ(response.value().operations.size(), 1U);
    return response.value().operations.front();
}

TEST(ProviderCapabilityQueryTest, ServesExactlyTheProviderAndCapabilityQueries)
{
    for (const auto action : ProviderCapabilityQuery::kOperations)
    {
        EXPECT_TRUE(ProviderCapabilityQuery::Serves(action)) << action;
    }
    EXPECT_TRUE(ProviderCapabilityQuery::Serves(mediator_ops::PROVIDER_INFO));
    EXPECT_TRUE(ProviderCapabilityQuery::Serves(mediator_ops::QUERY_CAPABILITIES));
    EXPECT_TRUE(ProviderCapabilityQuery::Serves(mediator_ops::SYSTEM_CAPABILITIES));
    EXPECT_FALSE(ProviderCapabilityQuery::Serves(mediator_ops::CTX_CREATE));
    EXPECT_FALSE(ProviderCapabilityQuery::Serves(mediator_ops::RESOLVE_RESOURCE));
}

TEST(ProviderCapabilityQueryTest, RejectsAnOperationItDoesNotServe)
{
    const ProviderCapabilityQuery query{nullptr};
    const auto op = RunQuery(query, [](auto& b) {
        b.operation(protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                  .operationAction = mediator_ops::RESOLVE_RESOURCE});
    });
    EXPECT_EQ(op.result, kUnsupportedOperation);
}

TEST(ProviderCapabilityQueryTest, WithoutProviderManagerReportsNoProviderAndRejectsProviderInfo)
{
    const ProviderCapabilityQuery query{nullptr};

    const auto info = RunQuery(query, [](auto& b) {
        b.operation(mediator_ops::GetProviderInfo()).with_in_val_uint64(0U);
    });
    EXPECT_EQ(info.result, kInvalidArgument);

    const auto caps = RunQuery(query, [](auto& b) {
        b.operation(mediator_ops::QueryCapabilities()).with_in_string("SHA-256");
    });
    ASSERT_EQ(caps.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(caps.parameters.size(), 1U);
    EXPECT_EQ(std::get<std::uint16_t>(caps.parameters[0]), 0U);

    const auto system = RunQuery(query, [](auto& b) {
        b.operation(mediator_ops::QuerySystemCapabilities());
    });
    ASSERT_EQ(system.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(system.parameters.size(), 2U);
    EXPECT_EQ(std::get<std::uint16_t>(system.parameters[0]), 0U);
    EXPECT_EQ(std::get<std::uint16_t>(system.parameters[1]), 0U);
}

TEST(ProviderCapabilityQueryTest, WithEmptyProviderManagerReportsNoProvider)
{
    auto manager = std::make_shared<ProviderManager>(config::Config{}.GetProviderInitConfig());
    (void)manager->Initialize();
    const ProviderCapabilityQuery query{manager};

    const auto system = RunQuery(query, [](auto& b) {
        b.operation(mediator_ops::QuerySystemCapabilities());
    });
    ASSERT_EQ(system.result, protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_EQ(system.parameters.size(), 2U);
    EXPECT_EQ(std::get<std::uint16_t>(system.parameters[0]), 0U);
}

}  // namespace
}  // namespace score::crypto::daemon::provider
