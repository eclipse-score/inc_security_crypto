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

#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include <gtest/gtest.h>

namespace score::crypto::daemon::mediator::operations
{
namespace
{

namespace ctx = common::context_types;
using Capability = common::ProviderCapability;

TEST(RequiredProviderCapabilityTest, ScopedManagementContextsRequireTheirCapability)
{
    EXPECT_EQ(RequiredProviderCapability(ctx::kKeyManagement), Capability::kKeyManagement);
    EXPECT_EQ(RequiredProviderCapability(ctx::kCertManagement), Capability::kCertManagement);
    EXPECT_EQ(RequiredProviderCapability("CERT:VERIFICATION"), Capability::kCertManagement);
}

TEST(RequiredProviderCapabilityTest, UnscopedContextsRequireNoCapability)
{
    for (const auto type : {ctx::kHash, ctx::kMac, ctx::kCipher, ctx::kSign, ctx::kVerify, ctx::kRandom})
    {
        EXPECT_EQ(RequiredProviderCapability(type), Capability::kNone) << type;
    }
}

TEST(RequiredProviderCapabilityTest, UnknownOrMalformedScopesRequireNoCapability)
{
    EXPECT_EQ(RequiredProviderCapability("KEY_MANAGEMENT"), Capability::kNone);
    EXPECT_EQ(RequiredProviderCapability("OTHER:MANAGEMENT"), Capability::kNone);
    EXPECT_EQ(RequiredProviderCapability("key:MANAGEMENT"), Capability::kNone);
    EXPECT_EQ(RequiredProviderCapability(":MANAGEMENT"), Capability::kNone);
    EXPECT_EQ(RequiredProviderCapability(""), Capability::kNone);
}

void ExpectMediatorOperation(const control_plane::protocol::OperationIdentifier& id, const OperationAction action)
{
    EXPECT_EQ(id.operationActor, common::actors::OP_ACTOR_MEDIATOR);
    EXPECT_EQ(id.operationAction, action);
}

TEST(MediatorOperationIdentifierTest, EachHelperAddressesTheMediatorWithItsAction)
{
    ExpectMediatorOperation(CreateContext(), CTX_CREATE);
    ExpectMediatorOperation(CloseContext(), CTX_CLOSE);
    ExpectMediatorOperation(ResolveResource(), RESOLVE_RESOURCE);
    ExpectMediatorOperation(CreateShmObject(), SHM_SETUP);
    ExpectMediatorOperation(DestroyShmObject(), SHM_DESTROY_OBJECT);
}

// The action values are part of the client/daemon wire contract.
TEST(MediatorOperationIdentifierTest, ActionValuesAreStableAndBelowCustomRange)
{
    EXPECT_EQ(CTX_CREATE, 1U);
    EXPECT_EQ(CTX_CLOSE, 2U);
    EXPECT_EQ(RESOLVE_RESOURCE, 3U);
    EXPECT_EQ(SHM_SETUP, 4U);
    EXPECT_EQ(SHM_DESTROY_OBJECT, 5U);
    for (const auto action : {CTX_CREATE, CTX_CLOSE, RESOLVE_RESOURCE, SHM_SETUP, SHM_DESTROY_OBJECT})
    {
        EXPECT_LT(action, CUSTOM_OP_START) << action;
    }
}

TEST(ProviderHintTest, PreservesResolvedProviderIncludingZero)
{
    const score::crypto::Expected<common::ProviderId, common::DaemonErrorCode> first_provider{0U};
    const score::crypto::Expected<common::ProviderId, common::DaemonErrorCode> another_provider{42U};

    EXPECT_EQ(ProviderHintOrInvalid(first_provider), 0U);
    EXPECT_EQ(ProviderHintOrInvalid(another_provider), 42U);
}

TEST(ProviderHintTest, MapsUnavailableProviderToInvalidSentinel)
{
    const score::crypto::Expected<common::ProviderId, common::DaemonErrorCode> unavailable{
        score::crypto::make_unexpected(common::DaemonErrorCode::kProviderNotAvailable)};

    EXPECT_EQ(ProviderHintOrInvalid(unavailable), common::kInvalidProviderId);
}

TEST(ProviderHintTest, MapsOtherResolutionErrorsToInvalidSentinel)
{
    const score::crypto::Expected<common::ProviderId, common::DaemonErrorCode> failure{
        score::crypto::make_unexpected(common::DaemonErrorCode::kInternalError)};

    EXPECT_EQ(ProviderHintOrInvalid(failure), common::kInvalidProviderId);
}

TEST(ProviderHintContractTest, UsesSameUnboundSentinelAcrossApiDaemonAndWire)
{
    EXPECT_EQ(SHM_WIRE_PROVIDER_ID_UNBOUND, common::kInvalidProviderId);
    EXPECT_EQ(SHM_WIRE_PROVIDER_ID_UNBOUND, score::crypto::kUnboundProviderId);
}

TEST(ProviderHintContractTest, ResourceDefaultsToUnboundProvider)
{
    EXPECT_EQ(score::crypto::CryptoResourceId{}.primary_provider, score::crypto::kUnboundProviderId);
}

TEST(ProviderIdHintDecoderTest, PreservesValidProviderIdsIncludingZero)
{
    const auto first_provider = DecodeProviderIdHint(0U);
    const auto another_provider = DecodeProviderIdHint(42U);

    EXPECT_EQ(first_provider.state, ProviderIdHintState::kBound);
    EXPECT_EQ(first_provider.provider_id, 0U);
    EXPECT_EQ(another_provider.state, ProviderIdHintState::kBound);
    EXPECT_EQ(another_provider.provider_id, 42U);
}

TEST(ProviderIdHintDecoderTest, RecognizesUnboundSentinel)
{
    const auto result = DecodeProviderIdHint(SHM_WIRE_PROVIDER_ID_UNBOUND);

    EXPECT_EQ(result.state, ProviderIdHintState::kUnbound);
    EXPECT_EQ(result.provider_id, common::kInvalidProviderId);
}

TEST(ProviderIdHintDecoderTest, RejectsValuesThatWouldNarrowToAnotherProvider)
{
    constexpr auto kFirstOutOfRangeProviderId =
        static_cast<std::uint64_t>(std::numeric_limits<common::ProviderId>::max()) + 1U;
    const auto result = DecodeProviderIdHint(kFirstOutOfRangeProviderId);

    EXPECT_EQ(result.state, ProviderIdHintState::kInvalid);
    EXPECT_EQ(result.provider_id, common::kInvalidProviderId);
}

TEST(ProviderHintTest, KeepsKeySlotResolutionSuccessfulWithoutProviderHint)
{
    const score::crypto::Expected<common::ProviderId, common::DaemonErrorCode> unavailable{
        score::crypto::make_unexpected(common::DaemonErrorCode::kProviderNotAvailable)};
    control_plane::protocol::OperationResponseBuilder builder;

    ReturnResolvedKeySlot(17U, unavailable, ResolveResource(), builder);
    const auto response = builder.build();

    ASSERT_TRUE(response.has_value());
    ASSERT_EQ(response.value().operations.size(), 1U);
    const auto& operation = response.value().operations.front();
    const auto node_id = operation.getParameter<std::uint64_t>(0U);
    const auto resource_type = operation.getParameter<std::uint8_t>(1U);
    const auto is_persistent = operation.getParameter<bool>(2U);
    const auto provider_id = operation.getParameter<std::uint16_t>(3U);

    EXPECT_EQ(operation.result, control_plane::protocol::OPERATION_RESULT_SUCCESS);
    ASSERT_TRUE(node_id.has_value());
    ASSERT_TRUE(resource_type.has_value());
    ASSERT_TRUE(is_persistent.has_value());
    ASSERT_TRUE(provider_id.has_value());
    EXPECT_EQ(node_id.value(), 17U);
    EXPECT_EQ(resource_type.value(), static_cast<std::uint8_t>(score::crypto::ResourceType::kKeySlot));
    EXPECT_TRUE(is_persistent.value());
    EXPECT_EQ(provider_id.value(), common::kInvalidProviderId);
}

}  // namespace
}  // namespace score::crypto::daemon::mediator::operations
