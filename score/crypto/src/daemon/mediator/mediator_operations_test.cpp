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

#include "score/crypto/src/daemon/common/operation_names.hpp"

#include <gtest/gtest.h>

#include <string_view>

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
    ExpectMediatorOperation(GetProviderInfo(), PROVIDER_INFO);
    ExpectMediatorOperation(QueryCapabilities(), QUERY_CAPABILITIES);
    ExpectMediatorOperation(QuerySystemCapabilities(), SYSTEM_CAPABILITIES);
}

// The action values are part of the client/daemon wire contract.
TEST(MediatorOperationIdentifierTest, ActionValuesAreStableAndBelowCustomRange)
{
    EXPECT_EQ(CTX_CREATE, 1U);
    EXPECT_EQ(CTX_CLOSE, 2U);
    EXPECT_EQ(RESOLVE_RESOURCE, 3U);
    EXPECT_EQ(SHM_SETUP, 4U);
    EXPECT_EQ(SHM_DESTROY_OBJECT, 5U);
    EXPECT_EQ(PROVIDER_INFO, 6U);
    EXPECT_EQ(QUERY_CAPABILITIES, 7U);
    EXPECT_EQ(SYSTEM_CAPABILITIES, 8U);
    for (const auto action : {CTX_CREATE,
                              CTX_CLOSE,
                              RESOLVE_RESOURCE,
                              SHM_SETUP,
                              SHM_DESTROY_OBJECT,
                              PROVIDER_INFO,
                              QUERY_CAPABILITIES,
                              SYSTEM_CAPABILITIES})
    {
        EXPECT_LT(action, CUSTOM_OP_START) << action;
    }
}

// operation_names.hpp keeps its own copy of these values; a mismatch would log the wrong name.
TEST(MediatorOperationIdentifierTest, EveryActionIsNamedInLogs)
{
    struct NamedAction
    {
        OperationAction action;
        std::string_view name;
    };
    for (const auto& [action, name] : {NamedAction{CTX_CREATE, "CTX_CREATE"},
                                       NamedAction{CTX_CLOSE, "CTX_CLOSE"},
                                       NamedAction{RESOLVE_RESOURCE, "RESOLVE_RESOURCE"},
                                       NamedAction{SHM_SETUP, "SHM_SETUP"},
                                       NamedAction{SHM_DESTROY_OBJECT, "SHM_DESTROY_OBJECT"},
                                       NamedAction{PROVIDER_INFO, "PROVIDER_INFO"},
                                       NamedAction{QUERY_CAPABILITIES, "QUERY_CAPABILITIES"},
                                       NamedAction{SYSTEM_CAPABILITIES, "SYSTEM_CAPABILITIES"}})
    {
        EXPECT_EQ(common::ActionName(common::actors::OP_ACTOR_MEDIATOR, action), name) << action;
    }
}

}  // namespace
}  // namespace score::crypto::daemon::mediator::operations
