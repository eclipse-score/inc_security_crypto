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

}  // namespace
}  // namespace score::crypto::daemon::mediator::operations
