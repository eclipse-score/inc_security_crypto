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

}  // namespace
}  // namespace score::crypto::daemon::mediator::operations
