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

#include "score/crypto/src/daemon/mediator/context_algorithm.hpp"

#include <gtest/gtest.h>

namespace score::crypto::daemon::mediator::operations
{
namespace
{

namespace context_types = common::context_types;

TEST(ContextAlgorithmTest, KeyManagementAndCertScopeContextsAreUnboundToAnAlgorithm)
{
    EXPECT_FALSE(ContextTakesAlgorithm(context_types::kKeyManagement));
    EXPECT_FALSE(ContextTakesAlgorithm(context_types::kCertManagement));
    EXPECT_FALSE(ContextTakesAlgorithm("CERT:VERIFICATION"));
    EXPECT_TRUE(ContextTakesAlgorithm(context_types::kHash));
    EXPECT_TRUE(ContextTakesAlgorithm(context_types::kRandom));
}

TEST(ContextAlgorithmTest, ResolvesCatalogNamesToTheirRow)
{
    const auto row = ResolveContextAlgorithm(context_types::kSign, "ECDSA-P256-SHA384");
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->id, ::score::crypto::Algorithm::kEcdsaP256Sha384);
    EXPECT_EQ(row->name, "ECDSA-P256-SHA384");
}

TEST(ContextAlgorithmTest, RefusesNamesTheCatalogDoesNotKnow)
{
    EXPECT_FALSE(ResolveContextAlgorithm(context_types::kHash, "UNSUPPORTED_ALGORITHM").has_value());
    EXPECT_FALSE(ResolveContextAlgorithm(context_types::kHash, "sha256").has_value());
    EXPECT_FALSE(ResolveContextAlgorithm(context_types::kSign, "ECDSA-P256-SHA1").has_value());
    EXPECT_FALSE(ResolveContextAlgorithm(context_types::kHash, "").has_value());
}

TEST(ContextAlgorithmTest, EmptyRandomAlgorithmSelectsCtrDrbg)
{
    const auto row = ResolveContextAlgorithm(context_types::kRandom, "");
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->id, ::score::crypto::Algorithm::kCtrDrbg);
}

}  // namespace
}  // namespace score::crypto::daemon::mediator::operations
