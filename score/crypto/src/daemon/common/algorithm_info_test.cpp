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

/// @file algorithm_info_test.cpp
/// @brief Verifies provider-neutral hash and MAC metadata lookup.

#include "score/crypto/src/daemon/common/algorithm_info.hpp"

#include <gtest/gtest.h>

namespace score::crypto::daemon::common
{
namespace
{

TEST(AlgorithmInfoTest, HashAlgorithmMetadata)
{
    const auto sha256_info = LookupHashAlgorithmInfo("SHA256");
    ASSERT_TRUE(sha256_info.has_value());
    EXPECT_EQ(sha256_info->algorithm, HashAlgorithm::kSha256);
    EXPECT_EQ(sha256_info->digest_size, 32U);

    const auto sha224_info = LookupHashAlgorithmInfo("SHA224");
    ASSERT_TRUE(sha224_info.has_value());
    EXPECT_EQ(sha224_info->algorithm, HashAlgorithm::kSha224);
    EXPECT_EQ(sha224_info->digest_size, 28U);

    EXPECT_FALSE(LookupHashAlgorithmInfo("SHA1").has_value());
    EXPECT_FALSE(LookupHashAlgorithmInfo("MD5").has_value());
    EXPECT_FALSE(LookupDigestSize("UNSUPPORTED_ALGORITHM").has_value());
}

TEST(AlgorithmInfoTest, MacAlgorithmMetadata)
{
    const auto hmac_sha256_info = LookupMacAlgorithmInfo("HMAC-SHA256");
    ASSERT_TRUE(hmac_sha256_info.has_value());
    EXPECT_EQ(hmac_sha256_info->algorithm, MacAlgorithm::kHmacSha256);
    EXPECT_EQ(hmac_sha256_info->mac_size, 32U);

    EXPECT_FALSE(LookupMacAlgorithmInfo("HMAC-SHA1").has_value());
    EXPECT_FALSE(LookupMacSize("UNSUPPORTED_ALGORITHM").has_value());
}

}  // namespace
}  // namespace score::crypto::daemon::common
