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
/// @brief Verifies provider-neutral algorithm metadata lookup.

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

TEST(AlgorithmInfoTest, PqcKeyAlgorithmsUseStandardizedPrivateKeySizes)
{
    struct ExpectedKeySize
    {
        std::string_view name;
        std::size_t private_key_size;
    };
    // Private-key byte sizes from FIPS 204 (ML-DSA) and FIPS 203 (ML-KEM).
    constexpr std::array<ExpectedKeySize, 6U> kExpectedSizes{{
        {"ML-DSA-44", 2560U},
        {"ML-DSA-65", 4032U},
        {"ML-DSA-87", 4896U},
        {"ML-KEM-512", 1632U},
        {"ML-KEM-768", 2400U},
        {"ML-KEM-1024", 3168U},
    }};

    for (const ExpectedKeySize& expected : kExpectedSizes)
    {
        SCOPED_TRACE(expected.name);
        const std::optional<std::size_t> size = LookupKeySize(expected.name);
        ASSERT_TRUE(size.has_value());
        EXPECT_EQ(size.value(), expected.private_key_size);
    }
}

TEST(AlgorithmInfoTest, KeySizeLookupPreservesClassicalAlgorithmsAndRejectsUnknownNames)
{
    EXPECT_EQ(LookupKeySize("AES-128-CBC"), std::optional<std::size_t>{16U});
    EXPECT_EQ(LookupKeySize("RSA-3072"), std::optional<std::size_t>{384U});
    EXPECT_EQ(LookupKeySize("Ed25519"), std::optional<std::size_t>{32U});
    EXPECT_FALSE(LookupKeySize("ML-KEM-999").has_value());
    EXPECT_FALSE(LookupKeySize("ml-kem-768").has_value());
    EXPECT_FALSE(LookupKeySize("UNSUPPORTED_ALGORITHM").has_value());
    EXPECT_FALSE(LookupKeySize("").has_value());
}

}  // namespace
}  // namespace score::crypto::daemon::common
