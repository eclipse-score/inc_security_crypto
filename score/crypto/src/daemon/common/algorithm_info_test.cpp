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

}  // namespace
}  // namespace score::crypto::daemon::common

namespace
{

namespace algo_info = score::crypto::daemon::common;
using score::crypto::EccCurve;

TEST(AlgorithmInfoTest, SizesComeFromTheMatchingCategoryOnly)
{
    EXPECT_EQ(algo_info::LookupDigestSize("SHA384"), 48U);
    EXPECT_FALSE(algo_info::LookupDigestSize("HMAC-SHA384").has_value());
    EXPECT_EQ(algo_info::LookupMacSize("HMAC-SHA384"), 48U);
    EXPECT_FALSE(algo_info::LookupMacSize("SHA384").has_value());
    EXPECT_TRUE(algo_info::LookupCipher("AES-192-CBC").has_value());
    EXPECT_FALSE(algo_info::LookupCipher("AES-192").has_value());
    EXPECT_FALSE(algo_info::LookupCipher("AES-192-GCM").has_value());
}

TEST(AlgorithmInfoTest, CipherPropertiesAreInBytes)
{
    const auto cbc = algo_info::LookupCipher("AES-256-CBC");
    ASSERT_TRUE(cbc.has_value());
    EXPECT_EQ(cbc->key_size, 32U);
    EXPECT_EQ(cbc->block_size, 16U);
    EXPECT_EQ(cbc->iv_size, 16U);
}

TEST(AlgorithmInfoTest, EcdsaNameSplitsIntoExactTokens)
{
    const auto key = algo_info::ParseEcdsaName("ECDSA-P384");
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(key->curve.curve, EccCurve::kP384);
    EXPECT_FALSE(key->digest.has_value());

    const auto scheme = algo_info::ParseEcdsaName("ECDSA-P256-SHA384");
    ASSERT_TRUE(scheme.has_value());
    EXPECT_EQ(scheme->curve.curve, EccCurve::kP256);
    EXPECT_EQ(scheme->digest, "SHA384");
}

TEST(AlgorithmInfoTest, EcdsaNameRejectsFragmentsOfOtherTokens)
{
    // Each of these contains a curve and/or a hash name as a substring.
    for (const auto name : {"ECDSA-P2561-SHA256",
                            "ECDSA-P256-SHA2566",
                            "ECDSA-P256-SHA256-",
                            "ECDSA-P256-",
                            "XECDSA-P256-SHA256",
                            "ECDSA-P-256-SHA256",
                            "EC-P256",
                            "ECDSA-",
                            "ECDSA",
                            "P256"})
    {
        EXPECT_FALSE(algo_info::ParseEcdsaName(name).has_value()) << name;
        EXPECT_FALSE(algo_info::IsEcdsaAlgorithm(name)) << name;
        EXPECT_FALSE(algo_info::LookupEcCurveOfAlgorithm(name).has_value()) << name;
    }
}

TEST(AlgorithmInfoTest, CurveTableMatchesCatalog)
{
    for (const auto& curve : algo_info::kEcCurves)
    {
        EXPECT_EQ(curve.signature_size, 2U * curve.field_size) << curve.name;
        const auto by_id = algo_info::LookupEcCurve(curve.curve);
        ASSERT_TRUE(by_id.has_value());
        EXPECT_EQ(by_id->name, curve.name);
    }
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        if (row.curve == EccCurve::kNone)
        {
            continue;
        }
        const auto curve = algo_info::LookupEcCurveOfAlgorithm(row.name);
        ASSERT_TRUE(curve.has_value()) << row.name;
        EXPECT_EQ(curve->curve, row.curve) << row.name;
        EXPECT_EQ(curve->key_bits, row.key_bits) << row.name;
        if (row.output_size != 0U)
        {
            EXPECT_EQ(curve->signature_size, row.output_size) << row.name;
        }
    }
}

TEST(AlgorithmInfoTest, KeySizeCoversKeyAndOperationRows)
{
    EXPECT_EQ(algo_info::LookupKeySize("AES-256"), 32U);
    EXPECT_EQ(algo_info::LookupKeySize("AES-128-CBC"), 16U);
    EXPECT_EQ(algo_info::LookupKeySize("HMAC-SHA512"), 64U);
    EXPECT_EQ(algo_info::LookupKeySize("ECDSA-P521"), 66U);
    EXPECT_FALSE(algo_info::LookupKeySize("SHA256").has_value());
    EXPECT_FALSE(algo_info::LookupKeySize("AES-512").has_value());
}

}  // namespace
