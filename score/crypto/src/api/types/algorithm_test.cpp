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

#include "score/crypto/src/api/types/algorithm.hpp"

#include <gtest/gtest.h>

#include <limits>
#include <set>
#include <string>
#include <string_view>

namespace
{

using score::crypto::Algorithm;
using score::crypto::AlgorithmCategory;
using score::crypto::EccCurve;
using score::crypto::HashFunction;
using score::crypto::KeyType;

static_assert(score::crypto::FromAlgorithmName("ECDSA-P384-SHA384") == Algorithm::kEcdsaP384Sha384);
static_assert(score::crypto::ToAlgorithmName(Algorithm::kSha256) == "SHA256");
static_assert(score::crypto::GetAlgorithmDescriptor(Algorithm::kEcdsaP384Sha384)->output_size == 96U);
static_assert(score::crypto::GetAlgorithmCategory("AES-256-CBC") == AlgorithmCategory::kCipher);
static_assert(score::crypto::GetFixedOutputSize(Algorithm::kEcdsaP384Sha384) == 96U);
static_assert(score::crypto::GetMaximumOutputSize(Algorithm::kAes256Cbc, 32U) == 48U);

TEST(AlgorithmCatalogTest, NamesAndIdentifiersAreUnique)
{
    std::set<std::string_view> names;
    std::set<Algorithm> ids;
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        EXPECT_NE(row.id, Algorithm::kUnknown);
        EXPECT_FALSE(row.name.empty());
        EXPECT_TRUE(names.insert(row.name).second) << "duplicate name " << row.name;
        EXPECT_TRUE(ids.insert(row.id).second) << "duplicate id for " << row.name;
    }
}

TEST(AlgorithmCatalogTest, NameRoundTripsThroughIdentifier)
{
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        const auto id = score::crypto::FromAlgorithmName(row.name);
        ASSERT_TRUE(id.has_value()) << row.name;
        EXPECT_EQ(*id, row.id);
        EXPECT_EQ(score::crypto::ToAlgorithmName(*id), row.name);
        EXPECT_EQ(score::crypto::GetAlgorithmCategory(*id), row.category);
    }
}

TEST(AlgorithmCatalogTest, MatchIsExactAndCaseSensitive)
{
    EXPECT_FALSE(score::crypto::FromAlgorithmName("").has_value());
    EXPECT_FALSE(score::crypto::FromAlgorithmName("sha256").has_value());
    EXPECT_FALSE(score::crypto::FromAlgorithmName("SHA-256").has_value());
    EXPECT_FALSE(score::crypto::FromAlgorithmName("HMAC-SHA256-X").has_value());
    EXPECT_FALSE(score::crypto::FromAlgorithmName("XECDSA-P256").has_value());
    // A signature scheme whose curve and digest are known individually is still
    // unknown as a whole unless the pairing has its own row.
    EXPECT_FALSE(score::crypto::FromAlgorithmName("ECDSA-P256-SHA384").has_value());
}

TEST(AlgorithmCatalogTest, UnknownAlgorithmHasNoProperties)
{
    EXPECT_EQ(score::crypto::ToAlgorithmName(Algorithm::kUnknown), std::string_view{});
    EXPECT_EQ(score::crypto::GetAlgorithmCategory(Algorithm::kUnknown), AlgorithmCategory::kUnknown);
    EXPECT_EQ(score::crypto::GetAlgorithmCategory("NOT-AN-ALGORITHM"), AlgorithmCategory::kUnknown);
    EXPECT_FALSE(score::crypto::GetAlgorithmDescriptor(Algorithm::kUnknown).has_value());
    EXPECT_FALSE(score::crypto::GetKeySizeBytes(Algorithm::kUnknown).has_value());
}

TEST(AlgorithmCatalogTest, SignatureRowsCarryCurveDigestAndP1363Size)
{
    const auto p521 = score::crypto::GetAlgorithmDescriptor("ECDSA-P521-SHA512");
    ASSERT_TRUE(p521.has_value());
    EXPECT_EQ(p521->category, AlgorithmCategory::kSignature);
    EXPECT_EQ(p521->key_type, KeyType::kEcc);
    EXPECT_EQ(p521->curve, EccCurve::kP521);
    EXPECT_EQ(p521->hash, HashFunction::kSha512);
    EXPECT_EQ(p521->output_size, 132U);
}

TEST(AlgorithmCatalogTest, KeySizes)
{
    EXPECT_EQ(score::crypto::GetKeySizeBytes(Algorithm::kAes128Cbc), 16U);
    EXPECT_EQ(score::crypto::GetKeySizeBytes(Algorithm::kAes192), 24U);
    EXPECT_EQ(score::crypto::GetKeySizeBytes(Algorithm::kHmacSha384), 48U);
    EXPECT_EQ(score::crypto::GetKeySizeBytes(Algorithm::kEcdsaP521), 66U);
    EXPECT_FALSE(score::crypto::GetKeySizeBytes(Algorithm::kSha256).has_value());
    EXPECT_FALSE(score::crypto::GetKeySizeBytes(Algorithm::kCtrDrbg).has_value());
}

TEST(AlgorithmCatalogTest, FixedOutputSizes)
{
    EXPECT_EQ(score::crypto::GetFixedOutputSize(Algorithm::kSha256), 32U);
    EXPECT_EQ(score::crypto::GetFixedOutputSize(Algorithm::kSha512), 64U);
    EXPECT_EQ(score::crypto::GetFixedOutputSize(Algorithm::kHmacSha384), 48U);
    EXPECT_EQ(score::crypto::GetFixedOutputSize(Algorithm::kAes128Cmac), 16U);
    EXPECT_EQ(score::crypto::GetFixedOutputSize(Algorithm::kEcdsaP256Sha256), 64U);
    EXPECT_EQ(score::crypto::GetFixedOutputSize(Algorithm::kEcdsaP521Sha512), 132U);
    for (const auto algorithm : {Algorithm::kUnknown, Algorithm::kAes256Cbc, Algorithm::kAes256, Algorithm::kCtrDrbg})
    {
        EXPECT_FALSE(score::crypto::GetFixedOutputSize(algorithm).has_value())
            << score::crypto::ToAlgorithmName(algorithm);
    }
}

TEST(AlgorithmCatalogTest, MaximumOutputSizeOfFixedOutputIgnoresInput)
{
    EXPECT_EQ(score::crypto::GetMaximumOutputSize(Algorithm::kSha384, 0U), 48U);
    EXPECT_EQ(score::crypto::GetMaximumOutputSize(Algorithm::kSha384, 1000U), 48U);
    EXPECT_EQ(score::crypto::GetMaximumOutputSize(Algorithm::kEcdsaP384Sha384, 7U), 96U);
}

TEST(AlgorithmCatalogTest, MaximumOutputSizeOfBlockCipherAddsOneBlock)
{
    EXPECT_EQ(score::crypto::GetMaximumOutputSize(Algorithm::kAes128Cbc, 0U), 16U);
    EXPECT_EQ(score::crypto::GetMaximumOutputSize(Algorithm::kAes192Cbc, 5U), 21U);
    EXPECT_EQ(score::crypto::GetMaximumOutputSize(Algorithm::kAes256Cbc, 16U), 32U);
}

TEST(AlgorithmCatalogTest, MaximumOutputSizeIsUndefinedWithoutABound)
{
    for (const auto algorithm :
         {Algorithm::kUnknown, Algorithm::kAes256, Algorithm::kEcdsaP256, Algorithm::kCtrDrbg, Algorithm::kAes128Gcm})
    {
        EXPECT_FALSE(score::crypto::GetMaximumOutputSize(algorithm, 16U).has_value())
            << score::crypto::ToAlgorithmName(algorithm);
    }
    EXPECT_FALSE(score::crypto::GetMaximumOutputSize(Algorithm::kAes256Cbc, std::numeric_limits<std::size_t>::max())
                     .has_value());
}

TEST(AlgorithmCatalogTest, KeyRowsAreNotOperations)
{
    for (const auto name : {"AES-128", "AES-192", "AES-256", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521"})
    {
        EXPECT_EQ(score::crypto::GetAlgorithmCategory(name), AlgorithmCategory::kKey) << name;
    }
}

}  // namespace
