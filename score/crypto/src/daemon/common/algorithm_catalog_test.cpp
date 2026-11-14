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

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
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
    EXPECT_FALSE(score::crypto::FromAlgorithmName("ECDSA-P2561-SHA256").has_value());
    EXPECT_FALSE(score::crypto::FromAlgorithmName("ECDSA-P256-SHA2561").has_value());
    // ECDSA pairs only with SHA-2 digests; there are no MD5 or SHA-1 rows.
    EXPECT_FALSE(score::crypto::FromAlgorithmName("ECDSA-P256-SHA1").has_value());
    EXPECT_FALSE(score::crypto::FromAlgorithmName("ECDSA-P256-MD5").has_value());
}

TEST(AlgorithmCatalogTest, EcdsaHasOneRowPerCurveAndSha2Digest)
{
    struct Curve
    {
        std::string_view token;
        EccCurve curve;
        std::uint16_t key_bits;
        std::uint16_t signature_size;
    };
    struct Digest
    {
        std::string_view token;
        HashFunction hash;
    };
    constexpr Curve kCurves[] = {
        {"P256", EccCurve::kP256, 256U, 64U},
        {"P384", EccCurve::kP384, 384U, 96U},
        {"P521", EccCurve::kP521, 521U, 132U},
    };
    constexpr Digest kDigests[] = {
        {"SHA224", HashFunction::kSha224},
        {"SHA256", HashFunction::kSha256},
        {"SHA384", HashFunction::kSha384},
        {"SHA512", HashFunction::kSha512},
    };

    std::size_t ecdsa_rows{0U};
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        if ((row.category == AlgorithmCategory::kSignature) && (row.key_type == KeyType::kEcc))
        {
            ++ecdsa_rows;
        }
    }
    EXPECT_EQ(ecdsa_rows, 12U);

    for (const auto& curve : kCurves)
    {
        for (const auto& digest : kDigests)
        {
            const std::string name = std::string{"ECDSA-"} + std::string{curve.token} + "-" + std::string{digest.token};
            const auto row = score::crypto::GetAlgorithmDescriptor(name);
            ASSERT_TRUE(row.has_value()) << name;
            EXPECT_EQ(row->category, AlgorithmCategory::kSignature) << name;
            EXPECT_EQ(row->key_type, KeyType::kEcc) << name;
            EXPECT_EQ(row->curve, curve.curve) << name;
            EXPECT_EQ(row->hash, digest.hash) << name;
            EXPECT_EQ(row->key_bits, curve.key_bits) << name;
            EXPECT_EQ(row->output_size, curve.signature_size) << name;
        }
    }
}

TEST(AlgorithmCatalogTest, EnumeratorValuesAreStable)
{
    EXPECT_EQ(static_cast<std::uint16_t>(Algorithm::kEcdsaP256Sha256), 18U);
    EXPECT_EQ(static_cast<std::uint16_t>(Algorithm::kEcdsaP384Sha384), 19U);
    EXPECT_EQ(static_cast<std::uint16_t>(Algorithm::kEcdsaP521Sha512), 20U);
    EXPECT_EQ(static_cast<std::uint16_t>(Algorithm::kCtrDrbg), 40U);
    EXPECT_EQ(static_cast<std::uint16_t>(Algorithm::kEcdsaP256Sha224), 41U);
    EXPECT_EQ(static_cast<std::uint16_t>(Algorithm::kEcdsaP521Sha384), 49U);
    EXPECT_EQ(score::crypto::FromAlgorithmName("ECDSA-P256-SHA384"), Algorithm::kEcdsaP256Sha384);
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

TEST(AlgorithmCatalogTest, RsaPssAndEd25519Rows)
{
    const auto pss = score::crypto::GetAlgorithmDescriptor("RSA-PSS-3072-SHA384");
    ASSERT_TRUE(pss.has_value());
    EXPECT_EQ(pss->category, AlgorithmCategory::kSignature);
    EXPECT_EQ(pss->key_type, KeyType::kRsa);
    EXPECT_EQ(pss->key_bits, 3072U);
    EXPECT_EQ(pss->hash, HashFunction::kSha384);
    EXPECT_EQ(pss->output_size, 384U);

    const auto ed = score::crypto::GetAlgorithmDescriptor("Ed25519");
    ASSERT_TRUE(ed.has_value());
    EXPECT_EQ(ed->category, AlgorithmCategory::kSignature);
    EXPECT_EQ(ed->key_type, KeyType::kEd25519);
    EXPECT_EQ(ed->hash, HashFunction::kNone);
    EXPECT_EQ(ed->output_size, 64U);

    EXPECT_EQ(score::crypto::GetKeySizeBytes(Algorithm::kRsa4096), 512U);
    EXPECT_EQ(score::crypto::GetKeySizeBytes(Algorithm::kEd25519), 32U);
    EXPECT_FALSE(score::crypto::FromAlgorithmName("RSA-PSS-20481-SHA256").has_value());
    EXPECT_FALSE(score::crypto::FromAlgorithmName("ED25519").has_value());
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

TEST(AlgorithmCatalogTest, KeyRowsAreNotOperations)
{
    for (const auto name : {"AES-128",
                            "AES-192",
                            "AES-256",
                            "ECDSA-P256",
                            "ECDSA-P384",
                            "ECDSA-P521",
                            "RSA-2048",
                            "RSA-3072",
                            "RSA-4096"})
    {
        EXPECT_EQ(score::crypto::GetAlgorithmCategory(name), AlgorithmCategory::kKey) << name;
    }
}

TEST(AlgorithmCatalogTest, FindKeyAlgorithmMatchesRsaByModulusLength)
{
    const auto rsa = score::crypto::FindKeyAlgorithm(score::crypto::KeyType::kRsa, 2048U, EccCurve::kNone);
    ASSERT_TRUE(rsa.has_value());
    EXPECT_EQ(rsa->name, "RSA-2048");
    EXPECT_FALSE(score::crypto::FindKeyAlgorithm(score::crypto::KeyType::kRsa, 1024U, EccCurve::kNone).has_value());
}

TEST(AlgorithmCatalogTest, FindKeyAlgorithmMatchesEllipticCurveByCurve)
{
    const auto p256 = score::crypto::FindKeyAlgorithm(score::crypto::KeyType::kEcc, 0U, EccCurve::kP256);
    ASSERT_TRUE(p256.has_value());
    EXPECT_EQ(p256->name, "ECDSA-P256");
    EXPECT_FALSE(score::crypto::FindKeyAlgorithm(score::crypto::KeyType::kEcc, 0U, EccCurve::kNone).has_value());
}

TEST(AlgorithmCatalogTest, FindKeyAlgorithmMatchesEd25519ByFamily)
{
    const auto ed25519 = score::crypto::FindKeyAlgorithm(score::crypto::KeyType::kEd25519, 0U, EccCurve::kNone);
    ASSERT_TRUE(ed25519.has_value());
    EXPECT_EQ(ed25519->name, "Ed25519");
}

}  // namespace
