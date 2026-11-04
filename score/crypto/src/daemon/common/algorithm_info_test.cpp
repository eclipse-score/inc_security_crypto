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

#include <optional>
#include <string_view>

namespace score::crypto::daemon::common
{
namespace
{

::score::crypto::AlgorithmDescriptor Row(std::string_view name)
{
    const auto row = ::score::crypto::GetAlgorithmDescriptor(name);
    EXPECT_TRUE(row.has_value()) << name;
    return row.value_or(::score::crypto::AlgorithmDescriptor{});
}

TEST(AlgorithmInfoTest, DigestSizeComesFromTheHashRow)
{
    EXPECT_EQ(LookupDigestSize(::score::crypto::HashFunction::kSha224), 28U);
    EXPECT_EQ(LookupDigestSize(::score::crypto::HashFunction::kSha256), 32U);
    EXPECT_EQ(LookupDigestSize(::score::crypto::HashFunction::kSha384), 48U);
    EXPECT_EQ(LookupDigestSize(::score::crypto::HashFunction::kSha512), 64U);
    EXPECT_EQ(LookupDigestSize(::score::crypto::HashFunction::kSha1), 20U);
    EXPECT_FALSE(LookupDigestSize(::score::crypto::HashFunction::kNone).has_value());
}

TEST(AlgorithmInfoTest, KeySizeCoversRowsThatLabelAKey)
{
    EXPECT_EQ(LookupKeySize(Row("AES-256")), 32U);
    EXPECT_EQ(LookupKeySize(Row("AES-128-CBC")), 16U);
    EXPECT_EQ(LookupKeySize(Row("AES-192-GCM")), 24U);
    EXPECT_EQ(LookupKeySize(Row("AES-256-CMAC")), 32U);
    EXPECT_EQ(LookupKeySize(Row("HMAC-SHA512")), 64U);
    EXPECT_EQ(LookupKeySize(Row("ECDSA-P521")), 66U);
    EXPECT_EQ(LookupKeySize(Row("RSA-3072")), 384U);
    EXPECT_EQ(LookupKeySize(Row("Ed25519")), kEd25519KeySize);
}

TEST(AlgorithmInfoTest, KeySizeRefusesRowsThatLabelNoKey)
{
    EXPECT_FALSE(LookupKeySize(Row("SHA256")).has_value());
    EXPECT_FALSE(LookupKeySize(Row("CTR-DRBG")).has_value());
    EXPECT_FALSE(LookupKeySize(Row("RSA-PSS-2048-SHA256")).has_value());
    EXPECT_FALSE(LookupKeySize(Row("ECDSA-P256-SHA256")).has_value());
    EXPECT_FALSE(LookupKeySize(Row("ECDSA-P384-SHA224")).has_value());
    EXPECT_FALSE(LookupKeySize(::score::crypto::AlgorithmDescriptor{}).has_value());
}

TEST(AlgorithmInfoTest, EcFieldSizeFollowsTheCurve)
{
    EXPECT_EQ(EcFieldSize(Row("ECDSA-P256")), 32U);
    EXPECT_EQ(EcFieldSize(Row("ECDSA-P384-SHA512")), 48U);
    EXPECT_EQ(EcFieldSize(Row("ECDSA-P521-SHA224")), 66U);
    EXPECT_EQ(EcFieldSize(Row("Ed25519")), 0U);
    for (const auto& row : ::score::crypto::kAlgorithmCatalog)
    {
        if ((row.key_type == ::score::crypto::KeyType::kEcc) &&
            (row.category == ::score::crypto::AlgorithmCategory::kSignature))
        {
            EXPECT_EQ(row.output_size, 2U * EcFieldSize(row)) << row.name;
        }
    }
}

TEST(AlgorithmInfoTest, Ed25519SizesAreFixed)
{
    EXPECT_EQ(kEd25519KeySize, 32U);
    EXPECT_EQ(kEd25519SignatureSize, 64U);
}

}  // namespace
}  // namespace score::crypto::daemon::common
