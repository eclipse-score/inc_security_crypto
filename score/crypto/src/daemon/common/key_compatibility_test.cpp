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

#include "score/crypto/src/daemon/common/key_compatibility.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <string_view>

namespace score::crypto::daemon::common
{
namespace
{

/// Catalog row of @p name; every name in these tests has one.
constexpr ::score::crypto::AlgorithmDescriptor Row(const std::string_view name)
{
    return ::score::crypto::GetAlgorithmDescriptor(name).value();
}

constexpr bool Fits(const std::string_view operation, const std::string_view key, const std::size_t key_size_bytes)
{
    return IsKeyCompatible(Row(operation), Row(key), key_size_bytes);
}

static_assert(Fits("ECDSA-P256-SHA256", "ECDSA-P256", 0U));
static_assert(!Fits("ECDSA-P384-SHA384", "ECDSA-P256", 0U));

TEST(KeyCompatibilityTest, EcdsaNeedsKeyOnSameCurve)
{
    EXPECT_TRUE(Fits("ECDSA-P256-SHA256", "ECDSA-P256", 32U));
    EXPECT_TRUE(Fits("ECDSA-P384-SHA384", "ECDSA-P384", 48U));
    EXPECT_TRUE(Fits("ECDSA-P521-SHA512", "ECDSA-P521", 66U));
    EXPECT_TRUE(Fits("ECDSA-P521-SHA224", "ECDSA-P521", 66U));

    EXPECT_FALSE(Fits("ECDSA-P384-SHA384", "ECDSA-P256", 32U));
    EXPECT_FALSE(Fits("ECDSA-P256-SHA256", "ECDSA-P521", 66U));
}

TEST(KeyCompatibilityTest, EcdsaHashIsNotPartOfTheKey)
{
    EXPECT_TRUE(Fits("ECDSA-P256-SHA384", "ECDSA-P256", 32U));
    EXPECT_TRUE(Fits("ECDSA-P256-SHA256", "ECDSA-P256-SHA512", 32U));
    EXPECT_FALSE(Fits("ECDSA-P384-SHA256", "ECDSA-P256-SHA256", 32U));
}

TEST(KeyCompatibilityTest, EcdsaRefusesOtherKeyTypes)
{
    EXPECT_FALSE(Fits("ECDSA-P256-SHA256", "AES-256", 32U));
    EXPECT_FALSE(Fits("ECDSA-P256-SHA256", "HMAC-SHA256", 32U));
    EXPECT_FALSE(Fits("ECDSA-P256-SHA256", "RSA-2048", 256U));
    EXPECT_FALSE(Fits("ECDSA-P256-SHA256", "Ed25519", 32U));
}

TEST(KeyCompatibilityTest, RsaPssNeedsRsaKeyOfStatedModulus)
{
    EXPECT_TRUE(Fits("RSA-PSS-2048-SHA256", "RSA-2048", 1218U));
    EXPECT_TRUE(Fits("RSA-PSS-4096-SHA512", "RSA-4096", 0U));

    EXPECT_FALSE(Fits("RSA-PSS-3072-SHA256", "RSA-2048", 256U));
    EXPECT_FALSE(Fits("RSA-PSS-2048-SHA256", "ECDSA-P256", 32U));
    EXPECT_FALSE(Fits("RSA-PSS-2048-SHA256", "Ed25519", 32U));
    EXPECT_FALSE(Fits("RSA-PSS-2048-SHA256", "AES-256", 256U));
}

TEST(KeyCompatibilityTest, Ed25519NeedsEd25519Key)
{
    EXPECT_TRUE(Fits("Ed25519", "Ed25519", 32U));
    EXPECT_FALSE(Fits("Ed25519", "ECDSA-P256", 32U));
    EXPECT_FALSE(Fits("Ed25519", "RSA-2048", 256U));
}

TEST(KeyCompatibilityTest, AesCipherNeedsAesKeyOfStatedLength)
{
    EXPECT_TRUE(Fits("AES-256-CBC", "AES-256", 32U));
    EXPECT_TRUE(Fits("AES-128-CBC", "AES-128-CBC", 16U));
    EXPECT_TRUE(Fits("AES-192-GCM", "AES-192", 0U));

    EXPECT_FALSE(Fits("AES-128-CBC", "AES-256", 32U));
    EXPECT_FALSE(Fits("AES-256-GCM", "AES-128", 16U));
    EXPECT_FALSE(Fits("AES-256-CBC", "HMAC-SHA256", 32U));
    EXPECT_FALSE(Fits("AES-256-CBC", "ECDSA-P256", 32U));
}

TEST(KeyCompatibilityTest, KeyMaterialLengthWinsOverName)
{
    // An imported key labelled AES-256 that only holds 16 bytes cannot serve AES-256.
    EXPECT_FALSE(Fits("AES-256-CBC", "AES-256", 16U));
    EXPECT_TRUE(Fits("AES-128-CBC", "AES-256", 16U));
}

TEST(KeyCompatibilityTest, CmacNeedsAesKeyOfStatedLength)
{
    EXPECT_TRUE(Fits("AES-256-CMAC", "AES-256-CMAC", 32U));
    EXPECT_TRUE(Fits("AES-128-CMAC", "AES-128", 16U));
    EXPECT_FALSE(Fits("AES-128-CMAC", "AES-256", 32U));
    EXPECT_FALSE(Fits("AES-256-CMAC", "HMAC-SHA256", 32U));
}

TEST(KeyCompatibilityTest, HmacTakesAnySymmetricKey)
{
    EXPECT_TRUE(Fits("HMAC-SHA256", "HMAC-SHA256", 32U));
    EXPECT_TRUE(Fits("HMAC-SHA256", "AES-256", 32U));
    EXPECT_TRUE(Fits("HMAC-SHA512", "HMAC-SHA256", 64U));
    EXPECT_TRUE(Fits("HMAC-SHA384", "AES-128-CBC", 16U));

    EXPECT_FALSE(Fits("HMAC-SHA256", "ECDSA-P256", 32U));
    EXPECT_FALSE(Fits("HMAC-SHA256", "RSA-2048", 256U));
}

TEST(KeyCompatibilityTest, UnkeyedRowsFitNoKey)
{
    EXPECT_FALSE(Fits("SHA256", "AES-256", 32U));
    EXPECT_FALSE(Fits("CTR-DRBG", "AES-256", 32U));
    EXPECT_FALSE(Fits("AES-256", "AES-256", 32U));
    EXPECT_FALSE(Fits("ECDSA-P256", "ECDSA-P256", 32U));
}

TEST(KeyCompatibilityTest, KeyWithoutKeyTypeFitsNothing)
{
    EXPECT_FALSE(Fits("AES-256-CBC", "SHA256", 0U));
    EXPECT_FALSE(Fits("ECDSA-P256-SHA256", "SHA256", 0U));
}

}  // namespace
}  // namespace score::crypto::daemon::common
