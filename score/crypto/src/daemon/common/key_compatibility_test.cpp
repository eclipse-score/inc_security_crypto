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

namespace score::crypto::daemon::common
{
namespace
{

constexpr auto kOk = KeyCompatibility::kCompatible;
constexpr auto kNo = KeyCompatibility::kIncompatible;
constexpr auto kSkip = KeyCompatibility::kUnchecked;

static_assert(CheckKeyCompatibility("ECDSA-P256-SHA256", "ECDSA-P256", 0U) == kOk);
static_assert(CheckKeyCompatibility("ECDSA-P384-SHA384", "ECDSA-P256", 0U) == kNo);

TEST(KeyCompatibilityTest, EcdsaNeedsKeyOnSameCurve)
{
    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P256-SHA256", "ECDSA-P256", 32U), kOk);
    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P384-SHA384", "ECDSA-P384", 48U), kOk);
    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P521-SHA512", "ECDSA-P521", 66U), kOk);

    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P384-SHA384", "ECDSA-P256", 32U), kNo);
    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P256-SHA256", "ECDSA-P521", 66U), kNo);
}

TEST(KeyCompatibilityTest, EcdsaHashIsNotPartOfTheKey)
{
    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P256-SHA384", "ECDSA-P256", 32U), kOk);
    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P256-SHA256", "ECDSA-P256-SHA512", 32U), kOk);
}

TEST(KeyCompatibilityTest, EcdsaRefusesSymmetricAndUnknownKeys)
{
    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P256-SHA256", "AES-256", 32U), kNo);
    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P256-SHA256", "HMAC-SHA256", 32U), kNo);
    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P256-SHA256", "", 0U), kNo);
    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P256-SHA256", "RSA-2048", 256U), kNo);
}

TEST(KeyCompatibilityTest, AesCipherNeedsAesKeyOfStatedLength)
{
    EXPECT_EQ(CheckKeyCompatibility("AES-256-CBC", "AES-256", 32U), kOk);
    EXPECT_EQ(CheckKeyCompatibility("AES-128-CBC", "AES-128-CBC", 16U), kOk);
    EXPECT_EQ(CheckKeyCompatibility("AES-192-GCM", "AES-192", 0U), kOk);

    EXPECT_EQ(CheckKeyCompatibility("AES-128-CBC", "AES-256", 32U), kNo);
    EXPECT_EQ(CheckKeyCompatibility("AES-256-GCM", "AES-128", 16U), kNo);
    EXPECT_EQ(CheckKeyCompatibility("AES-256-CBC", "HMAC-SHA256", 32U), kNo);
    EXPECT_EQ(CheckKeyCompatibility("AES-256-CBC", "ECDSA-P256", 32U), kNo);
}

TEST(KeyCompatibilityTest, KeyMaterialLengthWinsOverName)
{
    // An imported key labelled AES-256 that only holds 16 bytes cannot serve AES-256.
    EXPECT_EQ(CheckKeyCompatibility("AES-256-CBC", "AES-256", 16U), kNo);
    EXPECT_EQ(CheckKeyCompatibility("AES-128-CBC", "AES-256", 16U), kOk);
}

TEST(KeyCompatibilityTest, CmacNeedsAesKeyOfStatedLength)
{
    EXPECT_EQ(CheckKeyCompatibility("AES-256-CMAC", "AES-256-CMAC", 32U), kOk);
    EXPECT_EQ(CheckKeyCompatibility("AES-128-CMAC", "AES-128", 16U), kOk);
    EXPECT_EQ(CheckKeyCompatibility("AES-128-CMAC", "AES-256", 32U), kNo);
    EXPECT_EQ(CheckKeyCompatibility("AES-256-CMAC", "HMAC-SHA256", 32U), kNo);
}

TEST(KeyCompatibilityTest, HmacTakesAnySymmetricKey)
{
    EXPECT_EQ(CheckKeyCompatibility("HMAC-SHA256", "HMAC-SHA256", 32U), kOk);
    EXPECT_EQ(CheckKeyCompatibility("HMAC-SHA256", "AES-256", 32U), kOk);
    EXPECT_EQ(CheckKeyCompatibility("HMAC-SHA512", "HMAC-SHA256", 64U), kOk);
    EXPECT_EQ(CheckKeyCompatibility("HMAC-SHA384", "AES-128-CBC", 16U), kOk);

    EXPECT_EQ(CheckKeyCompatibility("HMAC-SHA256", "ECDSA-P256", 32U), kNo);
    EXPECT_EQ(CheckKeyCompatibility("HMAC-SHA256", "unknown", 32U), kNo);
}

TEST(KeyCompatibilityTest, UnknownOperationIsLeftToProvider)
{
    EXPECT_EQ(CheckKeyCompatibility("RSA-PSS-SHA256", "RSA-2048", 256U), kSkip);
    EXPECT_EQ(CheckKeyCompatibility("", "AES-256", 32U), kSkip);
    EXPECT_EQ(CheckKeyCompatibility("hmac-sha256", "AES-256", 32U), kSkip);
}

TEST(KeyCompatibilityTest, UnkeyedCategoriesAreNotChecked)
{
    EXPECT_EQ(CheckKeyCompatibility("SHA256", "AES-256", 32U), kSkip);
    EXPECT_EQ(CheckKeyCompatibility("CTR-DRBG", "AES-256", 32U), kSkip);
    EXPECT_EQ(CheckKeyCompatibility("AES-256", "AES-256", 32U), kSkip);
    EXPECT_EQ(CheckKeyCompatibility("ECDSA-P256", "ECDSA-P256", 32U), kSkip);
}

TEST(KeyCompatibilityTest, UnpinnedKeyServesAnyAlgorithm)
{
    EXPECT_TRUE(IsPermittedAlgorithm("AES-256-CBC", ""));
    EXPECT_TRUE(IsPermittedAlgorithm("AES-256-ECB", ""));
}

TEST(KeyCompatibilityTest, PinnedKeyServesOnlyItsAlgorithm)
{
    EXPECT_TRUE(IsPermittedAlgorithm("AES-256-GCM", "AES-256-GCM"));
    EXPECT_FALSE(IsPermittedAlgorithm("AES-256-CBC", "AES-256-GCM"));
    EXPECT_FALSE(IsPermittedAlgorithm("ECDSA-P256-SHA384", "ECDSA-P256-SHA256"));
    EXPECT_FALSE(IsPermittedAlgorithm("HMAC-SHA256", "AES-256-CMAC"));
    // Uncatalogued algorithms are refused too, which CheckKeyCompatibility leaves to the provider.
    EXPECT_FALSE(IsPermittedAlgorithm("AES-256-ECB", "AES-256-GCM"));
    // Exact, case-sensitive match, like every other algorithm identifier.
    EXPECT_FALSE(IsPermittedAlgorithm("aes-256-gcm", "AES-256-GCM"));
}

TEST(KeyCompatibilityTest, PinMustFitTheKey)
{
    EXPECT_TRUE(IsValidPermittedAlgorithm("", "AES-256", 32U));
    EXPECT_TRUE(IsValidPermittedAlgorithm("AES-256-GCM", "AES-256", 32U));
    EXPECT_TRUE(IsValidPermittedAlgorithm("HMAC-SHA256", "AES-256", 32U));
    EXPECT_TRUE(IsValidPermittedAlgorithm("ECDSA-P256-SHA256", "ECDSA-P256", 32U));

    EXPECT_FALSE(IsValidPermittedAlgorithm("AES-256-GCM", "AES-128", 16U));
    EXPECT_FALSE(IsValidPermittedAlgorithm("ECDSA-P384-SHA384", "ECDSA-P256", 32U));
    EXPECT_FALSE(IsValidPermittedAlgorithm("HMAC-SHA256", "ECDSA-P256", 32U));
}

TEST(KeyCompatibilityTest, PinMustNameAKeyedOperation)
{
    EXPECT_FALSE(IsValidPermittedAlgorithm("AES-256", "AES-256", 32U));
    EXPECT_FALSE(IsValidPermittedAlgorithm("ECDSA-P256", "ECDSA-P256", 32U));
    EXPECT_FALSE(IsValidPermittedAlgorithm("SHA256", "AES-256", 32U));
    EXPECT_FALSE(IsValidPermittedAlgorithm("CTR-DRBG", "AES-256", 32U));
    // Not in the catalog: nothing to judge, so the exact match alone governs.
    EXPECT_TRUE(IsValidPermittedAlgorithm("AES-256-ECB", "AES-256", 32U));
}

}  // namespace
}  // namespace score::crypto::daemon::common
