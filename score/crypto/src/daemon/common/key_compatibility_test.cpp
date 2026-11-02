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
static_assert(!Fits("HMAC-SHA256", "AES-256", 32U));

TEST(KeyCompatibilityTest, EcdsaNeedsKeyOnSameCurve)
{
    EXPECT_TRUE(Fits("ECDSA-P256-SHA256", "ECDSA-P256", 32U));
    EXPECT_TRUE(Fits("ECDSA-P384-SHA384", "ECDSA-P384", 48U));
    EXPECT_TRUE(Fits("ECDSA-P521-SHA512", "ECDSA-P521", 66U));
    EXPECT_TRUE(Fits("ECDSA-P521-SHA224", "ECDSA-P521", 66U));

    EXPECT_FALSE(Fits("ECDSA-P384-SHA384", "ECDSA-P256", 32U));
    EXPECT_FALSE(Fits("ECDSA-P256-SHA256", "ECDSA-P521", 66U));
}

TEST(KeyCompatibilityTest, EcKeyServesEcdsaWithAnyHash)
{
    EXPECT_TRUE(Fits("ECDSA-P256-SHA224", "ECDSA-P256", 32U));
    EXPECT_TRUE(Fits("ECDSA-P256-SHA384", "ECDSA-P256", 32U));
    EXPECT_TRUE(Fits("ECDSA-P256-SHA512", "ECDSA-P256", 32U));
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
    // The recorded size of an RSA key may be its encoding; only the row counts.
    EXPECT_TRUE(Fits("RSA-PSS-2048-SHA256", "RSA-2048", 1218U));
    EXPECT_TRUE(Fits("RSA-PSS-2048-SHA512", "RSA-2048", 1218U));
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

TEST(KeyCompatibilityTest, AesKeyRowServesEveryAesModeOfItsLength)
{
    EXPECT_TRUE(Fits("AES-256-CBC", "AES-256", 32U));
    EXPECT_TRUE(Fits("AES-256-GCM", "AES-256", 32U));
    EXPECT_TRUE(Fits("AES-256-CMAC", "AES-256", 32U));
    EXPECT_TRUE(Fits("AES-192-GCM", "AES-192", 0U));

    EXPECT_FALSE(Fits("AES-128-CBC", "AES-256", 32U));
    EXPECT_FALSE(Fits("AES-256-GCM", "AES-128", 16U));
    EXPECT_FALSE(Fits("AES-128-CMAC", "AES-256", 32U));
    EXPECT_FALSE(Fits("AES-256-CBC", "HMAC-SHA256", 32U));
    EXPECT_FALSE(Fits("AES-256-CBC", "ECDSA-P256", 32U));
}

TEST(KeyCompatibilityTest, OperationLabelServesThatOperationOnly)
{
    EXPECT_TRUE(Fits("AES-128-CBC", "AES-128-CBC", 16U));
    EXPECT_TRUE(Fits("AES-256-CMAC", "AES-256-CMAC", 32U));
    EXPECT_TRUE(Fits("AES-256-GCM", "AES-256-GCM", 32U));

    EXPECT_FALSE(Fits("AES-256-CBC", "AES-256-GCM", 32U));
    EXPECT_FALSE(Fits("AES-256-GCM", "AES-256-CBC", 32U));
    EXPECT_FALSE(Fits("AES-128-CBC", "AES-128-CMAC", 16U));
    EXPECT_FALSE(Fits("AES-256-CMAC", "AES-256-CBC", 32U));
}

TEST(KeyCompatibilityTest, AesMaterialMustHaveTheLengthOfItsRow)
{
    // A key labelled AES-256 that holds 16 bytes is misconfigured: it fits
    // neither AES-256 nor AES-128.
    EXPECT_FALSE(Fits("AES-256-CBC", "AES-256", 16U));
    EXPECT_FALSE(Fits("AES-128-CBC", "AES-256", 16U));
    EXPECT_FALSE(Fits("AES-128-CBC", "AES-128-CBC", 32U));
    EXPECT_FALSE(Fits("AES-256-CMAC", "AES-256", 24U));
}

TEST(KeyCompatibilityTest, HmacTakesOnlyAKeyLabelledWithThatHmac)
{
    EXPECT_TRUE(Fits("HMAC-SHA256", "HMAC-SHA256", 32U));
    EXPECT_TRUE(Fits("HMAC-SHA512", "HMAC-SHA512", 64U));

    EXPECT_FALSE(Fits("HMAC-SHA256", "AES-256", 32U));
    EXPECT_FALSE(Fits("HMAC-SHA256", "AES-256-CMAC", 32U));
    EXPECT_FALSE(Fits("HMAC-SHA384", "AES-128-CBC", 16U));
    EXPECT_FALSE(Fits("HMAC-SHA512", "HMAC-SHA256", 64U));
    EXPECT_FALSE(Fits("HMAC-SHA256", "ECDSA-P256", 32U));
    EXPECT_FALSE(Fits("HMAC-SHA256", "RSA-2048", 256U));
}

TEST(KeyCompatibilityTest, HmacKeyLengthIsFree)
{
    EXPECT_TRUE(Fits("HMAC-SHA256", "HMAC-SHA256", 16U));
    EXPECT_TRUE(Fits("HMAC-SHA256", "HMAC-SHA256", 64U));
    EXPECT_TRUE(Fits("HMAC-SHA256", "HMAC-SHA256", 0U));
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
    EXPECT_FALSE(Fits("HMAC-SHA256", "CTR-DRBG", 0U));
}

constexpr bool Permits(const std::string_view operation, const std::string_view permitted)
{
    return IsPermittedAlgorithm(Row(operation), Row(permitted));
}

constexpr bool PinFits(const std::string_view permitted, const std::string_view key, const std::size_t key_size_bytes)
{
    return IsValidPermittedAlgorithm(Row(permitted), Row(key), key_size_bytes);
}

TEST(KeyCompatibilityTest, UnpinnedKeyServesAnyAlgorithm)
{
    EXPECT_TRUE(IsPermittedAlgorithm(Row("AES-256-CBC"), std::nullopt));
    EXPECT_TRUE(IsPermittedAlgorithm(Row("HMAC-SHA512"), std::nullopt));
}

TEST(KeyCompatibilityTest, PinnedKeyServesOnlyItsAlgorithm)
{
    EXPECT_TRUE(Permits("AES-256-GCM", "AES-256-GCM"));
    EXPECT_FALSE(Permits("AES-256-CBC", "AES-256-GCM"));
    EXPECT_FALSE(Permits("ECDSA-P256-SHA384", "ECDSA-P256-SHA256"));
    EXPECT_FALSE(Permits("HMAC-SHA256", "AES-256-CMAC"));
    EXPECT_FALSE(Permits("HMAC-SHA384", "HMAC-SHA256"));
}

TEST(KeyCompatibilityTest, PinMustFitTheKey)
{
    EXPECT_TRUE(PinFits("AES-256-GCM", "AES-256", 32U));
    EXPECT_TRUE(PinFits("AES-256-CBC", "AES-256", 32U));
    EXPECT_TRUE(PinFits("ECDSA-P256-SHA256", "ECDSA-P256", 32U));
    EXPECT_TRUE(PinFits("ECDSA-P256-SHA384", "ECDSA-P256", 0U));

    EXPECT_FALSE(PinFits("AES-256-GCM", "AES-128", 16U));
    EXPECT_FALSE(PinFits("ECDSA-P384-SHA384", "ECDSA-P256", 32U));
    EXPECT_FALSE(PinFits("HMAC-SHA256", "ECDSA-P256", 32U));
    EXPECT_TRUE(PinFits("RSA-PSS-3072-SHA256", "RSA-3072", 0U));
    EXPECT_FALSE(PinFits("RSA-PSS-4096-SHA256", "RSA-3072", 0U));
    EXPECT_TRUE(PinFits("Ed25519", "Ed25519", 32U));
}

TEST(KeyCompatibilityTest, PinOnAnOperationKeyMustBeItsOwnAlgorithm)
{
    // A key labelled with an operation already serves only that operation, so
    // the only pin it can take is that operation itself.
    EXPECT_TRUE(PinFits("HMAC-SHA256", "HMAC-SHA256", 32U));
    EXPECT_TRUE(PinFits("AES-256-CBC", "AES-256-CBC", 32U));
    EXPECT_FALSE(PinFits("HMAC-SHA384", "HMAC-SHA256", 32U));
    EXPECT_FALSE(PinFits("HMAC-SHA256", "AES-256", 32U));
    EXPECT_FALSE(PinFits("AES-256-GCM", "AES-256-CBC", 32U));
}

TEST(KeyCompatibilityTest, PinMustNameAKeyedOperation)
{
    EXPECT_FALSE(PinFits("AES-256", "AES-256", 32U));
    EXPECT_FALSE(PinFits("ECDSA-P256", "ECDSA-P256", 32U));
    EXPECT_FALSE(PinFits("RSA-2048", "RSA-2048", 0U));
    EXPECT_FALSE(PinFits("SHA256", "AES-256", 32U));
    EXPECT_FALSE(PinFits("CTR-DRBG", "AES-256", 32U));
}

}  // namespace
}  // namespace score::crypto::daemon::common
