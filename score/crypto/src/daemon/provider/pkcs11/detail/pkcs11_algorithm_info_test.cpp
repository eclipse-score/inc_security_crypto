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

#include "score/crypto/src/daemon/provider/pkcs11/detail/pkcs11_algorithm_info.hpp"

#include <gtest/gtest.h>

namespace score::crypto::daemon::provider::pkcs11::detail
{
namespace
{

using ::score::crypto::Algorithm;
using ::score::crypto::GetAlgorithmDescriptor;

// Returned by value: GetAlgorithmDescriptor() yields a temporary optional.
::score::crypto::AlgorithmDescriptor Row(const Algorithm id)
{
    return *GetAlgorithmDescriptor(id);
}

CK_MECHANISM_INFO GenerationRange(CK_ULONG min_size, CK_ULONG max_size, CK_FLAGS flags = CKF_GENERATE)
{
    return CK_MECHANISM_INFO{min_size, max_size, flags};
}

TEST(Pkcs11AlgorithmInfoTest, AesKeySizeIsCountedInBytes)
{
    const auto aes128 = LookupAlgorithm(Row(Algorithm::kAes128));
    const auto aes256 = LookupAlgorithm(Row(Algorithm::kAes256));
    ASSERT_TRUE(aes128.has_value());
    ASSERT_TRUE(aes256.has_value());
    EXPECT_EQ(aes128->gen_mechanism, CKM_AES_KEY_GEN);
    EXPECT_EQ(KeySizeInMechanismUnits(*aes128), 16U);
    EXPECT_EQ(KeySizeInMechanismUnits(*aes256), 32U);

    // A token limited to AES-128.
    const auto aes128_only = GenerationRange(16U, 16U);
    EXPECT_TRUE(CanGenerateKey(*aes128, aes128_only));
    EXPECT_FALSE(CanGenerateKey(*aes256, aes128_only));

    const auto any_aes = GenerationRange(16U, 32U);
    EXPECT_TRUE(CanGenerateKey(*aes128, any_aes));
    EXPECT_TRUE(CanGenerateKey(*aes256, any_aes));
}

TEST(Pkcs11AlgorithmInfoTest, GenericSecretKeySizeIsCountedInBits)
{
    const auto hmac256 = LookupAlgorithm(Row(Algorithm::kHmacSha256));
    const auto hmac512 = LookupAlgorithm(Row(Algorithm::kHmacSha512));
    ASSERT_TRUE(hmac256.has_value());
    ASSERT_TRUE(hmac512.has_value());
    EXPECT_EQ(hmac256->gen_mechanism, CKM_GENERIC_SECRET_KEY_GEN);
    EXPECT_EQ(KeySizeInMechanismUnits(*hmac256), 256U);
    EXPECT_EQ(KeySizeInMechanismUnits(*hmac512), 512U);

    const auto up_to_256_bits = GenerationRange(8U, 256U);
    EXPECT_TRUE(CanGenerateKey(*hmac256, up_to_256_bits));
    EXPECT_FALSE(CanGenerateKey(*hmac512, up_to_256_bits));

    const auto at_least_384_bits = GenerationRange(384U, 4096U);
    EXPECT_FALSE(CanGenerateKey(*hmac256, at_least_384_bits));
    EXPECT_TRUE(CanGenerateKey(*hmac512, at_least_384_bits));
}

TEST(Pkcs11AlgorithmInfoTest, KeyGenerationNeedsTheGenerateFlag)
{
    const auto aes128 = LookupAlgorithm(Row(Algorithm::kAes128));
    ASSERT_TRUE(aes128.has_value());
    EXPECT_FALSE(CanGenerateKey(*aes128, GenerationRange(16U, 32U, CKF_ENCRYPT)));
    EXPECT_TRUE(CanGenerateKey(*aes128, GenerationRange(16U, 32U, CKF_GENERATE | CKF_ENCRYPT)));
}

TEST(Pkcs11AlgorithmInfoTest, HashRowsMapToDigestMechanisms)
{
    EXPECT_EQ(LookupHashMechanism(Row(Algorithm::kSha224)), CKM_SHA224);
    EXPECT_EQ(LookupHashMechanism(Row(Algorithm::kSha256)), CKM_SHA256);
    EXPECT_EQ(LookupHashMechanism(Row(Algorithm::kSha384)), CKM_SHA384);
    EXPECT_EQ(LookupHashMechanism(Row(Algorithm::kSha512)), CKM_SHA512);
}

TEST(Pkcs11AlgorithmInfoTest, LegacyHashesAndNonHashRowsHaveNoDigestMechanism)
{
    EXPECT_EQ(LookupHashMechanism(Row(Algorithm::kMd5)), CK_UNAVAILABLE_INFORMATION);
    EXPECT_EQ(LookupHashMechanism(Row(Algorithm::kSha1)), CK_UNAVAILABLE_INFORMATION);
    // An HMAC row carries a hash but is not a hash operation.
    EXPECT_EQ(LookupHashMechanism(Row(Algorithm::kHmacSha256)), CK_UNAVAILABLE_INFORMATION);
}

TEST(Pkcs11AlgorithmInfoTest, HmacRowsMapToHmacMechanisms)
{
    EXPECT_EQ(LookupMacMechanism(Row(Algorithm::kHmacSha256)), CKM_SHA256_HMAC);
    EXPECT_EQ(LookupMacMechanism(Row(Algorithm::kHmacSha384)), CKM_SHA384_HMAC);
    EXPECT_EQ(LookupMacMechanism(Row(Algorithm::kHmacSha512)), CKM_SHA512_HMAC);
}

TEST(Pkcs11AlgorithmInfoTest, OtherMacRowsAreNotServed)
{
    EXPECT_EQ(LookupMacMechanism(Row(Algorithm::kAes128Cmac)), CK_UNAVAILABLE_INFORMATION);
    EXPECT_EQ(LookupMacMechanism(Row(Algorithm::kAes256Cmac)), CK_UNAVAILABLE_INFORMATION);
    EXPECT_EQ(LookupMacMechanism(Row(Algorithm::kSha256)), CK_UNAVAILABLE_INFORMATION);
}

void ExpectKey(const Algorithm id, const CK_KEY_TYPE key_type, const CK_MECHANISM_TYPE gen, const CK_ULONG len)
{
    const auto info = LookupAlgorithm(Row(id));
    ASSERT_TRUE(info.has_value()) << Row(id).name;
    EXPECT_EQ(info->ck_key_type, key_type) << Row(id).name;
    EXPECT_EQ(info->gen_mechanism, gen) << Row(id).name;
    EXPECT_EQ(info->value_len, len) << Row(id).name;
}

TEST(Pkcs11AlgorithmInfoTest, AesKeyCipherAndCmacRowsNeedAnAesKeyOfTheRowLength)
{
    ExpectKey(Algorithm::kAes128, CKK_AES, CKM_AES_KEY_GEN, 16U);
    ExpectKey(Algorithm::kAes192, CKK_AES, CKM_AES_KEY_GEN, 24U);
    ExpectKey(Algorithm::kAes256, CKK_AES, CKM_AES_KEY_GEN, 32U);
    ExpectKey(Algorithm::kAes128Cbc, CKK_AES, CKM_AES_KEY_GEN, 16U);
    ExpectKey(Algorithm::kAes256Gcm, CKK_AES, CKM_AES_KEY_GEN, 32U);
    ExpectKey(Algorithm::kAes128Cmac, CKK_AES, CKM_AES_KEY_GEN, 16U);
    ExpectKey(Algorithm::kAes256Cmac, CKK_AES, CKM_AES_KEY_GEN, 32U);
}

TEST(Pkcs11AlgorithmInfoTest, HmacRowsNeedAGenericSecretOfTheDigestLength)
{
    ExpectKey(Algorithm::kHmacSha256, CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 32U);
    ExpectKey(Algorithm::kHmacSha384, CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 48U);
    ExpectKey(Algorithm::kHmacSha512, CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 64U);
}

TEST(Pkcs11AlgorithmInfoTest, EllipticCurveAndKeylessRowsHaveNoKey)
{
    EXPECT_FALSE(LookupAlgorithm(Row(Algorithm::kEcdsaP256)).has_value());
    EXPECT_FALSE(LookupAlgorithm(Row(Algorithm::kEcdsaP256Sha256)).has_value());
    EXPECT_FALSE(LookupAlgorithm(Row(Algorithm::kSha256)).has_value());
}

}  // namespace
}  // namespace score::crypto::daemon::provider::pkcs11::detail
