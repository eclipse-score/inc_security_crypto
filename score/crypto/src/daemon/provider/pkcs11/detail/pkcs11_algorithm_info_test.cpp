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
