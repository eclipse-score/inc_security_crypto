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

void ExpectKey(const char* name, const CK_KEY_TYPE key_type, const CK_MECHANISM_TYPE gen, const CK_ULONG len)
{
    const auto info = LookupAlgorithm(common::AlgorithmId{name});
    ASSERT_TRUE(info.has_value()) << name;
    EXPECT_EQ(info->ck_key_type, key_type) << name;
    EXPECT_EQ(info->gen_mechanism, gen) << name;
    EXPECT_EQ(info->value_len, len) << name;
}

TEST(Pkcs11AlgorithmInfoTest, AesKeyCipherAndCmacNamesNeedAnAesKeyOfTheNamedLength)
{
    ExpectKey("AES-128", CKK_AES, CKM_AES_KEY_GEN, 16U);
    ExpectKey("AES-192", CKK_AES, CKM_AES_KEY_GEN, 24U);
    ExpectKey("AES-256", CKK_AES, CKM_AES_KEY_GEN, 32U);
    ExpectKey("AES-128-CBC", CKK_AES, CKM_AES_KEY_GEN, 16U);
    ExpectKey("AES-256-GCM", CKK_AES, CKM_AES_KEY_GEN, 32U);
    ExpectKey("AES-128-CMAC", CKK_AES, CKM_AES_KEY_GEN, 16U);
    ExpectKey("AES-256-CMAC", CKK_AES, CKM_AES_KEY_GEN, 32U);
}

TEST(Pkcs11AlgorithmInfoTest, HmacNamesNeedAGenericSecretOfTheDigestLength)
{
    ExpectKey("HMAC-SHA256", CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 32U);
    ExpectKey("HMAC-SHA384", CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 48U);
    ExpectKey("HMAC-SHA512", CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 64U);
}

// Names are matched exactly; a known name inside a longer one is not enough.
TEST(Pkcs11AlgorithmInfoTest, MalformedAndUnknownNamesHaveNoKey)
{
    for (const char* name : {"XAES-256", "AES-256X", "HMAC-SHA256-X", "aes-256", "", "UNKNOWN"})
    {
        EXPECT_FALSE(LookupAlgorithm(common::AlgorithmId{name}).has_value()) << name;
    }
}

TEST(Pkcs11AlgorithmInfoTest, EllipticCurveAndKeylessNamesHaveNoKey)
{
    for (const char* name : {"ECDSA-P256", "ECDSA-P256-SHA256", "SHA256"})
    {
        EXPECT_FALSE(LookupAlgorithm(common::AlgorithmId{name}).has_value()) << name;
    }
}

}  // namespace
}  // namespace score::crypto::daemon::provider::pkcs11::detail
