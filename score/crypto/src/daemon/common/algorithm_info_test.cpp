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

TEST(AlgorithmInfoTest, HashPropertiesComeFromCatalog)
{
    EXPECT_EQ(LookupDigestSize("SHA256"), 32U);
    EXPECT_EQ(LookupDigestSize("SHA224"), 28U);
    EXPECT_EQ(LookupHashFunction("SHA384"), ::score::crypto::HashFunction::kSha384);

    EXPECT_FALSE(LookupDigestSize("HMAC-SHA256").has_value());
    EXPECT_FALSE(LookupHashFunction("HMAC-SHA256").has_value());
    EXPECT_FALSE(LookupDigestSize("sha256").has_value());
    EXPECT_FALSE(LookupDigestSize("UNSUPPORTED_ALGORITHM").has_value());
}

TEST(AlgorithmInfoTest, MacPropertiesComeFromCatalog)
{
    EXPECT_EQ(LookupMacSize("HMAC-SHA256"), 32U);
    EXPECT_EQ(LookupMacSize("AES-128-CMAC"), 16U);
    EXPECT_EQ(LookupHmacHashFunction("HMAC-SHA512"), ::score::crypto::HashFunction::kSha512);

    // CMAC is a MAC without an underlying hash.
    EXPECT_FALSE(LookupHmacHashFunction("AES-128-CMAC").has_value());
    EXPECT_FALSE(LookupMacSize("SHA256").has_value());
    EXPECT_FALSE(LookupMacSize("HMAC-SHA1").has_value());
    EXPECT_FALSE(LookupMacSize("UNSUPPORTED_ALGORITHM").has_value());
}

TEST(AlgorithmInfoTest, RsaPssAndEd25519ResolveThroughCatalog)
{
    EXPECT_TRUE(IsRsaPssAlgorithm("RSA-PSS-2048-SHA256"));
    EXPECT_FALSE(IsRsaPssAlgorithm("RSA-2048"));
    EXPECT_FALSE(IsRsaPssAlgorithm("RSA-PSS-20481-SHA256"));
    EXPECT_FALSE(IsRsaPssAlgorithm("RSA-PSS-2048-SHA256X"));
    EXPECT_FALSE(IsRsaPssAlgorithm("XRSA-PSS-2048-SHA256"));

    EXPECT_EQ(LookupSignatureDigest("RSA-PSS-4096-SHA384"), std::optional<std::string_view>{"SHA384"});
    EXPECT_EQ(LookupSignatureDigestSize("RSA-PSS-4096-SHA512"), 64U);
    EXPECT_EQ(LookupSignatureDigestSize("ECDSA-P384-SHA384"), 48U);
    EXPECT_FALSE(LookupSignatureDigest("Ed25519").has_value());
    EXPECT_FALSE(LookupSignatureDigestSize("Ed25519").has_value());
    // A hash name inside an unknown identifier no longer yields a digest.
    EXPECT_FALSE(LookupSignatureDigestSize("FOO-SHA256").has_value());

    const auto key = LookupRsaKeyInfo("RSA-3072");
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(key->modulus_size, 384U);
    EXPECT_EQ(key->key_bits, 3072U);
    EXPECT_FALSE(LookupRsaKeyInfo("RSA-PSS-3072-SHA256").has_value());

    const auto scheme_key = LookupRsaKeyInfoForSignatureAlgorithm("RSA-PSS-3072-SHA512");
    ASSERT_TRUE(scheme_key.has_value());
    EXPECT_EQ(scheme_key->name, "RSA-3072");
    EXPECT_FALSE(LookupRsaKeyInfoForSignatureAlgorithm("RSA-PSS-20481-SHA256").has_value());

    EXPECT_TRUE(IsEd25519Algorithm("Ed25519"));
    EXPECT_FALSE(IsEd25519Algorithm("ED25519"));
    EXPECT_EQ(LookupKeySize("Ed25519"), 32U);
    EXPECT_EQ(LookupKeySize("RSA-2048"), 256U);
}

TEST(AlgorithmInfoTest, AllInCatalogRejectsUnknownAndMiscategorisedNames)
{
    using ::score::crypto::AlgorithmCategory;
    constexpr const char* kCatalogued[] = {"AES-256-CBC", "HMAC-SHA256", "AES-256"};
    constexpr const char* kMisspelt[] = {"AES-256-CBC", "AES256-CBC"};
    constexpr std::string_view kCiphers[] = {"AES-128-CBC", "AES-256-CBC"};
    constexpr std::string_view kKeyInCipherList[] = {"AES-128-CBC", "AES-256"};

    static_assert(AllInCatalog(kCatalogued));
    static_assert(!AllInCatalog(kMisspelt));
    static_assert(AllInCatalog(kCiphers, AlgorithmCategory::kCipher));
    static_assert(!AllInCatalog(kKeyInCipherList, AlgorithmCategory::kCipher));
    static_assert(!AllInCatalog(kMisspelt, AlgorithmCategory::kCipher));
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

TEST(AlgorithmInfoTest, EcdsaNamePairsAnyCurveWithAnyCatalogHash)
{
    // No catalog row is needed for a pairing; refusing a weak hash is up to the provider.
    for (const auto name : {"ECDSA-P256-SHA384", "ECDSA-P384-SHA512", "ECDSA-P521-SHA224", "ECDSA-P256-SHA1"})
    {
        EXPECT_TRUE(algo_info::IsEcdsaAlgorithm(name)) << name;
        EXPECT_TRUE(algo_info::LookupSignatureDigest(name).has_value()) << name;
    }
    EXPECT_EQ(algo_info::LookupSignatureDigestSize("ECDSA-P384-SHA512"), 64U);

    // The hash token must be a hash row, not any catalog name.
    for (const auto name : {"ECDSA-P256-MD4", "ECDSA-P256-HMAC-SHA256", "ECDSA-P256-AES-256"})
    {
        EXPECT_FALSE(algo_info::ParseEcdsaName(name).has_value()) << name;
    }
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
    EXPECT_FALSE(algo_info::LookupKeySize("RSA-PSS-2048-SHA256").has_value());
    EXPECT_FALSE(algo_info::LookupKeySize("ECDSA-P256-SHA256").has_value());
}

}  // namespace
