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

#include "score/crypto/src/api/config/algorithm_selection.hpp"
#include "score/crypto/src/api/config/cipher_context_config.hpp"
#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/config/mac_context_config.hpp"
#include "score/crypto/src/api/config/random_context_config.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace score::crypto
{
namespace
{

// The fluent return type is the derived config for both overloads.
static_assert(
    std::is_same_v<decltype(std::declval<HashContextConfig&>().SetAlgorithm(Algorithm::kSha256)), HashContextConfig&>);
static_assert(
    std::is_same_v<decltype(std::declval<SignContextConfig&>().SetAlgorithm(Algorithm::kEd25519)), SignContextConfig&>);
static_assert(
    std::is_same_v<decltype(std::declval<GenerateKeyParams&>().SetAlgorithm(Algorithm::kAes256)), GenerateKeyParams&>);
// String literals and std::string still pick the string overload: these
// expressions would not compile if the call were ambiguous.
static_assert(std::is_same_v<decltype(std::declval<HashContextConfig&>().SetAlgorithm("SHA256")), HashContextConfig&>);
static_assert(std::is_same_v<decltype(std::declval<MacContextConfig&>().SetAlgorithm(std::string{"HMAC-SHA256"})),
                             MacContextConfig&>);
static_assert(std::is_same_v<decltype(std::declval<ImportKeyParams&>().SetAlgorithm("AES-256")), ImportKeyParams&>);

std::string_view Name(const AlgorithmId& id)
{
    return std::string_view{id};
}

TEST(AlgorithmSelectionTest, EnumeratorStoresTheCatalogName)
{
    EXPECT_EQ(Name(HashContextConfig{}.SetAlgorithm(Algorithm::kSha256).algorithm), "SHA256");
    EXPECT_EQ(Name(MacContextConfig{}.SetAlgorithm(Algorithm::kHmacSha384).algorithm), "HMAC-SHA384");
    EXPECT_EQ(Name(CipherContextConfig{}.SetAlgorithm(Algorithm::kAes128Cbc).algorithm), "AES-128-CBC");
    EXPECT_EQ(Name(SignContextConfig{}.SetAlgorithm(Algorithm::kEcdsaP256Sha384).algorithm), "ECDSA-P256-SHA384");
    EXPECT_EQ(Name(VerifySignatureContextConfig{}.SetAlgorithm(Algorithm::kEd25519).algorithm), "Ed25519");
    EXPECT_EQ(Name(RandomContextConfig{}.SetAlgorithm(Algorithm::kCtrDrbg).algorithm), "CTR-DRBG");
    EXPECT_EQ(Name(GenerateKeyParams{}.SetAlgorithm(Algorithm::kEcdsaP384).algorithm), "ECDSA-P384");
    EXPECT_EQ(Name(ImportKeyParams{}.SetAlgorithm(Algorithm::kAes256).algorithm), "AES-256");
}

TEST(AlgorithmSelectionTest, ValueWithoutRowStoresANonCatalogNonEmptyName)
{
    const auto unknown = HashContextConfig{}.SetAlgorithm(Algorithm::kUnknown).algorithm;
    EXPECT_FALSE(Name(unknown).empty());
    EXPECT_FALSE(FromAlgorithmName(Name(unknown)).has_value());

    const auto out_of_range = RandomContextConfig{}.SetAlgorithm(static_cast<Algorithm>(0xFFFFU)).algorithm;
    EXPECT_EQ(Name(out_of_range), config_detail::kNoCatalogRowName);
    EXPECT_EQ(Name(GenerateKeyParams{}.SetAlgorithm(Algorithm::kUnknown).algorithm), config_detail::kNoCatalogRowName);
}

TEST(AlgorithmSelectionTest, StringOverloadStoresTheNameUnchanged)
{
    // A name the enum overload could never produce proves the string overload ran.
    EXPECT_EQ(Name(HashContextConfig{}.SetAlgorithm("NOT-IN-CATALOG").algorithm), "NOT-IN-CATALOG");
    const std::string name{"sha256"};
    EXPECT_EQ(Name(HashContextConfig{}.SetAlgorithm(name).algorithm), "sha256");
}

}  // namespace
}  // namespace score::crypto
