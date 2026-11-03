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

/// @file openssl_algorithm_info_test.cpp
/// @brief Pins the relation between the OpenSSL provider's supported-algorithm
///        lists and the provider-neutral property tables.
///
/// The provider list gates what the factory accepts; the common table supplies
/// the properties the handler bases read. A list entry the common table cannot
/// resolve would be accepted at CTX_CREATE and fail at the first operation, and
/// a common-table row the list does not name must stay refused.

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cipher/openssl_cipher_handler.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace
{

namespace detail = score::crypto::daemon::provider::openssl::detail;
namespace algo_info = score::crypto::daemon::common;
using score::crypto::daemon::provider::score_provider::openssl::handler::OpenSslCipherHandler;

/// The provider serves SHA-2 only; MD5 and SHA-1 have catalog rows but are refused.
TEST(OpenSslAlgorithmInfoTest, HashAndHmacMapping)
{
    EXPECT_EQ(detail::LookupHashEVPMD("SHA224"), EVP_sha224());
    EXPECT_EQ(detail::LookupHashEVPMD("SHA256"), EVP_sha256());
    EXPECT_EQ(detail::LookupHashEVPMD("SHA384"), EVP_sha384());
    EXPECT_EQ(detail::LookupHashEVPMD("SHA512"), EVP_sha512());
    EXPECT_EQ(detail::LookupHashEVPMD("SHA1"), nullptr);
    EXPECT_EQ(detail::LookupHashEVPMD("MD5"), nullptr);
    EXPECT_EQ(detail::LookupHashEVPMD("HMAC-SHA256"), nullptr);

    EXPECT_EQ(detail::LookupHmacEVPMD("HMAC-SHA256"), EVP_sha256());
    EXPECT_EQ(detail::LookupHmacEVPMD("HMAC-SHA512"), EVP_sha512());
    EXPECT_EQ(detail::LookupHmacEVPMD("AES-128-CMAC"), nullptr);
    EXPECT_EQ(detail::LookupHmacEVPMD("SHA256"), nullptr);
}

/// Every cipher the provider lists has properties in the common table.
TEST(OpenSslAlgorithmInfoTest, EveryListedCipherHasCommonProperties)
{
    for (const auto name : detail::kSupportedCiphers)
    {
        EXPECT_TRUE(algo_info::LookupCipher(name).has_value()) << name << " is listed but has no common properties";
    }
}

/// Every signature scheme the provider lists resolves according to its family.
TEST(OpenSslAlgorithmInfoTest, EveryListedSignatureSchemeResolvesCurveAndDigest)
{
    for (const auto name : detail::kSupportedSignatureAlgorithms)
    {
        const std::string_view algorithm{name};
        if (algorithm.find("ECDSA-") == 0U)
        {
            EXPECT_TRUE(algo_info::IsEcdsaAlgorithm(name)) << name << " does not name a known curve";
            EXPECT_TRUE(algo_info::LookupSignatureDigest(name).has_value()) << name << " does not name a known digest";
        }
        else if (algorithm.find("RSA-PSS-") == 0U)
        {
            EXPECT_TRUE(algo_info::IsRsaPssAlgorithm(name)) << name << " is not a valid RSA-PSS algorithm";
            EXPECT_TRUE(algo_info::LookupSignatureDigest(name).has_value()) << name << " does not name a known digest";
        }
        else
        {
            EXPECT_TRUE(algo_info::IsEd25519Algorithm(name)) << name << " is not a valid Ed25519 algorithm";
        }
    }
}

/// The cipher handler accepts exactly the common-table rows the provider lists.
TEST(OpenSslAlgorithmInfoTest, CipherHandlerAcceptsOnlyListedRows)
{
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        if (row.category != score::crypto::AlgorithmCategory::kCipher)
        {
            continue;
        }
        const std::string name{row.name};
        EXPECT_EQ(OpenSslCipherHandler::IsAlgorithmSupported(name), detail::IsCipherSupported(row.name)) << name;
    }
}

/// ECDSA is served on every curve with every hash the provider maps to an EVP_MD.
TEST(OpenSslAlgorithmInfoTest, EcdsaServedForEverySupportedHash)
{
    for (const auto curve : {"P256", "P384", "P521"})
    {
        for (const auto hash : {"SHA224", "SHA256", "SHA384", "SHA512"})
        {
            const std::string name = std::string{"ECDSA-"} + curve + "-" + hash;
            EXPECT_TRUE(detail::IsSignatureAlgorithmSupported(name)) << name;
        }
        for (const auto hash : {"SHA1", "MD5"})
        {
            const std::string name = std::string{"ECDSA-"} + curve + "-" + hash;
            EXPECT_TRUE(algo_info::IsEcdsaAlgorithm(name)) << name;
            EXPECT_FALSE(detail::IsSignatureAlgorithmSupported(name)) << name;
        }
    }
}

/// The bare key form is a key algorithm, not a signature scheme.
TEST(OpenSslAlgorithmInfoTest, BareKeyFormIsNotASignatureScheme)
{
    const std::string bare{"ECDSA-P256"};
    const std::string full{"ECDSA-P256-SHA256"};
    EXPECT_TRUE(detail::IsSignatureAlgorithmSupported(full));
    EXPECT_FALSE(detail::IsSignatureAlgorithmSupported(bare));
}

}  // namespace
