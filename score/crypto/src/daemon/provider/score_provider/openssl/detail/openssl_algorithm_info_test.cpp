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
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/ecdsa_common.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cipher/openssl_cipher_handler.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace
{

namespace detail = score::crypto::daemon::provider::openssl::detail;
namespace algo_info = score::crypto::daemon::common;
namespace ecdsa = score::crypto::daemon::provider::score_provider::openssl::handler::ecdsa;
using score::crypto::daemon::provider::score_provider::openssl::handler::OpenSslCipherHandler;

/// Every cipher the provider lists has properties in the common table.
TEST(OpenSslAlgorithmInfoTest, EveryListedCipherHasCommonProperties)
{
    for (const auto name : detail::kSupportedCiphers)
    {
        EXPECT_TRUE(algo_info::LookupCipher(name).has_value()) << name << " is listed but has no common properties";
    }
}

/// Every signature scheme the provider lists resolves to a curve and a digest.
TEST(OpenSslAlgorithmInfoTest, EveryListedSignatureSchemeResolvesCurveAndDigest)
{
    for (const auto name : detail::kSupportedSignatureAlgorithms)
    {
        EXPECT_TRUE(algo_info::IsEcdsaAlgorithm(name)) << name << " does not name a known curve";
        EXPECT_TRUE(algo_info::LookupSignatureDigest(name).has_value()) << name << " does not name a known digest";
    }
}

/// The cipher handler accepts exactly the common-table rows the provider lists.
TEST(OpenSslAlgorithmInfoTest, CipherHandlerAcceptsOnlyListedRows)
{
    for (const auto& row : algo_info::kCipherAlgorithms)
    {
        const std::string name{row.name};
        EXPECT_EQ(OpenSslCipherHandler::IsAlgorithmSupported(name), detail::IsCipherSupported(row.name)) << name;
    }
}

/// A scheme the common table can resolve is still refused when the provider does not list it.
TEST(OpenSslAlgorithmInfoTest, UnlistedButResolvableSchemeIsRefused)
{
    // Curve and digest both resolve in the common table; the pairing is not one
    // the provider serves.
    const std::string unlisted{"ECDSA-P256-SHA384"};
    ASSERT_TRUE(algo_info::IsEcdsaAlgorithm(unlisted));
    ASSERT_TRUE(algo_info::LookupSignatureDigest(unlisted).has_value());

    EXPECT_FALSE(detail::IsSignatureAlgorithmSupported(unlisted));
    EXPECT_FALSE(ecdsa::IsAlgorithmSupported(unlisted));
}

/// The bare key form is a key algorithm, not a signature scheme.
TEST(OpenSslAlgorithmInfoTest, BareKeyFormIsNotASignatureScheme)
{
    EXPECT_FALSE(ecdsa::IsAlgorithmSupported(std::string{"ECDSA-P256"}));
    EXPECT_TRUE(ecdsa::IsAlgorithmSupported(std::string{"ECDSA-P256-SHA256"}));
}

}  // namespace
