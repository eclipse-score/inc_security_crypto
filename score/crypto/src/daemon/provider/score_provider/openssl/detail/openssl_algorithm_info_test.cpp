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
/// @brief Pins which catalog rows the OpenSSL provider serves.
///
/// The provider decides from the typed fields of a row. These tests walk the
/// whole catalog so that a row added to it shows up here as a change of the
/// served set rather than slipping in or out unnoticed.

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cipher/openssl_cipher_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/hash/openssl_hash_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/mac/openssl_hmac_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/random/openssl_random_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/sign/openssl_ecdsa_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/sign/openssl_ed25519_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/sign/openssl_rsa_pss_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/verify/openssl_ecdsa_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/verify/openssl_ed25519_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/verify/openssl_rsa_pss_verify_handler.hpp"

#include <gtest/gtest.h>

#include <set>
#include <string>
#include <string_view>

namespace
{

namespace detail = score::crypto::daemon::provider::openssl::detail;
namespace handler = score::crypto::daemon::provider::score_provider::openssl::handler;
using score::crypto::AlgorithmDescriptor;

AlgorithmDescriptor Row(std::string_view name)
{
    const auto row = score::crypto::GetAlgorithmDescriptor(name);
    EXPECT_TRUE(row.has_value()) << name;
    return row.value_or(AlgorithmDescriptor{});
}

/// Names of the catalog rows @p served accepts.
template <typename Predicate>
std::set<std::string_view> ServedRows(Predicate served)
{
    std::set<std::string_view> names;
    for (const auto& row : score::crypto::kAlgorithmCatalog)
    {
        if (served(row))
        {
            names.insert(row.name);
        }
    }
    return names;
}

/// The provider serves SHA-2 only; MD5 and SHA-1 have catalog rows but are refused.
TEST(OpenSslAlgorithmInfoTest, HashFunctionMapping)
{
    EXPECT_EQ(detail::ToEvpMd(score::crypto::HashFunction::kSha224), EVP_sha224());
    EXPECT_EQ(detail::ToEvpMd(score::crypto::HashFunction::kSha256), EVP_sha256());
    EXPECT_EQ(detail::ToEvpMd(score::crypto::HashFunction::kSha384), EVP_sha384());
    EXPECT_EQ(detail::ToEvpMd(score::crypto::HashFunction::kSha512), EVP_sha512());
    EXPECT_EQ(detail::ToEvpMd(score::crypto::HashFunction::kSha1), nullptr);
    EXPECT_EQ(detail::ToEvpMd(score::crypto::HashFunction::kMd5), nullptr);
    EXPECT_EQ(detail::ToEvpMd(score::crypto::HashFunction::kNone), nullptr);
}

TEST(OpenSslAlgorithmInfoTest, CurveMapping)
{
    EXPECT_STREQ(detail::ToOpenSslGroupName(score::crypto::EccCurve::kP256), "prime256v1");
    EXPECT_STREQ(detail::ToOpenSslGroupName(score::crypto::EccCurve::kP384), "secp384r1");
    EXPECT_STREQ(detail::ToOpenSslGroupName(score::crypto::EccCurve::kP521), "secp521r1");
    EXPECT_EQ(detail::ToOpenSslGroupName(score::crypto::EccCurve::kNone), nullptr);
}

TEST(OpenSslAlgorithmInfoTest, HashHandlerServesSha2Rows)
{
    const std::set<std::string_view> expected{"SHA224", "SHA256", "SHA384", "SHA512"};
    EXPECT_EQ(ServedRows(handler::OpenSslHashHandler::IsAlgorithmSupported), expected);
    EXPECT_FALSE(handler::OpenSslHashHandler::IsAlgorithmSupported(Row("SHA1")));
    EXPECT_FALSE(handler::OpenSslHashHandler::IsAlgorithmSupported(Row("MD5")));
}

/// CMAC is a MAC as well, but not one the HMAC path serves.
TEST(OpenSslAlgorithmInfoTest, HmacHandlerServesHmacRowsOnly)
{
    const std::set<std::string_view> expected{"HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"};
    EXPECT_EQ(ServedRows(handler::OpenSslHmacHandler::IsAlgorithmSupported), expected);
    EXPECT_FALSE(handler::OpenSslHmacHandler::IsAlgorithmSupported(Row("AES-128-CMAC")));
    EXPECT_FALSE(handler::OpenSslHmacHandler::IsAlgorithmSupported(Row("AES-256-CMAC")));
    EXPECT_FALSE(handler::OpenSslHmacHandler::IsAlgorithmSupported(Row("SHA256")));
}

TEST(OpenSslAlgorithmInfoTest, CipherHandlerServesAesCbcRows)
{
    const std::set<std::string_view> expected{"AES-128-CBC", "AES-192-CBC", "AES-256-CBC"};
    EXPECT_EQ(ServedRows(handler::OpenSslCipherHandler::IsAlgorithmSupported), expected);
    for (const auto name : expected)
    {
        EXPECT_STREQ(detail::ToEvpCipherName(Row(name)), std::string{name}.c_str());
    }
    EXPECT_EQ(detail::ToEvpCipherName(Row("AES-256-GCM")), nullptr);
    EXPECT_EQ(detail::ToEvpCipherName(Row("AES-256")), nullptr);
}

/// ECDSA is served on every curve with every SHA-2 digest; each family claims its own rows.
TEST(OpenSslAlgorithmInfoTest, SignatureHandlersServeTheirFamily)
{
    const std::set<std::string_view> ecdsa{"ECDSA-P256-SHA224",
                                           "ECDSA-P256-SHA256",
                                           "ECDSA-P256-SHA384",
                                           "ECDSA-P256-SHA512",
                                           "ECDSA-P384-SHA224",
                                           "ECDSA-P384-SHA256",
                                           "ECDSA-P384-SHA384",
                                           "ECDSA-P384-SHA512",
                                           "ECDSA-P521-SHA224",
                                           "ECDSA-P521-SHA256",
                                           "ECDSA-P521-SHA384",
                                           "ECDSA-P521-SHA512"};
    const std::set<std::string_view> rsa_pss{"RSA-PSS-2048-SHA256",
                                             "RSA-PSS-2048-SHA384",
                                             "RSA-PSS-2048-SHA512",
                                             "RSA-PSS-3072-SHA256",
                                             "RSA-PSS-3072-SHA384",
                                             "RSA-PSS-3072-SHA512",
                                             "RSA-PSS-4096-SHA256",
                                             "RSA-PSS-4096-SHA384",
                                             "RSA-PSS-4096-SHA512"};
    const std::set<std::string_view> ed25519{"Ed25519"};

    EXPECT_EQ(ServedRows(handler::OpenSslEcdsaSignHandler::IsAlgorithmSupported), ecdsa);
    EXPECT_EQ(ServedRows(handler::OpenSslEcdsaVerifyHandler::IsAlgorithmSupported), ecdsa);
    EXPECT_EQ(ServedRows(handler::OpenSslRsaPssSignHandler::IsAlgorithmSupported), rsa_pss);
    EXPECT_EQ(ServedRows(handler::OpenSslRsaPssVerifyHandler::IsAlgorithmSupported), rsa_pss);
    EXPECT_EQ(ServedRows(handler::OpenSslEd25519SignHandler::IsAlgorithmSupported), ed25519);
    EXPECT_EQ(ServedRows(handler::OpenSslEd25519VerifyHandler::IsAlgorithmSupported), ed25519);

    EXPECT_TRUE(detail::IsSignatureSupported(Row("ECDSA-P256-SHA384")));
    EXPECT_TRUE(detail::IsSignatureSupported(Row("ECDSA-P521-SHA224")));
}

/// The bare key form is a key algorithm, not a signature scheme.
TEST(OpenSslAlgorithmInfoTest, KeyRowsAreNotSignatureSchemes)
{
    EXPECT_FALSE(detail::IsSignatureSupported(Row("ECDSA-P256")));
    EXPECT_FALSE(detail::IsSignatureSupported(Row("RSA-2048")));
    EXPECT_FALSE(detail::IsSignatureSupported(Row("AES-256")));
}

TEST(OpenSslAlgorithmInfoTest, RandomHandlerServesCtrDrbg)
{
    const std::set<std::string_view> expected{"CTR-DRBG"};
    EXPECT_EQ(ServedRows(handler::OpenSslRandomHandler::IsAlgorithmSupported), expected);
}

}  // namespace
