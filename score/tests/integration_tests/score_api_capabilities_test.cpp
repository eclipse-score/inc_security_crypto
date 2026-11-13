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

/// @file score_api_capabilities_test.cpp
/// @brief Provider information and capability discovery through ICryptoContext.
///
/// Expectations follow the providers configured for the integration daemon:
/// "OPENSSL" (software) and "PKCS11_ENGINE" (hardware, SoftHSM), each only when
/// its backend is part of the build.

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/types/common.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>

using namespace score::crypto;

namespace
{

#ifdef __QNXNTO__
constexpr auto kControlSocketEndpoint = "unix:///opt/crypto_daemon.sock";
#else
constexpr auto kControlSocketEndpoint = "unix:///tmp/crypto_daemon.sock";
#endif

#if !defined(SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED) && !defined(SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED)
static_assert(false, "At least one crypto backend must be enabled for the capability tests");
#endif

bool HasOperation(const AlgorithmCapabilities& caps, std::string_view operation)
{
    const auto end = caps.operations.begin() + static_cast<std::ptrdiff_t>(caps.operation_count);
    return std::any_of(caps.operations.begin(), end, [operation](const auto& entry) {
        return std::string_view{entry} == operation;
    });
}

const ProviderInfo* FindProvider(const SystemCapabilities& caps, std::string_view name)
{
    for (std::size_t i = 0U; i < caps.provider_count; ++i)
    {
        if (std::string_view{caps.providers[i].name} == name)
        {
            return &caps.providers[i];
        }
    }
    return nullptr;
}

class CapabilitiesTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        CryptoStackConfig stack_config;
        stack_config.SetConnectionEndpoint(kControlSocketEndpoint);
        auto stack_result = CreateCryptoStack(stack_config);
        ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
        m_stack = std::move(stack_result.value());

        auto ctx_result = m_stack->CreateCryptoContext();
        ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
        m_ctx = std::move(ctx_result.value());
    }

    ICryptoStack::Uptr m_stack;
    ICryptoContext::Uptr m_ctx;
};

TEST_F(CapabilitiesTest, SystemCapabilitiesListConfiguredProviders)
{
    const auto caps = m_ctx->QueryCapabilities();
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();

#ifdef SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED
    const auto* openssl = FindProvider(caps.value(), "OPENSSL");
    ASSERT_NE(openssl, nullptr);
    EXPECT_EQ(openssl->type, ProviderType::kSoftware);
#endif
#ifdef SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED
    const auto* pkcs11 = FindProvider(caps.value(), "PKCS11_ENGINE");
    ASSERT_NE(pkcs11, nullptr);
    EXPECT_EQ(pkcs11->type, ProviderType::kHardware);
#endif
}

TEST_F(CapabilitiesTest, SystemCapabilitiesListOnlySupportedAlgorithms)
{
    const auto caps = m_ctx->QueryCapabilities();
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();
    ASSERT_GT(caps->algorithm_count, 0U);

    bool found_sha256 = false;
    for (std::size_t i = 0U; i < caps->algorithm_count; ++i)
    {
        const auto& entry = caps->algorithms[i];
        EXPECT_TRUE(entry.supported) << std::string_view{entry.id};
        EXPECT_GT(entry.operation_count, 0U) << std::string_view{entry.id};
        found_sha256 = found_sha256 || (std::string_view{entry.id} == "SHA256");
    }
    EXPECT_TRUE(found_sha256);
}

TEST_F(CapabilitiesTest, ProviderInfoMatchesSystemCapabilities)
{
    const auto caps = m_ctx->QueryCapabilities();
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();
    ASSERT_GT(caps->provider_count, 0U);

    for (std::size_t i = 0U; i < caps->provider_count; ++i)
    {
        const auto& listed = caps->providers[i];
        const auto info = m_ctx->GetProviderInfo(listed.id);
        ASSERT_TRUE(info.has_value()) << info.error().Message();
        EXPECT_EQ(info->id, listed.id);
        EXPECT_EQ(info->type, listed.type);
        EXPECT_EQ(std::string_view{info->name}, std::string_view{listed.name});
    }
}

TEST_F(CapabilitiesTest, ProviderInfoRejectsUnknownId)
{
    const auto info = m_ctx->GetProviderInfo(static_cast<std::uint16_t>(0xFFFEU));
    ASSERT_FALSE(info.has_value());
    EXPECT_EQ(*info.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument))
        << info.error().Message();
}

TEST_F(CapabilitiesTest, ProviderInfoForAResourceUsesItsPrimaryProvider)
{
    const auto caps = m_ctx->QueryCapabilities();
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();
    ASSERT_GT(caps->provider_count, 0U);
    const auto& listed = caps->providers[0];

    CryptoResourceId resource{};
    resource.primary_provider = listed.id;
    const auto info = m_ctx->GetProviderInfo(resource);
    ASSERT_TRUE(info.has_value()) << info.error().Message();
    EXPECT_EQ(info->id, listed.id);
    EXPECT_EQ(std::string_view{info->name}, std::string_view{listed.name});
}

TEST_F(CapabilitiesTest, HashIsReported)
{
    const auto caps = m_ctx->QueryCapabilities(AlgorithmId{"SHA256"});
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();
    EXPECT_TRUE(caps->supported);
    EXPECT_TRUE(HasOperation(caps.value(), "HASH"));
    EXPECT_FALSE(HasOperation(caps.value(), "SIGN"));
}

#ifdef SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED
// An empty name is the default random generator, as for CreateRandomContext.
// Only the software provider serves random generation.
TEST_F(CapabilitiesTest, EmptyNameReportsDefaultRandomGenerator)
{
    const auto empty = m_ctx->QueryCapabilities(AlgorithmId{""});
    ASSERT_TRUE(empty.has_value()) << empty.error().Message();
    const auto drbg = m_ctx->QueryCapabilities(AlgorithmId{"CTR-DRBG"});
    ASSERT_TRUE(drbg.has_value()) << drbg.error().Message();
    EXPECT_TRUE(empty->supported);
    EXPECT_TRUE(HasOperation(empty.value(), "RANDOM"));
    EXPECT_EQ(empty->supported, drbg->supported);
    EXPECT_EQ(empty->operation_count, drbg->operation_count);
}
#endif

TEST_F(CapabilitiesTest, HmacReportsMacAndKeyGeneration)
{
    const auto caps = m_ctx->QueryCapabilities(AlgorithmId{"HMAC-SHA256"});
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();
    EXPECT_TRUE(caps->supported);
    EXPECT_TRUE(HasOperation(caps.value(), "MAC"));
    EXPECT_TRUE(HasOperation(caps.value(), "GENERATE_KEY"));
}

#ifdef SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED
TEST_F(CapabilitiesTest, SoftwareSignatureAndCipherAreReported)
{
    const auto ecdsa = m_ctx->QueryCapabilities(AlgorithmId{"ECDSA-P256-SHA256"});
    ASSERT_TRUE(ecdsa.has_value()) << ecdsa.error().Message();
    EXPECT_TRUE(HasOperation(ecdsa.value(), "SIGN"));
    EXPECT_TRUE(HasOperation(ecdsa.value(), "VERIFY"));

    const auto ec_key = m_ctx->QueryCapabilities(AlgorithmId{"ECDSA-P256"});
    ASSERT_TRUE(ec_key.has_value()) << ec_key.error().Message();
    EXPECT_TRUE(HasOperation(ec_key.value(), "GENERATE_KEY"));
    EXPECT_FALSE(HasOperation(ec_key.value(), "SIGN"));

    const auto cbc = m_ctx->QueryCapabilities(AlgorithmId{"AES-256-CBC"});
    ASSERT_TRUE(cbc.has_value()) << cbc.error().Message();
    EXPECT_TRUE(HasOperation(cbc.value(), "CIPHER"));
}

// Every curve/hash pairing is a catalog row of its own, so the cross pairings
// are reported like the curve's matching-hash row.
TEST_F(CapabilitiesTest, EcdsaCrossPairingsAreReported)
{
    for (const char* name : {"ECDSA-P256-SHA384", "ECDSA-P384-SHA512", "ECDSA-P521-SHA224"})
    {
        const auto caps = m_ctx->QueryCapabilities(AlgorithmId{name});
        ASSERT_TRUE(caps.has_value()) << name << ": " << caps.error().Message();
        EXPECT_TRUE(HasOperation(caps.value(), "SIGN")) << name;
        EXPECT_TRUE(HasOperation(caps.value(), "VERIFY")) << name;
    }

    const auto system = m_ctx->QueryCapabilities();
    ASSERT_TRUE(system.has_value()) << system.error().Message();
    bool found = false;
    for (std::size_t i = 0U; i < system->algorithm_count; ++i)
    {
        found = found || (std::string_view{system->algorithms[i].id} == "ECDSA-P256-SHA384");
    }
    EXPECT_TRUE(found);
}

TEST_F(CapabilitiesTest, RsaPssAndEd25519AreReported)
{
    const auto pss = m_ctx->QueryCapabilities(AlgorithmId{"RSA-PSS-2048-SHA256"});
    ASSERT_TRUE(pss.has_value());
    EXPECT_TRUE(HasOperation(pss.value(), "SIGN"));
    EXPECT_TRUE(HasOperation(pss.value(), "VERIFY"));
    EXPECT_FALSE(HasOperation(pss.value(), "GENERATE_KEY"));

    const auto rsa_key = m_ctx->QueryCapabilities(AlgorithmId{"RSA-2048"});
    ASSERT_TRUE(rsa_key.has_value());
    EXPECT_TRUE(HasOperation(rsa_key.value(), "GENERATE_KEY"));
    EXPECT_FALSE(HasOperation(rsa_key.value(), "SIGN"));

    const auto ed = m_ctx->QueryCapabilities(AlgorithmId{"Ed25519"});
    ASSERT_TRUE(ed.has_value());
    EXPECT_TRUE(HasOperation(ed.value(), "SIGN"));
    EXPECT_TRUE(HasOperation(ed.value(), "VERIFY"));
    EXPECT_TRUE(HasOperation(ed.value(), "GENERATE_KEY"));
}
#else
// The PKCS#11 provider serves hash, HMAC and symmetric key generation only.
TEST_F(CapabilitiesTest, SoftwareOnlyAlgorithmsAreUnsupportedWithoutTheSoftwareProvider)
{
    for (const char* name : {"", "CTR-DRBG", "ECDSA-P256-SHA256", "RSA-PSS-2048-SHA256", "Ed25519"})
    {
        const auto caps = m_ctx->QueryCapabilities(AlgorithmId{name});
        ASSERT_TRUE(caps.has_value()) << name << ": " << caps.error().Message();
        EXPECT_FALSE(caps->supported) << name;
        EXPECT_EQ(caps->operation_count, 0U) << name;
    }

    // The token generates the AES key, but only the software provider ciphers.
    const auto cbc = m_ctx->QueryCapabilities(AlgorithmId{"AES-256-CBC"});
    ASSERT_TRUE(cbc.has_value()) << cbc.error().Message();
    EXPECT_FALSE(HasOperation(cbc.value(), "CIPHER"));
    EXPECT_TRUE(HasOperation(cbc.value(), "GENERATE_KEY"));
}
#endif

TEST_F(CapabilitiesTest, UnknownAlgorithmIsUnsupported)
{
    const auto caps = m_ctx->QueryCapabilities(AlgorithmId{"NOT-AN-ALGORITHM"});
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();
    EXPECT_FALSE(caps->supported);
    EXPECT_EQ(caps->operation_count, 0U);
    EXPECT_EQ(std::string_view{caps->id}, "NOT-AN-ALGORITHM");
}

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
