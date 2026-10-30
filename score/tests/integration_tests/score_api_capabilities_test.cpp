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

bool HasMode(const AlgorithmCapabilities& caps, std::string_view mode)
{
    const auto end = caps.modes.begin() + static_cast<std::ptrdiff_t>(caps.mode_count);
    return std::any_of(caps.modes.begin(), end, [mode](const auto& entry) {
        return std::string_view{entry} == mode;
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
        EXPECT_GT(entry.mode_count, 0U) << std::string_view{entry.id};
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

TEST_F(CapabilitiesTest, ProviderResolvesByName)
{
#ifdef SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED
    constexpr std::string_view kName = "OPENSSL";
#else
    constexpr std::string_view kName = "PKCS11_ENGINE";
#endif
    const auto resource = m_ctx->ResolveResource(ResourceId{kName}, ResourceType::kProvider);
    ASSERT_TRUE(resource.has_value()) << resource.error().Message();
    EXPECT_EQ(resource->type, ResourceType::kProvider);
    EXPECT_EQ(resource->primary_provider, static_cast<std::uint16_t>(resource->id));

    const auto info = m_ctx->GetProviderInfo(resource.value());
    ASSERT_TRUE(info.has_value()) << info.error().Message();
    EXPECT_EQ(std::string_view{info->name}, kName);
}

TEST_F(CapabilitiesTest, UnknownProviderNameDoesNotResolve)
{
    const auto resource = m_ctx->ResolveResource(ResourceId{"NO_SUCH_PROVIDER"}, ResourceType::kProvider);
    EXPECT_FALSE(resource.has_value());
}

TEST_F(CapabilitiesTest, HashIsReported)
{
    const auto caps = m_ctx->QueryCapabilities(AlgorithmId{"SHA256"});
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();
    EXPECT_TRUE(caps->supported);
    EXPECT_TRUE(HasMode(caps.value(), "HASH"));
    EXPECT_FALSE(HasMode(caps.value(), "SIGN"));
}

TEST_F(CapabilitiesTest, HmacReportsMacAndKeyGeneration)
{
    const auto caps = m_ctx->QueryCapabilities(AlgorithmId{"HMAC-SHA256"});
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();
    EXPECT_TRUE(caps->supported);
    EXPECT_TRUE(HasMode(caps.value(), "MAC"));
    EXPECT_TRUE(HasMode(caps.value(), "GENERATE_KEY"));
}

#ifdef SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED
TEST_F(CapabilitiesTest, SoftwareSignatureAndCipherAreReported)
{
    const auto ecdsa = m_ctx->QueryCapabilities(AlgorithmId{"ECDSA-P256-SHA256"});
    ASSERT_TRUE(ecdsa.has_value()) << ecdsa.error().Message();
    EXPECT_TRUE(HasMode(ecdsa.value(), "SIGN"));
    EXPECT_TRUE(HasMode(ecdsa.value(), "VERIFY"));

    const auto ec_key = m_ctx->QueryCapabilities(AlgorithmId{"ECDSA-P256"});
    ASSERT_TRUE(ec_key.has_value()) << ec_key.error().Message();
    EXPECT_TRUE(HasMode(ec_key.value(), "GENERATE_KEY"));
    EXPECT_FALSE(HasMode(ec_key.value(), "SIGN"));

    const auto cbc = m_ctx->QueryCapabilities(AlgorithmId{"AES-256-CBC"});
    ASSERT_TRUE(cbc.has_value()) << cbc.error().Message();
    EXPECT_TRUE(HasMode(cbc.value(), "CIPHER"));
}
#endif

TEST_F(CapabilitiesTest, UnknownAlgorithmIsUnsupported)
{
    const auto caps = m_ctx->QueryCapabilities(AlgorithmId{"NOT-AN-ALGORITHM"});
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();
    EXPECT_FALSE(caps->supported);
    EXPECT_EQ(caps->mode_count, 0U);
    EXPECT_EQ(std::string_view{caps->id}, "NOT-AN-ALGORITHM");
}

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
