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
/// its backend is part of the build. Those configured names never reach the
/// app: providers are listed by id and type, and a provider resource reports
/// the app-scoped name it was resolved by.

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/mac_context_config.hpp"
#include "score/crypto/src/api/config/random_context_config.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_mac_context.hpp"
#include "score/crypto/src/api/contexts/i_random_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/types/common.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
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

const ProviderInfo* FindProvider(const SystemCapabilities& caps, ProviderType type)
{
    for (std::size_t i = 0U; i < caps.provider_count; ++i)
    {
        if (caps.providers[i].type == type)
        {
            return &caps.providers[i];
        }
    }
    return nullptr;
}

score::result::ErrorCode Code(CryptoErrorCode code)
{
    return static_cast<score::result::ErrorCode>(code);
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
    EXPECT_NE(FindProvider(caps.value(), ProviderType::kSoftware), nullptr);
#endif
#ifdef SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED
    EXPECT_NE(FindProvider(caps.value(), ProviderType::kHardware), nullptr);
#endif
}

TEST_F(CapabilitiesTest, SystemCapabilitiesDoNotExposeProviderNames)
{
    const auto caps = m_ctx->QueryCapabilities();
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();
    ASSERT_GT(caps->provider_count, 0U);

    for (std::size_t i = 0U; i < caps->provider_count; ++i)
    {
        EXPECT_EQ(std::string_view{caps->providers[i].name}, "") << caps->providers[i].id;
        const auto info = m_ctx->GetProviderInfo(caps->providers[i].id);
        ASSERT_TRUE(info.has_value()) << info.error().Message();
        EXPECT_EQ(std::string_view{info->name}, "") << caps->providers[i].id;
    }
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
    EXPECT_EQ(info->type, listed.type);
}

// Provider resources are mapped per uid in provider_config of integration_test_config.json.
constexpr auto kSoftwareProvider = "IntegrationTest_SoftwareProvider";
constexpr auto kHardwareProvider = "IntegrationTest_HardwareProvider";

void ExpectProviderResourceResolvesTo(ICryptoContext& ctx, std::string_view resource_name, ProviderType type)
{
    const auto handle = ctx.ResolveResource(ResourceId{resource_name}, ResourceType::kProvider);
    ASSERT_TRUE(handle.has_value()) << resource_name << ": " << handle.error().Message();
    EXPECT_EQ(handle->type, ResourceType::kProvider);
    EXPECT_EQ(handle->primary_provider, 0xFFFFU);  // the provider id is not exposed in the handle

    const auto info = ctx.GetProviderInfo(handle.value());
    ASSERT_TRUE(info.has_value()) << info.error().Message();
    EXPECT_EQ(info->type, type);
    // The app's own name for the provider, not the configured provider name.
    EXPECT_EQ(std::string_view{info->name}, resource_name);
}

CryptoResourceId ProviderResource(ICryptoContext& ctx, std::string_view resource_name)
{
    const auto handle = ctx.ResolveResource(ResourceId{resource_name}, ResourceType::kProvider);
    EXPECT_TRUE(handle.has_value()) << resource_name << ": " << handle.error().Message();
    return handle.value_or(CryptoResourceId{});
}

// SHA-256("abc"), FIPS 180-2 Appendix B.1.
constexpr std::array<std::uint8_t, 32U> kSha256Abc{
    0xBAU, 0x78U, 0x16U, 0xBFU, 0x8FU, 0x01U, 0xCFU, 0xEAU, 0x41U, 0x41U, 0x40U, 0xDEU, 0x5DU, 0xAEU, 0x22U, 0x23U,
    0xB0U, 0x03U, 0x61U, 0xA3U, 0x96U, 0x17U, 0x7AU, 0x9CU, 0xB4U, 0x10U, 0xFFU, 0x61U, 0xF2U, 0x00U, 0x15U, 0xADU};

void ExpectHashOnProviderResource(ICryptoContext& ctx, std::string_view resource_name)
{
    HashContextConfig config;
    config.SetAlgorithm("SHA256");
    config.SetProvider(ProviderResource(ctx, resource_name));
    auto hash = ctx.CreateHashContext(config);
    ASSERT_TRUE(hash.has_value()) << resource_name << ": " << hash.error().Message();

    constexpr std::array<std::uint8_t, 3U> input{'a', 'b', 'c'};
    std::array<std::uint8_t, 32U> digest{};
    const auto written = hash.value()->SingleShot({input.data(), input.size()}, {digest.data(), digest.size()});
    ASSERT_TRUE(written.has_value()) << resource_name << ": " << written.error().Message();
    EXPECT_EQ(written.value(), digest.size());
    EXPECT_EQ(digest, kSha256Abc) << resource_name;
}

#ifdef SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED
TEST_F(CapabilitiesTest, SoftwareProviderResourceResolvesToOpaqueHandle)
{
    ExpectProviderResourceResolvesTo(*m_ctx, kSoftwareProvider, ProviderType::kSoftware);
}

TEST_F(CapabilitiesTest, HashContextRunsOnTheSoftwareProviderResource)
{
    ExpectHashOnProviderResource(*m_ctx, kSoftwareProvider);
}
#endif

#ifdef SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED
TEST_F(CapabilitiesTest, HardwareProviderResourceResolvesToOpaqueHandle)
{
    ExpectProviderResourceResolvesTo(*m_ctx, kHardwareProvider, ProviderType::kHardware);
}

TEST_F(CapabilitiesTest, HashContextRunsOnTheHardwareProviderResource)
{
    ExpectHashOnProviderResource(*m_ctx, kHardwareProvider);
}

// Only the software provider serves random generation. A context pinned to the
// hardware provider resource reports that instead of silently moving to software.
TEST_F(CapabilitiesTest, ContextOnAProviderResourceDoesNotFallBack)
{
    RandomContextConfig pinned;
    pinned.SetProvider(ProviderResource(*m_ctx, kHardwareProvider));
    const auto random = m_ctx->CreateRandomContext(pinned);
    ASSERT_FALSE(random.has_value());
    EXPECT_EQ(*random.error(), Code(CryptoErrorCode::kUnsupportedOperation)) << random.error().Message();

#ifdef SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED
    // The same request by provider type still falls back to software.
    RandomContextConfig preferred;
    preferred.SetProviderType(ProviderType::kHardwarePreferred);
    const auto fallback = m_ctx->CreateRandomContext(preferred);
    EXPECT_TRUE(fallback.has_value()) << fallback.error().Message();
#endif
}

#ifdef SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED
// The key of HMAC_SHA256_IntegrationTestKey lives on the hardware provider.
TEST_F(CapabilitiesTest, KeyedContextRunsOnlyOnTheProviderOfItsKey)
{
    KeyManagementContextConfig key_mgmt_config;
    key_mgmt_config.SetProviderType(ProviderType::kHardware);
    auto key_mgmt = m_ctx->CreateKeyManagementContext(key_mgmt_config);
    ASSERT_TRUE(key_mgmt.has_value()) << key_mgmt.error().Message();
    const auto slot = m_ctx->ResolveResource(ResourceId{"HMAC_SHA256_IntegrationTestKey"}, ResourceType::kKeySlot);
    ASSERT_TRUE(slot.has_value()) << slot.error().Message();
    auto key = key_mgmt.value()->LoadKey(slot.value());
    ASSERT_TRUE(key.has_value()) << key.error().Message();

    MacContextConfig on_software;
    on_software.SetAlgorithm("HMAC-SHA256");
    on_software.SetKey(key.value());
    on_software.SetProvider(ProviderResource(*m_ctx, kSoftwareProvider));
    const auto mismatch = m_ctx->CreateMacContext(on_software);
    ASSERT_FALSE(mismatch.has_value());
    EXPECT_EQ(*mismatch.error(), Code(CryptoErrorCode::kCrossProviderIncompatible)) << mismatch.error().Message();

    MacContextConfig on_hardware;
    on_hardware.SetAlgorithm("HMAC-SHA256");
    on_hardware.SetKey(key.value());
    on_hardware.SetProvider(ProviderResource(*m_ctx, kHardwareProvider));
    const auto match = m_ctx->CreateMacContext(on_hardware);
    EXPECT_TRUE(match.has_value()) << match.error().Message();
}
#endif
#endif

TEST_F(CapabilitiesTest, ContextRejectsAProviderThatIsNotAProviderResource)
{
    CryptoResourceId not_a_provider{};
    not_a_provider.id = 1U;
    not_a_provider.type = ResourceType::kKeySlot;
    HashContextConfig config;
    config.SetAlgorithm("SHA256");
    config.SetProvider(not_a_provider);

    const auto hash = m_ctx->CreateHashContext(config);
    ASSERT_FALSE(hash.has_value());
    EXPECT_EQ(*hash.error(), Code(CryptoErrorCode::kInvalidResourceType)) << hash.error().Message();
}

TEST_F(CapabilitiesTest, ContextRejectsAProviderHandleThatWasNotResolved)
{
    CryptoResourceId forged{};
    forged.id = 0xDEADU;
    forged.type = ResourceType::kProvider;
    HashContextConfig config;
    config.SetAlgorithm("SHA256");
    config.SetProvider(forged);

    const auto hash = m_ctx->CreateHashContext(config);
    ASSERT_FALSE(hash.has_value());
    EXPECT_EQ(*hash.error(), Code(CryptoErrorCode::kInvalidResourceId)) << hash.error().Message();

    const auto info = m_ctx->GetProviderInfo(forged);
    ASSERT_FALSE(info.has_value());
    EXPECT_EQ(*info.error(), Code(CryptoErrorCode::kInvalidResourceId)) << info.error().Message();
}

TEST_F(CapabilitiesTest, ProviderNamesAndUnmappedNamesAreNotProviderResources)
{
    for (const char* name : {"OPENSSL", "PKCS11_ENGINE", "IntegrationTest_UnknownProvider"})
    {
        const auto handle = m_ctx->ResolveResource(ResourceId{name}, ResourceType::kProvider);
        EXPECT_FALSE(handle.has_value()) << name;
    }
}

TEST_F(CapabilitiesTest, HashIsReported)
{
    const auto caps = m_ctx->QueryCapabilities(AlgorithmId{"SHA256"});
    ASSERT_TRUE(caps.has_value()) << caps.error().Message();
    EXPECT_TRUE(caps->supported);
    EXPECT_TRUE(HasMode(caps.value(), "HASH"));
    EXPECT_FALSE(HasMode(caps.value(), "SIGN"));
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
    EXPECT_TRUE(HasMode(empty.value(), "RANDOM"));
    EXPECT_EQ(empty->supported, drbg->supported);
    EXPECT_EQ(empty->mode_count, drbg->mode_count);
}
#endif

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

// Every curve/hash pairing is a catalog row of its own, so the cross pairings
// are reported like the curve's matching-hash row.
TEST_F(CapabilitiesTest, EcdsaCrossPairingsAreReported)
{
    for (const char* name : {"ECDSA-P256-SHA384", "ECDSA-P384-SHA512", "ECDSA-P521-SHA224"})
    {
        const auto caps = m_ctx->QueryCapabilities(AlgorithmId{name});
        ASSERT_TRUE(caps.has_value()) << name << ": " << caps.error().Message();
        EXPECT_TRUE(HasMode(caps.value(), "SIGN")) << name;
        EXPECT_TRUE(HasMode(caps.value(), "VERIFY")) << name;
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
    EXPECT_TRUE(HasMode(pss.value(), "SIGN"));
    EXPECT_TRUE(HasMode(pss.value(), "VERIFY"));
    EXPECT_FALSE(HasMode(pss.value(), "GENERATE_KEY"));

    const auto rsa_key = m_ctx->QueryCapabilities(AlgorithmId{"RSA-2048"});
    ASSERT_TRUE(rsa_key.has_value());
    EXPECT_TRUE(HasMode(rsa_key.value(), "GENERATE_KEY"));
    EXPECT_FALSE(HasMode(rsa_key.value(), "SIGN"));

    const auto ed = m_ctx->QueryCapabilities(AlgorithmId{"Ed25519"});
    ASSERT_TRUE(ed.has_value());
    EXPECT_TRUE(HasMode(ed.value(), "SIGN"));
    EXPECT_TRUE(HasMode(ed.value(), "VERIFY"));
    EXPECT_TRUE(HasMode(ed.value(), "GENERATE_KEY"));
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
        EXPECT_EQ(caps->mode_count, 0U) << name;
    }

    // The token generates the AES key, but only the software provider ciphers.
    const auto cbc = m_ctx->QueryCapabilities(AlgorithmId{"AES-256-CBC"});
    ASSERT_TRUE(cbc.has_value()) << cbc.error().Message();
    EXPECT_FALSE(HasMode(cbc.value(), "CIPHER"));
    EXPECT_TRUE(HasMode(cbc.value(), "GENERATE_KEY"));
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
