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

/// @file score_api_random_example.cpp
/// @brief Demonstrates random number generation using the score::crypto API.
///
/// Shows:
///   - Creating a random context with and without a provider preference
///   - Generating buffers of various sizes
///   - Seeding the generator with additional entropy
///
/// A statistical quality assessment of the RNG is out of scope here — that is
/// the provider's responsibility and is covered by its own certification. What
/// these tests establish is that the plumbing is correct: the requested number
/// of bytes arrives, the whole buffer is written, and successive draws differ.

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/api/config/random_context_config.hpp"
#include "score/crypto/src/api/contexts/i_random_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace score::crypto;
using tests::utility::print_hex;

namespace
{

struct RandomTestData
{
    std::string test_case_name;
    std::optional<ProviderType> provider_type;
    std::string algorithm;  ///< empty selects the provider default
};

/// Creates a stack, a crypto context and a random context in one step.
/// Returns nullptr (with a gtest failure already recorded) on any error.
struct RandomFixture
{
    ICryptoStack::Uptr stack;
    ICryptoContext::Uptr ctx;
    std::unique_ptr<IRandomContext> random;
};

void MakeRandomFixture(const RandomTestData& data, RandomFixture& out)
{
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    out.stack = std::move(stack_result.value());

    auto ctx_result = out.stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    out.ctx = std::move(ctx_result.value());

    RandomContextConfig config;
    if (!data.algorithm.empty())
    {
        config.SetAlgorithm(data.algorithm);
    }
    if (data.provider_type.has_value())
    {
        config.SetProviderType(data.provider_type.value());
    }

    auto random_result = out.ctx->CreateRandomContext(config);
    ASSERT_TRUE(random_result.has_value()) << "Failed to create random context";
    out.random = std::move(random_result.value());
}

class RandomGenerationTest : public ::testing::TestWithParam<RandomTestData>
{
};

TEST_P(RandomGenerationTest, GenerateAndSeed)
{
    const auto test_data = GetParam();

    RandomFixture fixture;
    ASSERT_NO_FATAL_FAILURE(MakeRandomFixture(test_data, fixture));
    auto& random = *fixture.random;

    // =========================================================================
    // 1. Generate the common sizes an application actually asks for
    // =========================================================================
    //
    // 12 and 16 bytes are AEAD nonces and CBC/CTR IVs, 32 bytes is an AES-256
    // key's worth of material, 1 byte exercises the smallest legal request.
    for (const std::size_t size : {std::size_t{1U}, std::size_t{12U}, std::size_t{16U}, std::size_t{32U}})
    {
        // Pre-fill with a recognisable pattern so a short write is detectable.
        std::vector<uint8_t> buffer(size, 0xAAU);

        auto generated = random.Generate({buffer.data(), buffer.size()});
        ASSERT_TRUE(generated.has_value()) << "Generate(" << size << ") failed";
        EXPECT_EQ(generated.value(), size) << "Generate must report exactly the requested byte count";

        print_hex("Random", buffer, buffer.size());
    }

    // =========================================================================
    // 2. A large request is served in full
    // =========================================================================
    {
        constexpr std::size_t kLargeSize = 4096U;
        std::vector<uint8_t> buffer(kLargeSize, 0U);

        auto generated = random.Generate({buffer.data(), buffer.size()});
        ASSERT_TRUE(generated.has_value()) << "Generate(4096) failed";
        EXPECT_EQ(generated.value(), kLargeSize);

        // An all-zero 4 KiB block would mean the buffer was never written. The
        // probability of a working RNG producing it is negligible.
        const bool all_zero = std::all_of(buffer.begin(), buffer.end(), [](uint8_t b) {
            return b == 0U;
        });
        EXPECT_FALSE(all_zero) << "4 KiB of random data must not be all zero";
    }

    // =========================================================================
    // 3. Successive draws differ
    // =========================================================================
    //
    // Ten independent 32-byte draws must all be distinct. A generator that
    // repeats within ten draws of 256 bits is broken, not unlucky.
    {
        constexpr std::size_t kDraws = 10U;
        constexpr std::size_t kDrawSize = 32U;
        std::set<std::vector<uint8_t>> seen;

        for (std::size_t i = 0U; i < kDraws; ++i)
        {
            std::vector<uint8_t> buffer(kDrawSize, 0U);
            auto generated = random.Generate({buffer.data(), buffer.size()});
            ASSERT_TRUE(generated.has_value()) << "Generate for draw " << i << " failed";
            seen.insert(std::move(buffer));
        }

        EXPECT_EQ(seen.size(), kDraws) << "Successive random draws must not repeat";
    }

    // =========================================================================
    // 4. Seeding with additional entropy
    // =========================================================================
    //
    // Seeding is advisory: a provider whose entropy source cannot be seeded
    // externally reports success without changing state. Either way the call
    // must succeed and the generator must keep working afterwards.
    {
        const std::vector<uint8_t> seed{0x01U,
                                        0x02U,
                                        0x03U,
                                        0x04U,
                                        0x05U,
                                        0x06U,
                                        0x07U,
                                        0x08U,
                                        0x09U,
                                        0x0AU,
                                        0x0BU,
                                        0x0CU,
                                        0x0DU,
                                        0x0EU,
                                        0x0FU,
                                        0x10U};

        auto seeded = random.Seed({seed.data(), seed.size()});
        ASSERT_TRUE(seeded.has_value()) << "Seed failed";

        std::vector<uint8_t> after_seed(32U, 0U);
        auto generated = random.Generate({after_seed.data(), after_seed.size()});
        ASSERT_TRUE(generated.has_value()) << "Generate after Seed failed";
        EXPECT_EQ(generated.value(), after_seed.size());
    }

    // =========================================================================
    // 5. A zero-length request is a no-op, not an error
    // =========================================================================
    {
        std::vector<uint8_t> empty;
        auto generated = random.Generate({empty.data(), empty.size()});
        ASSERT_TRUE(generated.has_value()) << "Generate of zero bytes should succeed";
        EXPECT_EQ(generated.value(), 0U);
    }
}

// Random generation is provided only by the OpenSSL (software) provider, so
// every case pins ProviderType::kSoftware. Leaving the provider unset — or
// asking for kDefault — resolves to the daemon's DEFAULT provider, currently
// SoftHSM, which offers no random handler.
INSTANTIATE_TEST_SUITE_P(
    SelectionOfProviderType,
    RandomGenerationTest,
    ::testing::Values(RandomTestData{"Random_SoftwareProvider", ProviderType::kSoftware, ""},
                      RandomTestData{"Random_CtrDrbg_SoftwareProvider", ProviderType::kSoftware, "CTR-DRBG"}),
    [](const testing::TestParamInfo<RandomGenerationTest::ParamType>& info) {
        return info.param.test_case_name;
    });

// =========================================================================
// Two contexts draw independently
// =========================================================================

TEST(RandomIndependenceTest, TwoContextsProduceDifferentData)
{
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value());
    auto& stack = stack_result.value();

    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value());
    auto& ctx = ctx_result.value();

    RandomContextConfig config;
    config.SetProviderType(ProviderType::kSoftware);  // only provider offering an RNG
    auto first = ctx->CreateRandomContext(config);
    ASSERT_TRUE(first.has_value());
    auto second = ctx->CreateRandomContext(config);
    ASSERT_TRUE(second.has_value());

    std::vector<uint8_t> a(32U, 0U);
    std::vector<uint8_t> b(32U, 0U);
    ASSERT_TRUE(first.value()->Generate({a.data(), a.size()}).has_value());
    ASSERT_TRUE(second.value()->Generate({b.data(), b.size()}).has_value());

    EXPECT_NE(a, b) << "Two random contexts must not return identical data";
}

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
