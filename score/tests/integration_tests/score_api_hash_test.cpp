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

/// @file hashing_example.cpp
/// @brief Demonstrates SHA-256 hashing using the score::crypto API.
///
/// Shows both streaming (Init → Update* → Finalize) and single-shot modes.

#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace score::crypto;
using tests::utility::print_hex;

namespace
{

#ifdef __QNXNTO__
constexpr auto kControlSocketEndpoint = "unix:///opt/crypto_daemon.sock";
#else
constexpr auto kControlSocketEndpoint = "unix:///tmp/crypto_daemon.sock";
#endif

constexpr std::chrono::milliseconds kDefaultOperationTimeout{500};
constexpr std::size_t kInBandThreshold = 32U;

// Parameterized Test Data
struct HashTestData
{
    std::string_view test_case_name;
    std::optional<ProviderType> provider_type;
    std::string_view algorithm;
    size_t expected_out_data_size;
    std::string_view in_data_relative_path;
    std::string_view expected_out_data_relative_path;
    std::string_view in_data_alternative_relative_path;
    std::string_view expected_out_data_alternative_relative_path;
};

class ParameterizedHashTest : public ::testing::TestWithParam<HashTestData>
{
};

class HashExampleTest : public ::testing::Test
{
};

std::string GetTestVectorPath(const std::string_view relative_path)
{
    const char* dir = std::getenv("TEST_VECTORS_DIR");
    return std::string{dir != nullptr ? dir : "/opt/crypto/share/test_vectors"} + std::string{relative_path};
}

TEST_P(ParameterizedHashTest, HashingTest)
{
    // Prepare test data
    auto test_data = GetParam();

    auto provider_type = test_data.provider_type;
    auto algorithm = test_data.algorithm;
    auto expected_out_data_size = test_data.expected_out_data_size;

    auto input_buffer = tests::utility::read_bin(GetTestVectorPath(test_data.in_data_relative_path));
    ASSERT_FALSE(input_buffer.empty());
    const auto expected_hash = tests::utility::read_bin(GetTestVectorPath(test_data.expected_out_data_relative_path));
    ASSERT_EQ(expected_hash.size(), expected_out_data_size);

    auto input_buffer_alternative =
        tests::utility::read_bin(GetTestVectorPath(test_data.in_data_alternative_relative_path));
    ASSERT_FALSE(input_buffer_alternative.empty());
    const auto expected_hash_alternative =
        tests::utility::read_bin(GetTestVectorPath(test_data.expected_out_data_alternative_relative_path));
    ASSERT_EQ(expected_hash_alternative.size(), expected_out_data_size);

    // 1. Create the crypto stack and connect to the daemon
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    auto& stack = stack_result.value();

    // 2. Create a crypto context
    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    auto& ctx = ctx_result.value();

    // 3. Configure and create a hash context
    HashContextConfig hash_config;
    hash_config.SetAlgorithm(std::string{algorithm});

    // Select provider type
    if (provider_type.has_value())
    {
        hash_config.SetProviderType(provider_type.value());
    }

    auto hash_result = ctx->CreateHashContext(hash_config);
    ASSERT_TRUE(hash_result.has_value()) << "Failed to create hash context";
    auto& hash = hash_result.value();

    // 4. Streaming hash: Init → Update → Update → Finalize
    std::vector<uint8_t> digest(expected_out_data_size, 0);

    const auto first_chunk_size = static_cast<std::ptrdiff_t>(input_buffer.size()) / 2;
    std::vector<uint8_t> chunk1_buffer(input_buffer.begin(), input_buffer.begin() + first_chunk_size);
    std::vector<uint8_t> chunk2_buffer(input_buffer.begin() + first_chunk_size, input_buffer.end());

    auto init_result = hash->Init();
    ASSERT_TRUE(init_result.has_value()) << "Init failed";

    hash->Update({chunk1_buffer.data(), chunk1_buffer.size()});
    hash->Update({chunk2_buffer.data(), chunk2_buffer.size()});

    auto finalize_result = hash->Finalize({digest.data(), digest.size()});
    ASSERT_TRUE(finalize_result.has_value()) << "Finalize failed";

    print_hex("Streaming", digest, finalize_result.value());
    ASSERT_EQ(digest.size(), expected_hash.size());
    EXPECT_EQ(digest, expected_hash) << "Hash output does not match expected SHA256 hash";

    // 5. Single-shot hash (equivalent to Init + Update + Finalize)
    std::vector<uint8_t> digest2(expected_out_data_size, 0);

    auto single_result = hash->SingleShot(input_buffer, digest2);

    ASSERT_TRUE(single_result.has_value()) << "SingleShot failed";

    print_hex("SingleShot", digest2, single_result.value());
    ASSERT_EQ(digest.size(), expected_hash.size());
    EXPECT_EQ(digest, expected_hash) << "Hash output does not match expected SHA256 hash";

    // 6. Context reuse via Reset()
    //    Reset() returns the context to its post-construction state — the key
    //    (none for hash) and algorithm binding are preserved but the streaming
    //    state machine and intermediate data are cleared.  This avoids the
    //    factory + IPC cost of creating a new context, which matters for
    //    high-throughput scenarios (per-frame V2X AEAD, bulk log hashing).
    auto reset_result = hash->Reset();
    ASSERT_TRUE(reset_result.has_value()) << "Reset failed";

    // Hash a different message using the same context
    std::vector<uint8_t> digest3(expected_out_data_size, 0);

    ASSERT_TRUE(hash->Init());
    ASSERT_TRUE(hash->Update(input_buffer_alternative));
    auto finalize3 = hash->Finalize(digest3);
    ASSERT_TRUE(finalize3.has_value()) << "Finalize after Reset failed";

    print_hex("Reused-ctx", digest3, finalize3.value());
    ASSERT_EQ(digest3.size(), expected_hash_alternative.size());
    EXPECT_EQ(digest3, expected_hash_alternative) << "Hash output does not match expected SHA256 hash";

    // Reset() also works mid-stream to abort and restart
    ASSERT_TRUE(hash->Init());
    ASSERT_TRUE(hash->Update({chunk1_buffer.data(), chunk1_buffer.size()}));
    ASSERT_TRUE(hash->Reset());  // discard partial work

    ASSERT_TRUE(hash->Init());
    ASSERT_TRUE(hash->Update(input_buffer_alternative));
    std::vector<uint8_t> digest4(expected_out_data_size, 0);
    auto finalize4 = hash->Finalize({digest4.data(), digest4.size()});
    ASSERT_TRUE(finalize4.has_value()) << "Finalize after Reset failed";

    ASSERT_EQ(digest4.size(), expected_hash_alternative.size());
    ASSERT_EQ(expected_hash_alternative.size(), expected_out_data_size);

    // 7. Query digest size
    auto digest_size = hash->GetDigestSize();
    EXPECT_EQ(digest_size, expected_out_data_size) << "Unexpected Digest size of: " << digest_size;
}

/// @brief Demonstrates three SHM transport routing paths using SHA-256 (in-band)
/// and SHA-512 (pool and bulk), with the 32-byte in-band threshold defined in
/// BufferShmTranscoder::kInBandThreshold.
TEST_F(HashExampleTest, MemoryAllocationStrategyComparison)
{
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint).SetDefaultOperationTimeout(kDefaultOperationTimeout);

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    auto& stack = stack_result.value();

    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    auto& ctx = ctx_result.value();

    constexpr std::size_t kSha256DigestSize = 32;
    constexpr std::size_t kSha512DigestSize = 64;

    // =========================================================================
    // [1/3] IN-BAND — SHA-256. Message size below 32-byte threshold forces in-band transport.
    std::cout << "\n[1/3] IN-BAND Transport Path (SHA-256, 13-byte heap message):\n";

    HashContextConfig inband_config;
    inband_config.SetAlgorithm("SHA256").SetOperationTimeout(kDefaultOperationTimeout);
    auto inband_ctx = ctx->CreateHashContext(inband_config);
    ASSERT_TRUE(inband_ctx.has_value()) << "Failed to create SHA-256 context";
    auto inband_hash = std::move(inband_ctx).value();

    const auto inband_msg = tests::utility::read_bin(GetTestVectorPath("/hash/input_hello_world.bin"));
    ASSERT_LT(inband_msg.size(), kInBandThreshold);

    std::array<uint8_t, kSha256DigestSize> digest_inband{};
    ASSERT_TRUE(inband_hash->Init().has_value()) << "Init failed";
    ASSERT_TRUE(inband_hash->Update({inband_msg.data(), inband_msg.size()}).has_value()) << "Update failed";
    auto fin_inband = inband_hash->Finalize({digest_inband.data(), digest_inband.size()});
    ASSERT_TRUE(fin_inband.has_value()) << "Finalize failed";

    print_hex("In-band SHA-256", std::vector<uint8_t>(digest_inband.begin(), digest_inband.end()), fin_inband.value());
    std::cout << "      [OK] In-band transport verified\n";

    // =========================================================================
    // [2/3] POOL — SHA-512, 100-byte heap message
    //   Input  100B > 32-byte threshold  =>  copied into pool SHM slot
    //   Output  64B > 32-byte threshold  =>  copied from pool SHM slot
    // =========================================================================
    std::cout << "\n[2/3] POOL Transport Path (SHA-512, 100-byte heap message):\n";

    HashContextConfig pool_config;
    pool_config.SetAlgorithm("SHA512").SetOperationTimeout(kDefaultOperationTimeout);
    auto pool_ctx = ctx->CreateHashContext(pool_config);
    ASSERT_TRUE(pool_ctx.has_value()) << "Failed to create SHA-512 pool context";
    auto pool_hash = std::move(pool_ctx).value();

    const std::vector<uint8_t> pool_msg(100, static_cast<uint8_t>('A'));  // 100 bytes > kInBandThreshold (32 bytes)
    std::array<uint8_t, kSha512DigestSize> digest_pool{};

    ASSERT_TRUE(pool_hash->Init().has_value()) << "Init failed";
    ASSERT_TRUE(pool_hash->Update({pool_msg.data(), pool_msg.size()}).has_value()) << "Update failed";
    auto fin_pool = pool_hash->Finalize({digest_pool.data(), digest_pool.size()});
    ASSERT_TRUE(fin_pool.has_value()) << "Finalize failed";

    print_hex("Pool-path SHA-512", std::vector<uint8_t>(digest_pool.begin(), digest_pool.end()), fin_pool.value());
    std::cout << "      [OK] Pool-path transport verified\n";

    // =========================================================================
    // [3/3] BULK — SHA-512, 100-byte message placed in pre-allocated SHM region
    //   Input  detected as registered SHM subregion  =>  zero-copy BULK
    //   Output  detected as registered SHM subregion =>  zero-copy BULK (reuse)
    // =========================================================================
    std::cout << "\n[3/3] BULK Transport Path (SHA-512, 100-byte SHM input + 64-byte SHM output):\n";
    std::cout << "      Input  in pre-alloc SHM  ->  BULK (zero-copy)\n";
    std::cout << "      Output in pre-alloc SHM  ->  BULK (zero-copy reuse)\n";

    auto allocator_result = stack->GetMemoryAllocator();
    ASSERT_TRUE(allocator_result.has_value()) << "Failed to get memory allocator";
    auto allocator = std::move(allocator_result).value();

    // Quota tracking demonstration
    std::cout << "\nQuota tracking:\n";
    std::cout << "  Initial quota:  " << allocator->GetQuota() << " bytes\n";
    std::cout << "  Initial usage:  " << allocator->GetCurrentUsage() << " bytes\n";

    // Create a larger bulk region (8KB) to hold both input (100B) and output (64B) subregions
    constexpr std::size_t kBulkRegionSize = 8192;
    auto bulk_region_result = allocator->Allocate(kBulkRegionSize);
    ASSERT_TRUE(bulk_region_result.has_value()) << "Failed to create bulk SHM region";
    auto bulk_region = std::move(bulk_region_result).value();

    // Show usage after allocation
    std::cout << "  After alloc:    " << allocator->GetCurrentUsage() << " bytes (+" << kBulkRegionSize << ")\n";

    // Same 100-byte content as pool test so we can verify consistency below
    std::memcpy(bulk_region->AsWritableSpan().data(), pool_msg.data(), pool_msg.size());
    const auto bulk_input = bulk_region->AsSpan().subspan(0, pool_msg.size());

    // Reserve output buffer at offset 4096 (second half of the 8KB region, avoids input overlap)
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)
    uint8_t* output_buffer = bulk_region->AsWritableSpan().data() + 4096;
    auto output_span = score::cpp::span<uint8_t>{output_buffer, kSha512DigestSize};

    HashContextConfig bulk_config;
    bulk_config.SetAlgorithm("SHA512").SetOperationTimeout(kDefaultOperationTimeout);
    auto bulk_ctx = ctx->CreateHashContext(bulk_config);
    ASSERT_TRUE(bulk_ctx.has_value()) << "Failed to create SHA-512 bulk context";
    auto bulk_hash = std::move(bulk_ctx).value();

    std::array<uint8_t, kSha512DigestSize> digest_bulk{};

    ASSERT_TRUE(bulk_hash->Init().has_value()) << "Init failed";
    ASSERT_TRUE(bulk_hash->Update(bulk_input).has_value()) << "Update failed";
    // Output directly into the bulk SHM region (second half)
    auto fin_bulk = bulk_hash->Finalize(output_span);
    ASSERT_TRUE(fin_bulk.has_value()) << "Finalize failed";

    // Copy result back for verification
    std::memcpy(digest_bulk.data(), output_buffer, kSha512DigestSize);

    print_hex("Bulk-path SHA-512", std::vector<uint8_t>(digest_bulk.begin(), digest_bulk.end()), fin_bulk.value());
    std::cout << "      [OK] Bulk-path transport verified\n";

    // Show usage lifecycle before/after region deallocation
    std::cout << "  Before reset:   " << allocator->GetCurrentUsage() << " bytes\n";
    bulk_region.reset();
    std::cout << "  After reset:    " << allocator->GetCurrentUsage() << " bytes\n";

    EXPECT_EQ(digest_pool, digest_bulk) << "Pool and bulk SHA-512 must match for identical input";
}

constexpr std::string_view kAlgSha256 = "SHA256";
constexpr std::size_t kSha256DigestSize = 32;

constexpr std::string_view kInDataRelativePath = "/hash/input_hello_world.bin";
constexpr std::string_view kSha256OutDataRelativePath = "/hash/sha256_hello_world.bin";
constexpr std::string_view kInDataAlternativeRelativePath = "/hash/input_complete_data.bin";
constexpr std::string_view kSha256OutDataAlternativeRelativePath = "/hash/sha256_complete_data.bin";

// TODO: Daemon expects SHA256 here we planned to use SHA-256
// Either we find the common standard or allow variations, which we would need to re-map

INSTANTIATE_TEST_SUITE_P(SelectionOfProviderType,
                         ParameterizedHashTest,
                         ::testing::Values(HashTestData{"SHA256_NoProviderSelection",
                                                        std::nullopt,
                                                        kAlgSha256,
                                                        kSha256DigestSize,
                                                        kInDataRelativePath,
                                                        kSha256OutDataRelativePath,
                                                        kInDataAlternativeRelativePath,
                                                        kSha256OutDataAlternativeRelativePath},
                                           HashTestData{"SHA256_DefaultProviderType",
                                                        ProviderType::kDefault,
                                                        kAlgSha256,
                                                        kSha256DigestSize,
                                                        kInDataRelativePath,
                                                        kSha256OutDataRelativePath,
                                                        kInDataAlternativeRelativePath,
                                                        kSha256OutDataAlternativeRelativePath}
#ifdef SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED
                                           ,
                                           HashTestData{"SHA256_SoftwareProvider",
                                                        ProviderType::kSoftware,
                                                        kAlgSha256,
                                                        kSha256DigestSize,
                                                        kInDataRelativePath,
                                                        kSha256OutDataRelativePath,
                                                        kInDataAlternativeRelativePath,
                                                        kSha256OutDataAlternativeRelativePath}
#endif
#ifdef SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED
                                           ,
                                           HashTestData{"SHA256_HardwareProvider",
                                                        ProviderType::kHardware,
                                                        kAlgSha256,
                                                        kSha256DigestSize,
                                                        kInDataRelativePath,
                                                        kSha256OutDataRelativePath,
                                                        kInDataAlternativeRelativePath,
                                                        kSha256OutDataAlternativeRelativePath}
#endif
                                           ),
                         [](const testing::TestParamInfo<ParameterizedHashTest::ParamType>& info) {
                             return std::string{info.param.test_case_name};
                         });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
