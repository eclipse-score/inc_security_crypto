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

/// @file score_api_hash_test.cpp
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

#include <array>
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
    std::string test_case_name;
    std::optional<ProviderType> provider_type;
    std::string algorithm;
    size_t expected_out_data_size;
    std::string in_data_relative_path;
    std::string expected_out_data_relative_path;
    std::string in_data_alternative_relative_path;
    std::string expected_out_data_alternative_relative_path;
    std::string expected_empty_data_relative_path;
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

    ASSERT_TRUE(hash->Update({chunk1_buffer.data(), chunk1_buffer.size()}).has_value());
    ASSERT_TRUE(hash->Update({chunk2_buffer.data(), chunk2_buffer.size()}).has_value());

    auto finalize_result = hash->Finalize({digest.data(), digest.size()});
    ASSERT_TRUE(finalize_result.has_value()) << "Finalize failed";

    print_hex("Streaming", digest, finalize_result.value());
    ASSERT_EQ(digest.size(), expected_hash.size());
    EXPECT_EQ(digest, expected_hash) << "Streaming hash output does not match the expected digest";

    // 5. Single-shot hash (equivalent to Init + Update + Finalize)
    std::vector<uint8_t> digest2(expected_out_data_size, 0);

    auto single_result = hash->SingleShot(input_buffer, digest2);

    ASSERT_TRUE(single_result.has_value()) << "SingleShot failed";

    print_hex("SingleShot", digest2, single_result.value());
    ASSERT_EQ(digest2.size(), expected_hash.size());
    EXPECT_EQ(digest2, expected_hash) << "Single-shot hash output does not match the expected digest";
    EXPECT_EQ(digest2, digest) << "Streaming and single-shot hash outputs differ";

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
    EXPECT_EQ(digest3, expected_hash_alternative) << "Reused context produced an unexpected digest";

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
    EXPECT_EQ(digest4, expected_hash_alternative) << "Mid-stream reset produced an unexpected digest";

    // 7. Query digest size
    auto digest_size = hash->GetDigestSize();
    EXPECT_EQ(digest_size, expected_out_data_size) << "Unexpected Digest size of: " << digest_size;

    // 8. Reject caller-owned output buffers smaller than the algorithm digest.
    std::vector<uint8_t> undersized_digest(expected_out_data_size - 1U, 0U);
    const auto undersized_single_shot = hash->SingleShot(input_buffer, undersized_digest);
    ASSERT_FALSE(undersized_single_shot.has_value());
    EXPECT_EQ(*undersized_single_shot.error(),
              static_cast<score::result::ErrorCode>(CryptoErrorCode::kInsufficientBufferSize));

    // An undersized Finalize() is retryable without reinitializing or replaying
    // the input. This must behave identically for OpenSSL and PKCS#11.
    ASSERT_TRUE(hash->Init().has_value());
    ASSERT_TRUE(hash->Update(input_buffer).has_value());
    const auto undersized_finalize = hash->Finalize(undersized_digest);
    ASSERT_FALSE(undersized_finalize.has_value());
    EXPECT_EQ(*undersized_finalize.error(),
              static_cast<score::result::ErrorCode>(CryptoErrorCode::kInsufficientBufferSize));

    std::vector<uint8_t> retry_digest(expected_out_data_size, 0U);
    const auto retry_finalize = hash->Finalize(retry_digest);
    ASSERT_TRUE(retry_finalize.has_value()) << "Finalize retry failed after an undersized output buffer";
    EXPECT_EQ(retry_digest, expected_hash);

    // 9. Empty input is valid in both single-shot and zero-update streaming modes.
    const auto empty_input = tests::utility::read_bin(GetTestVectorPath("/hash/input_empty.bin"));
    ASSERT_TRUE(empty_input.empty());
    const auto expected_empty_hash =
        tests::utility::read_bin(GetTestVectorPath(test_data.expected_empty_data_relative_path));
    ASSERT_EQ(expected_empty_hash.size(), expected_out_data_size);

    ASSERT_TRUE(hash->Reset().has_value());
    std::vector<uint8_t> empty_single_shot_digest(expected_out_data_size, 0U);
    const auto empty_single_shot = hash->SingleShot(empty_input, empty_single_shot_digest);
    ASSERT_TRUE(empty_single_shot.has_value()) << "Empty SingleShot failed";
    EXPECT_EQ(empty_single_shot_digest, expected_empty_hash);

    ASSERT_TRUE(hash->Init().has_value());
    std::vector<uint8_t> zero_update_digest(expected_out_data_size, 0U);
    const auto zero_update_finalize = hash->Finalize(zero_update_digest);
    ASSERT_TRUE(zero_update_finalize.has_value()) << "Init followed directly by Finalize failed";
    EXPECT_EQ(zero_update_digest, expected_empty_hash);
}

TEST_F(HashExampleTest, PreservesArbitraryBinaryInputAcrossTheClientDaemonBoundary)
{
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    auto& stack = stack_result.value();

    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    auto& ctx = ctx_result.value();

    HashContextConfig hash_config;
    hash_config.SetAlgorithm("SHA256");
    auto hash_result = ctx->CreateHashContext(hash_config);
    ASSERT_TRUE(hash_result.has_value()) << "Failed to create SHA-256 context";
    auto& hash = hash_result.value();

    const std::array<uint8_t, 7U> input{0x00U, 0x01U, 0x7fU, 0x80U, 0xffU, 0x00U, 0x42U};
    const std::array<uint8_t, 32U> expected{
        0x81U, 0x84U, 0x56U, 0x98U, 0x34U, 0xaeU, 0x09U, 0xc8U, 0x6fU, 0x52U, 0xf8U, 0x46U, 0x62U, 0xbeU, 0x23U, 0x13U,
        0x97U, 0x18U, 0xc4U, 0xacU, 0x9bU, 0x48U, 0x99U, 0x54U, 0xe4U, 0xacU, 0x6fU, 0x7eU, 0x18U, 0x37U, 0x82U, 0xfaU,
    };
    std::array<uint8_t, 32U> output{};

    const auto result = hash->SingleShot(input, output);
    ASSERT_TRUE(result.has_value()) << "Binary SingleShot failed";
    EXPECT_EQ(result.value(), output.size());
    EXPECT_EQ(output, expected);
}

TEST_F(HashExampleTest, ReportsUnsupportedHashAlgorithmAtContextCreation)
{
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value());
    auto ctx_result = stack_result.value()->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value());

    HashContextConfig hash_config;
    hash_config.SetAlgorithm("UNSUPPORTED_ALGORITHM");
    const auto hash_result = ctx_result.value()->CreateHashContext(hash_config);
    ASSERT_FALSE(hash_result.has_value());
    EXPECT_EQ(*hash_result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kUnsupportedAlgorithm));
}

TEST_F(HashExampleTest, RejectsNonProviderResourceForExplicitSelection)
{
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value());
    auto ctx_result = stack_result.value()->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value());

    CryptoResourceId key_resource{};
    key_resource.id = 1U;
    key_resource.type = ResourceType::kKey;
    key_resource.primary_provider = 0U;

    HashContextConfig hash_config;
    hash_config.SetAlgorithm("SHA256").SetProvider(key_resource);
    const auto hash_result = ctx_result.value()->CreateHashContext(hash_config);
    ASSERT_FALSE(hash_result.has_value());
    EXPECT_EQ(*hash_result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidResourceType));
}

TEST_F(HashExampleTest, ResolvesAndUsesExplicitProvider)
{
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value());
    auto ctx_result = stack_result.value()->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value());

    const auto provider_result = ctx_result.value()->ResolveResource("OPENSSL", ResourceType::kProvider);
    ASSERT_TRUE(provider_result.has_value());
    EXPECT_EQ(provider_result.value().type, ResourceType::kProvider);

    HashContextConfig hash_config;
    hash_config.SetAlgorithm("SHA256").SetProvider(provider_result.value());
    const auto hash_result = ctx_result.value()->CreateHashContext(hash_config);
    EXPECT_TRUE(hash_result.has_value());
}

TEST_F(HashExampleTest, ReportsMissingExplicitProvider)
{
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value());
    auto ctx_result = stack_result.value()->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value());

    const auto provider_result =
        ctx_result.value()->ResolveResource("PROVIDER_THAT_DOES_NOT_EXIST", ResourceType::kProvider);
    ASSERT_FALSE(provider_result.has_value());
    EXPECT_EQ(*provider_result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kProviderNotAvailable));
}

TEST_F(HashExampleTest, ReportsStreamStateErrorsAndRecoversWithReset)
{
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value());
    auto ctx_result = stack_result.value()->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value());

    HashContextConfig hash_config;
    hash_config.SetAlgorithm("SHA256");
    auto hash_result = ctx_result.value()->CreateHashContext(hash_config);
    ASSERT_TRUE(hash_result.has_value());
    auto& hash = hash_result.value();

    const std::array<std::uint8_t, 1U> input{0x42U};
    std::array<std::uint8_t, 32U> output{};

    const auto update_before_init = hash->Update(input);
    ASSERT_FALSE(update_before_init.has_value());
    EXPECT_EQ(*update_before_init.error(),
              static_cast<score::result::ErrorCode>(CryptoErrorCode::kStreamNotInitialized));

    const auto finalize_before_init = hash->Finalize(output);
    ASSERT_FALSE(finalize_before_init.has_value());
    EXPECT_EQ(*finalize_before_init.error(),
              static_cast<score::result::ErrorCode>(CryptoErrorCode::kStreamNotInitialized));

    ASSERT_TRUE(hash->Init().has_value());
    ASSERT_TRUE(hash->Update(input).has_value());
    EXPECT_TRUE(hash->Init().has_value()) << "Init on an active stream must discard the previous input";

    const auto single_shot_while_active = hash->SingleShot(input, output);
    ASSERT_FALSE(single_shot_while_active.has_value());
    EXPECT_EQ(*single_shot_while_active.error(),
              static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidOperation));

    const auto restarted_finalize = hash->Finalize(output);
    ASSERT_TRUE(restarted_finalize.has_value());
    const std::vector<std::uint8_t> restarted_digest{output.begin(), output.end()};
    EXPECT_EQ(restarted_digest, tests::utility::read_bin(GetTestVectorPath("/hash/sha256_empty.bin")));

    EXPECT_TRUE(hash->SingleShot(input, output).has_value());
    EXPECT_TRUE(hash->Reset().has_value());
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

HashTestData MakeHashTestData(const std::string& algorithm,
                              const std::string& file_prefix,
                              const std::size_t digest_size,
                              const std::optional<ProviderType> provider_type,
                              const std::string& provider_name)
{
    const std::string vector_root = "/hash/";
    return HashTestData{algorithm + "_" + provider_name,
                        provider_type,
                        algorithm,
                        digest_size,
                        vector_root + "input_hello_world.bin",
                        vector_root + file_prefix + "_hello_world.bin",
                        vector_root + "input_complete_data.bin",
                        vector_root + file_prefix + "_complete_data.bin",
                        vector_root + file_prefix + "_empty.bin"};
}

std::vector<HashTestData> MakeHashTestDataSet()
{
    std::vector<HashTestData> test_data;
    const auto add_algorithm =
        [&test_data](const std::string& algorithm, const std::string& file_prefix, const std::size_t digest_size) {
            test_data.emplace_back(
                MakeHashTestData(algorithm, file_prefix, digest_size, std::nullopt, "NoProviderSelection"));
            test_data.emplace_back(
                MakeHashTestData(algorithm, file_prefix, digest_size, ProviderType::kDefault, "DefaultProviderType"));
            test_data.emplace_back(MakeHashTestData(
                algorithm, file_prefix, digest_size, ProviderType::kHardwarePreferred, "HardwarePreferred"));
            test_data.emplace_back(MakeHashTestData(
                algorithm, file_prefix, digest_size, ProviderType::kSoftwarePreferred, "SoftwarePreferred"));
#ifdef SCORE_CRYPTO_SOFTWARE_BACKEND_ENABLED
            test_data.emplace_back(
                MakeHashTestData(algorithm, file_prefix, digest_size, ProviderType::kSoftware, "SoftwareProvider"));
#endif
#ifdef SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED
            test_data.emplace_back(
                MakeHashTestData(algorithm, file_prefix, digest_size, ProviderType::kHardware, "HardwareProvider"));
#endif
        };

    add_algorithm("SHA256", "sha256", 32U);
    add_algorithm("SHA384", "sha384", 48U);
    add_algorithm("SHA512", "sha512", 64U);
    return test_data;
}

const std::vector<HashTestData> kHashTestData = MakeHashTestDataSet();

INSTANTIATE_TEST_SUITE_P(SelectionOfProviderType,
                         ParameterizedHashTest,
                         ::testing::ValuesIn(kHashTestData),
                         [](const testing::TestParamInfo<ParameterizedHashTest::ParamType>& info) {
                             return info.param.test_case_name;
                         });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
