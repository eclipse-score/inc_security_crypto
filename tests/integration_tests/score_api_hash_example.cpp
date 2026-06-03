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
/// @brief Demonstrates SHA-256 hashing using the score::mw::crypto API.
///
/// Shows both streaming (Init → Update* → Finalize) and single-shot modes.

#include "score/mw/crypto/api/config/hash_context_config.hpp"
#include "score/mw/crypto/api/contexts/i_hash_context.hpp"
#include "score/mw/crypto/api/crypto_stack_factory.hpp"
#include "score/mw/crypto/api/i_crypto_context.hpp"
#include "score/mw/crypto/api/i_crypto_stack.hpp"
#include "tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace score::mw::crypto;
using tests::utility::print_hex;

namespace
{

// Parameterized Test Data
struct HashTestData
{
    std::string test_case_name;
    std::optional<ProviderType> provider_type;
    std::string algorithm;
    size_t expected_out_data_size;
    std::string in_data_path;
    std::string expected_out_data_path;
    std::string in_data_path_alternative;
    std::string expected_out_data_path_alternative;
};

class ParameterizedHashTest : public ::testing::TestWithParam<HashTestData>
{
};

TEST_P(ParameterizedHashTest, HashingTest)
{
    // Prepare test data
    auto test_data = GetParam();

    auto provider_type = test_data.provider_type;
    auto algorithm = test_data.algorithm;
    auto expected_out_data_size = test_data.expected_out_data_size;

    auto input_buffer = tests::utility::read_bin(test_data.in_data_path);
    ASSERT_FALSE(input_buffer.empty());
    const auto expected_hash = tests::utility::read_bin(test_data.expected_out_data_path);
    ASSERT_EQ(expected_hash.size(), expected_out_data_size);

    auto input_buffer_alternative = tests::utility::read_bin(test_data.in_data_path_alternative);
    ASSERT_FALSE(input_buffer_alternative.empty());
    const auto expected_hash_alternative = tests::utility::read_bin(test_data.expected_out_data_path_alternative);
    ASSERT_EQ(expected_hash_alternative.size(), expected_out_data_size);

    // 1. Create the crypto stack and connect to the daemon
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    auto& stack = stack_result.value();

    // 2. Create a crypto context
    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    auto& ctx = ctx_result.value();

    // 3. Configure and create a hash context
    HashContextConfig hash_config;
    hash_config.SetAlgorithm(algorithm);

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

const std::string kAlgSha256 = "SHA256";
const std::size_t kSha256DigestSize = 32;
const std::string kInDataPath = "/opt/crypto/tests/test_vectors/hash/input_hello_world.bin";
const std::string kSha256OutDataPath = "/opt/crypto/tests/test_vectors/hash/sha256_hello_world.bin";
const std::string kInDataPathAlternative = "/opt/crypto/tests/test_vectors/hash/input_complete_data.bin";
const std::string kSha256OutDataPathAlternative = "/opt/crypto/tests/test_vectors/hash/sha256_complete_data.bin";

// TODO: Daemon expects SHA256 here we planned to use SHA-256
// Either we find the common standard or allow variations, which we would need to re-map

INSTANTIATE_TEST_SUITE_P(SelectionOfProviderType,
                         ParameterizedHashTest,
                         ::testing::Values(HashTestData{"SHA256_NoProviderSelection",
                                                        std::nullopt,
                                                        kAlgSha256,
                                                        kSha256DigestSize,
                                                        kInDataPath,
                                                        kSha256OutDataPath,
                                                        kInDataPathAlternative,
                                                        kSha256OutDataPathAlternative},
                                           HashTestData{"SHA256_DefaultProviderType",
                                                        ProviderType::kDefault,
                                                        kAlgSha256,
                                                        kSha256DigestSize,
                                                        kInDataPath,
                                                        kSha256OutDataPath,
                                                        kInDataPathAlternative,
                                                        kSha256OutDataPathAlternative},
                                           HashTestData{"SHA256_SoftwareProvider",
                                                        ProviderType::kSoftware,
                                                        kAlgSha256,
                                                        kSha256DigestSize,
                                                        kInDataPath,
                                                        kSha256OutDataPath,
                                                        kInDataPathAlternative,
                                                        kSha256OutDataPathAlternative},
                                           HashTestData{"SHA256_HardwareProvider",
                                                        ProviderType::kHardware,
                                                        kAlgSha256,
                                                        kSha256DigestSize,
                                                        kInDataPath,
                                                        kSha256OutDataPath,
                                                        kInDataPathAlternative,
                                                        kSha256OutDataPathAlternative}),
                         [](const testing::TestParamInfo<ParameterizedHashTest::ParamType>& info) {
                             return info.param.test_case_name;
                         });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
