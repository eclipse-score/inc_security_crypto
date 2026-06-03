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

/// @file score_api_mac_example.cpp
/// @brief Demonstrates HMAC-SHA-256 MAC operations using the score::mw::crypto API.
///
/// Shows:
///   - Key generation via IKeyManagementContext::GenerateKey (ephemeral guard path)
///   - Key loading from a named key slot via ResolveResource + LoadKey
///   - Streaming MAC computation (Init → Update* → Finalize)
///   - MAC verification via Verify()
///   - Context reuse via Reset()
///   - Automatic key release via CryptoResourceGuard RAII

#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/config/key_management_context_config.hpp"
#include "score/mw/crypto/api/config/key_operation_params.hpp"
#include "score/mw/crypto/api/config/mac_context_config.hpp"
#include "score/mw/crypto/api/contexts/i_key_management_context.hpp"
#include "score/mw/crypto/api/contexts/i_mac_context.hpp"
#include "score/mw/crypto/api/crypto_stack_factory.hpp"
#include "score/mw/crypto/api/i_crypto_context.hpp"
#include "score/mw/crypto/api/i_crypto_stack.hpp"
#include "tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace score::mw::crypto;
using tests::utility::print_hex;

namespace
{

// =========================================================================
// Parameterized Test Data
// =========================================================================

/// @brief Test parameters for MAC tests using a generated (ephemeral) key.
///
/// Since the key is randomly generated, MAC outputs cannot be compared against
/// fixed test vectors. Instead, self-consistency is verified: compute → Verify,
/// tamper detection, and deterministic re-computation via Reset.
struct MacTestData
{
    std::string test_case_name;
    std::optional<ProviderType> provider_type;
    std::string mac_algorithm;
    std::string key_algorithm;
    size_t expected_mac_size;
    std::string in_data_path;
    std::string in_data_path_alternative;
};

/// @brief Test parameters for MAC tests using a key loaded from a named slot.
///
/// With a deterministic key from a slot, MAC outputs can be compared against
/// known test vectors in addition to self-consistency checks.
struct KeySlotMacTestData
{
    std::string test_case_name;
    std::optional<ProviderType> provider_type;
    std::string mac_algorithm;
    std::string key_algorithm;
    size_t expected_mac_size;
    std::string in_data_path;
    std::string in_data_path_alternative;
    std::string expected_mac_data_path;
    std::string expected_mac_data_path_alternative;
    std::string key_slot_name;
};

// =========================================================================
// Helper functions for test steps
// =========================================================================

/// Streaming MAC: splits input into two chunks, Init → Update → Update → Finalize.
/// The computed MAC is written to @p output.
void ComputeStreamingMac(IMacContext& mac,
                         const std::vector<uint8_t>& input,
                         size_t mac_size,
                         std::vector<uint8_t>& output)
{
    output.assign(mac_size, 0);

    const auto first_chunk_size = static_cast<std::ptrdiff_t>(input.size()) / 2;
    std::vector<uint8_t> chunk1(input.begin(), input.begin() + first_chunk_size);
    std::vector<uint8_t> chunk2(input.begin() + first_chunk_size, input.end());

    auto init_result = mac.Init();
    ASSERT_TRUE(init_result.has_value()) << "Init failed";

    auto update1_result = mac.Update({chunk1.data(), chunk1.size()});
    ASSERT_TRUE(update1_result.has_value()) << "Update (chunk 1) failed";

    auto update2_result = mac.Update({chunk2.data(), chunk2.size()});
    ASSERT_TRUE(update2_result.has_value()) << "Update (chunk 2) failed";

    auto finalize_result = mac.Finalize({output.data(), output.size()});
    ASSERT_TRUE(finalize_result.has_value()) << "Finalize failed";

    print_hex("Streaming-MAC", output, finalize_result.value());
}

/// Reset → Init → Update (full buffer) → Verify against @p expected_mac.
/// Asserts that the verification succeeds.
void ResetAndVerifyMac(IMacContext& mac, const std::vector<uint8_t>& input, const std::vector<uint8_t>& expected_mac)
{
    auto reset = mac.Reset();
    ASSERT_TRUE(reset.has_value()) << "Reset before Verify failed";

    auto init = mac.Init();
    ASSERT_TRUE(init.has_value()) << "Init for Verify failed";

    auto update = mac.Update(input);
    ASSERT_TRUE(update.has_value()) << "Update for Verify failed";

    auto verify = mac.Verify({expected_mac.data(), expected_mac.size()});
    ASSERT_TRUE(verify.has_value()) << "Verify call failed";
    EXPECT_TRUE(verify.value()) << "MAC verification should succeed for correct MAC";
}

/// Reset → Init → Update → Verify with a tampered MAC (first byte flipped).
/// Asserts that verification fails.
void ResetAndVerifyTamperedMac(IMacContext& mac,
                               const std::vector<uint8_t>& input,
                               const std::vector<uint8_t>& original_mac)
{
    auto reset = mac.Reset();
    ASSERT_TRUE(reset.has_value()) << "Reset before tampered verify failed";

    auto init = mac.Init();
    ASSERT_TRUE(init.has_value()) << "Init for tampered verify failed";

    auto update = mac.Update(input);
    ASSERT_TRUE(update.has_value()) << "Update for tampered verify failed";

    std::vector<uint8_t> tampered_mac = original_mac;
    tampered_mac[0] ^= 0xFF;  // Flip bits in first byte

    auto verify = mac.Verify({tampered_mac.data(), tampered_mac.size()});
    ASSERT_TRUE(verify.has_value()) << "Verify call with tampered MAC failed unexpectedly";
    EXPECT_FALSE(verify.value()) << "MAC verification should fail for tampered MAC";
}

/// Reset → Init → Update (full buffer) → Finalize.
/// The computed MAC is written to @p output.
void ResetAndComputeMac(IMacContext& mac,
                        const std::vector<uint8_t>& input,
                        size_t mac_size,
                        std::vector<uint8_t>& output)
{
    output.assign(mac_size, 0);

    auto reset = mac.Reset();
    ASSERT_TRUE(reset.has_value()) << "Reset failed";

    auto init = mac.Init();
    ASSERT_TRUE(init.has_value()) << "Init after Reset failed";

    auto update = mac.Update(input);
    ASSERT_TRUE(update.has_value()) << "Update after Reset failed";

    auto finalize = mac.Finalize({output.data(), output.size()});
    ASSERT_TRUE(finalize.has_value()) << "Finalize after Reset failed";

    print_hex("Reused-ctx-MAC", output, finalize.value());
}

/// Init → Update (partial) → Reset (discard) → Init → Update (full) → Finalize.
/// Verifies that Reset mid-stream correctly discards partial work.
void ResetMidStreamAndComputeMac(IMacContext& mac,
                                 const std::vector<uint8_t>& partial_input,
                                 const std::vector<uint8_t>& full_input,
                                 size_t mac_size,
                                 std::vector<uint8_t>& output)
{
    output.assign(mac_size, 0);

    ASSERT_TRUE(mac.Reset());  // Reset before to ensure clean state

    ASSERT_TRUE(mac.Init());
    ASSERT_TRUE(mac.Update({partial_input.data(), partial_input.size()}));
    ASSERT_TRUE(mac.Reset());  // discard partial work

    ASSERT_TRUE(mac.Init());
    ASSERT_TRUE(mac.Update({full_input.data(), full_input.size()}));
    auto finalize = mac.Finalize({output.data(), output.size()});
    ASSERT_TRUE(finalize.has_value()) << "Finalize after mid-stream Reset failed";
}

/// Query and assert GetMacSize() and GetOutputSize().
void AssertMacSizes(IMacContext& mac, size_t expected_mac_size)
{
    auto mac_size = mac.GetMacSize();
    EXPECT_EQ(mac_size, expected_mac_size) << "Unexpected MAC size of: " << mac_size;
}

/// Explicit key release and assertion.
void ReleaseAndAssertKey(CryptoResourceGuard& key)
{
    auto release_result = key.Release();
    ASSERT_TRUE(release_result.has_value()) << "Key release failed";
    EXPECT_FALSE(key.IsActive()) << "Key should be inactive after Release";
}

// =========================================================================
// Test 1: MAC with Generated Key (self-consistency, no fixed vectors)
// =========================================================================

class GeneratedKeyMacTest : public ::testing::TestWithParam<MacTestData>
{
};

TEST_P(GeneratedKeyMacTest, MacGenerationAndVerificationTest)
{
    auto test_data = GetParam();

    auto provider_type = test_data.provider_type;
    auto mac_algorithm = test_data.mac_algorithm;
    auto key_algorithm = test_data.key_algorithm;
    auto expected_mac_size = test_data.expected_mac_size;

    auto input_buffer = tests::utility::read_bin(test_data.in_data_path);
    ASSERT_FALSE(input_buffer.empty());
    auto input_buffer_alternative = tests::utility::read_bin(test_data.in_data_path_alternative);
    ASSERT_FALSE(input_buffer_alternative.empty());

    // =========================================================================
    // 1. Create the crypto stack and connect to the daemon
    // =========================================================================
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    auto& stack = stack_result.value();

    // =========================================================================
    // 2. Create a crypto context (factory for operation contexts)
    // =========================================================================
    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    auto& ctx = ctx_result.value();

    // =========================================================================
    // 3. Create a key management context and generate an ephemeral key
    // =========================================================================
    //
    // The key management context handles key lifecycle operations.
    // GenerateKey returns a CryptoResourceGuard — an RAII wrapper that
    // automatically releases the ephemeral key to the daemon when the
    // guard goes out of scope. No manual cleanup needed.
    KeyManagementContextConfig key_mgmt_config;
    if (provider_type.has_value())
    {
        key_mgmt_config.SetProviderType(provider_type.value());
    }

    auto key_mgmt_result = ctx->CreateKeyManagementContext(key_mgmt_config);
    ASSERT_TRUE(key_mgmt_result.has_value()) << "Failed to create key management context";
    auto& key_mgmt = key_mgmt_result.value();

    // Generate an ephemeral symmetric key for MAC operations.
    // The CryptoResourceGuard owns the key lifetime — it will be auto-released
    // when key goes out of scope.
    GenerateKeyParams key_gen_params;
    key_gen_params.SetAlgorithm(key_algorithm).SetPermissions(KeyOperationPermission::kMac);

    auto key_result = key_mgmt->GenerateKey(key_gen_params);
    ASSERT_TRUE(key_result.has_value()) << "Failed to generate MAC key";
    auto key = std::move(key_result.value());
    ASSERT_TRUE(key.IsActive()) << "Key guard should be active after generation";

    // =========================================================================
    // 4. Configure and create a MAC context
    // =========================================================================
    //
    // MacContextConfig requires both an algorithm and a key.
    // The key implicitly converts to const CryptoResourceId& via its
    // operator, so it can be passed directly to SetKey().
    MacContextConfig mac_config;
    mac_config.SetAlgorithm(mac_algorithm).SetKey(key);  // implicit conversion from CryptoResourceGuard

    if (provider_type.has_value())
    {
        mac_config.SetProviderType(provider_type.value());
    }

    auto mac_result = ctx->CreateMacContext(mac_config);
    ASSERT_TRUE(mac_result.has_value()) << "Failed to create MAC context";
    auto& mac = mac_result.value();

    // =========================================================================
    // 5. Streaming MAC: Init → Update → Update → Finalize
    // =========================================================================
    //
    // Since the key is randomly generated, we cannot compare the MAC output
    // against a fixed test vector. Instead, we verify self-consistency:
    // the computed MAC must pass Verify(), and re-computation after Reset
    // must yield the same result (deterministic for same key + input).
    std::vector<uint8_t> computed_mac;
    ASSERT_NO_FATAL_FAILURE(ComputeStreamingMac(*mac, input_buffer, expected_mac_size, computed_mac));
    ASSERT_EQ(computed_mac.size(), expected_mac_size);

    // =========================================================================
    // 6. MAC verification via Verify()
    // =========================================================================
    //
    // Verify() is an alternative to Finalize(): instead of producing a MAC,
    // it checks whether the accumulated data matches the provided MAC value.
    ASSERT_NO_FATAL_FAILURE(ResetAndVerifyMac(*mac, input_buffer, computed_mac));

    // =========================================================================
    // 7. Verify with tampered MAC should fail
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(ResetAndVerifyTamperedMac(*mac, input_buffer, computed_mac));

    // =========================================================================
    // 8. Context reuse via Reset() — same input yields same MAC
    // =========================================================================
    //
    // Reset() clears the streaming state machine and intermediate data, but
    // preserves the key binding and algorithm configuration. This avoids the
    // factory + IPC round-trip cost of creating a new context.
    std::vector<uint8_t> recomputed_mac;
    ASSERT_NO_FATAL_FAILURE(ResetAndComputeMac(*mac, input_buffer, expected_mac_size, recomputed_mac));
    EXPECT_EQ(recomputed_mac, computed_mac) << "Re-computed MAC should match original (deterministic)";

    // =========================================================================
    // 9. Context reuse via Reset() — different input yields different MAC
    // =========================================================================
    std::vector<uint8_t> computed_mac_alt;
    ASSERT_NO_FATAL_FAILURE(ResetAndComputeMac(*mac, input_buffer_alternative, expected_mac_size, computed_mac_alt));
    EXPECT_NE(computed_mac_alt, computed_mac) << "MAC for different input should differ";

    // Verify the alternative MAC is also self-consistent
    ASSERT_NO_FATAL_FAILURE(ResetAndVerifyMac(*mac, input_buffer_alternative, computed_mac_alt));

    // =========================================================================
    // 10. Reset mid-stream discards partial work
    // =========================================================================
    const auto first_chunk_size = static_cast<std::ptrdiff_t>(input_buffer.size()) / 2;
    std::vector<uint8_t> chunk1(input_buffer.begin(), input_buffer.begin() + first_chunk_size);
    std::vector<uint8_t> mac_after_abort;
    ASSERT_NO_FATAL_FAILURE(
        ResetMidStreamAndComputeMac(*mac, chunk1, input_buffer_alternative, expected_mac_size, mac_after_abort));
    EXPECT_EQ(mac_after_abort, computed_mac_alt) << "MAC after mid-stream Reset does not match";

    // =========================================================================
    // 11. Query MAC size
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(AssertMacSizes(*mac, expected_mac_size));

    // =========================================================================
    // 12. Explicit release of Key
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(ReleaseAndAssertKey(key));
}

// =========================================================================
// Test 2: MAC with Key Loaded from Slot (fixed vector verification)
// =========================================================================

class KeySlotMacTest : public ::testing::TestWithParam<KeySlotMacTestData>
{
};

TEST_P(KeySlotMacTest, MacWithKeySlotTest)
{
    auto test_data = GetParam();

    auto provider_type = test_data.provider_type;
    auto mac_algorithm = test_data.mac_algorithm;
    auto expected_mac_size = test_data.expected_mac_size;

    auto input_buffer = tests::utility::read_bin(test_data.in_data_path);
    ASSERT_FALSE(input_buffer.empty());
    const auto expected_mac = tests::utility::read_bin(test_data.expected_mac_data_path);
    ASSERT_EQ(expected_mac.size(), expected_mac_size);

    auto input_buffer_alternative = tests::utility::read_bin(test_data.in_data_path_alternative);
    ASSERT_FALSE(input_buffer_alternative.empty());
    const auto expected_mac_alternative = tests::utility::read_bin(test_data.expected_mac_data_path_alternative);
    ASSERT_EQ(expected_mac_alternative.size(), expected_mac_size);

    // =========================================================================
    // 1. Create the crypto stack and connect to the daemon
    // =========================================================================
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    auto& stack = stack_result.value();

    // =========================================================================
    // 2. Create a crypto context (factory for operation contexts)
    // =========================================================================
    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    auto& ctx = ctx_result.value();

    // =========================================================================
    // 3. Create a key management context and load key from a named slot
    // =========================================================================
    //
    // Instead of generating an ephemeral key, we resolve a pre-provisioned
    // key slot by name and load the key material from it. This allows
    // verification against known test vectors produced with the same key.
    KeyManagementContextConfig key_mgmt_config;
    if (provider_type.has_value())
    {
        key_mgmt_config.SetProviderType(provider_type.value());
    }

    auto key_mgmt_result = ctx->CreateKeyManagementContext(key_mgmt_config);
    ASSERT_TRUE(key_mgmt_result.has_value()) << "Failed to create key management context";
    auto& key_mgmt = key_mgmt_result.value();

    // Resolve the named key slot to a CryptoResourceId,
    // then load the key material into a CryptoResourceGuard.
    auto slot_result = ctx->ResolveResource(test_data.key_slot_name, ResourceType::kKeySlot);
    ASSERT_TRUE(slot_result.has_value()) << "Failed to resolve key slot: " << test_data.key_slot_name;

    auto key_result = key_mgmt->LoadKey(slot_result.value());
    ASSERT_TRUE(key_result.has_value()) << "Failed to load key from slot: " << test_data.key_slot_name;
    auto key = std::move(key_result.value());
    ASSERT_TRUE(key.IsActive()) << "Key guard should be active after loading from slot";

    // =========================================================================
    // 4. Configure and create a MAC context
    // =========================================================================
    MacContextConfig mac_config;
    mac_config.SetAlgorithm(mac_algorithm).SetKey(key);  // implicit conversion from CryptoResourceGuard

    if (provider_type.has_value())
    {
        mac_config.SetProviderType(provider_type.value());
    }

    auto mac_result = ctx->CreateMacContext(mac_config);
    ASSERT_TRUE(mac_result.has_value()) << "Failed to create MAC context";
    auto& mac = mac_result.value();

    // =========================================================================
    // 5. Streaming MAC: Init → Update → Update → Finalize
    // =========================================================================
    //
    // With a deterministic key from a slot, the MAC output is reproducible
    // and can be verified against precomputed test vectors.
    std::vector<uint8_t> computed_mac;
    ASSERT_NO_FATAL_FAILURE(ComputeStreamingMac(*mac, input_buffer, expected_mac_size, computed_mac));
    ASSERT_EQ(computed_mac.size(), expected_mac.size());
    EXPECT_EQ(computed_mac, expected_mac) << "MAC output does not match expected value";

    // =========================================================================
    // 6. MAC verification via Verify()
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(ResetAndVerifyMac(*mac, input_buffer, expected_mac));

    // =========================================================================
    // 7. Verify with tampered MAC should fail
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(ResetAndVerifyTamperedMac(*mac, input_buffer, expected_mac));

    // =========================================================================
    // 8. Context reuse via Reset() — different data, verified against vectors
    // =========================================================================
    std::vector<uint8_t> computed_mac_alt;
    ASSERT_NO_FATAL_FAILURE(ResetAndComputeMac(*mac, input_buffer_alternative, expected_mac_size, computed_mac_alt));
    ASSERT_EQ(computed_mac_alt.size(), expected_mac_alternative.size());
    EXPECT_EQ(computed_mac_alt, expected_mac_alternative) << "MAC output does not match expected value after Reset";

    // =========================================================================
    // 9. Reset mid-stream discards partial work
    // =========================================================================
    const auto first_chunk_size = static_cast<std::ptrdiff_t>(input_buffer.size()) / 2;
    std::vector<uint8_t> chunk1(input_buffer.begin(), input_buffer.begin() + first_chunk_size);
    std::vector<uint8_t> mac_after_abort;
    ASSERT_NO_FATAL_FAILURE(
        ResetMidStreamAndComputeMac(*mac, chunk1, input_buffer_alternative, expected_mac_size, mac_after_abort));
    ASSERT_EQ(mac_after_abort.size(), expected_mac_alternative.size());
    EXPECT_EQ(mac_after_abort, expected_mac_alternative) << "MAC after mid-stream Reset does not match";

    // =========================================================================
    // 10. Query MAC size
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(AssertMacSizes(*mac, expected_mac_size));

    // =========================================================================
    // 11. Explicit release of Key
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(ReleaseAndAssertKey(key));
}

// =========================================================================
// Test Vector Constants
// =========================================================================

const std::string kAlgHmacSha256 = "HMAC-SHA256";
const std::string kKeyAlgHmacSha256 = "HMAC-SHA256";
const std::size_t kHmacSha256MacSize = 32;

const std::string kMacInDataPath = "/opt/crypto/tests/test_vectors/mac/input_hello_world.bin";
const std::string kMacInDataPathAlternative = "/opt/crypto/tests/test_vectors/mac/input_complete_data.bin";

const std::string kMacHmacSha256OutDataPath = "/opt/crypto/tests/test_vectors/mac/hmac_sha256_hello_world.bin";
const std::string kMacHmacSha256OutDataPathAlternative =
    "/opt/crypto/tests/test_vectors/mac/hmac_sha256_complete_data.bin";

const std::string kHmacSha256KeySlotNameOpenSSL = "HMAC_SHA256_IntegrationTestKey_OpenSSL";
const std::string kHmacSha256KeySlotNameSoftHSM = "HMAC_SHA256_IntegrationTestKey_SoftHSM";

// =========================================================================
// Test Suite: Generated Key MAC (self-consistency, no fixed vectors)
// =========================================================================

INSTANTIATE_TEST_SUITE_P(SelectionOfProviderType,
                         GeneratedKeyMacTest,
                         ::testing::Values(MacTestData{"HMAC_SHA256_NoProviderSelection",
                                                       std::nullopt,
                                                       kAlgHmacSha256,
                                                       kKeyAlgHmacSha256,
                                                       kHmacSha256MacSize,
                                                       kMacInDataPath,
                                                       kMacInDataPathAlternative},
                                           MacTestData{"HMAC_SHA256_DefaultProviderType",
                                                       ProviderType::kDefault,
                                                       kAlgHmacSha256,
                                                       kKeyAlgHmacSha256,
                                                       kHmacSha256MacSize,
                                                       kMacInDataPath,
                                                       kMacInDataPathAlternative},
                                           MacTestData{"HMAC_SHA256_SoftwareProvider",
                                                       ProviderType::kSoftware,
                                                       kAlgHmacSha256,
                                                       kKeyAlgHmacSha256,
                                                       kHmacSha256MacSize,
                                                       kMacInDataPath,
                                                       kMacInDataPathAlternative},
                                           MacTestData{"HMAC_SHA256_HardwareProvider",
                                                       ProviderType::kHardware,
                                                       kAlgHmacSha256,
                                                       kKeyAlgHmacSha256,
                                                       kHmacSha256MacSize,
                                                       kMacInDataPath,
                                                       kMacInDataPathAlternative}),
                         [](const testing::TestParamInfo<GeneratedKeyMacTest::ParamType>& info) {
                             return info.param.test_case_name;
                         });

// =========================================================================
// Test Suite: Key Slot MAC (fixed vector verification)
// =========================================================================

// =========================================================================
// Test Suite: Key Slot MAC (fixed vector verification)
// =========================================================================

INSTANTIATE_TEST_SUITE_P(KeySlotProviderType,
                         KeySlotMacTest,
                         ::testing::Values(KeySlotMacTestData{"HMAC_SHA256_KeySlot_NoProviderSelection",
                                                              std::nullopt,
                                                              kAlgHmacSha256,
                                                              kKeyAlgHmacSha256,
                                                              kHmacSha256MacSize,
                                                              kMacInDataPath,
                                                              kMacInDataPathAlternative,
                                                              kMacHmacSha256OutDataPath,
                                                              kMacHmacSha256OutDataPathAlternative,
                                                              kHmacSha256KeySlotNameSoftHSM},
                                           KeySlotMacTestData{"HMAC_SHA256_KeySlot_DefaultProviderType",
                                                              ProviderType::kDefault,
                                                              kAlgHmacSha256,
                                                              kKeyAlgHmacSha256,
                                                              kHmacSha256MacSize,
                                                              kMacInDataPath,
                                                              kMacInDataPathAlternative,
                                                              kMacHmacSha256OutDataPath,
                                                              kMacHmacSha256OutDataPathAlternative,
                                                              kHmacSha256KeySlotNameSoftHSM},
                                           KeySlotMacTestData{"HMAC_SHA256_KeySlot_SoftwareProvider",
                                                              ProviderType::kSoftware,
                                                              kAlgHmacSha256,
                                                              kKeyAlgHmacSha256,
                                                              kHmacSha256MacSize,
                                                              kMacInDataPath,
                                                              kMacInDataPathAlternative,
                                                              kMacHmacSha256OutDataPath,
                                                              kMacHmacSha256OutDataPathAlternative,
                                                              kHmacSha256KeySlotNameOpenSSL},
                                           KeySlotMacTestData{"HMAC_SHA256_KeySlot_HardwareProvider",
                                                              ProviderType::kHardware,
                                                              kAlgHmacSha256,
                                                              kKeyAlgHmacSha256,
                                                              kHmacSha256MacSize,
                                                              kMacInDataPath,
                                                              kMacInDataPathAlternative,
                                                              kMacHmacSha256OutDataPath,
                                                              kMacHmacSha256OutDataPathAlternative,
                                                              kHmacSha256KeySlotNameSoftHSM}),
                         [](const testing::TestParamInfo<KeySlotMacTest::ParamType>& info) {
                             return info.param.test_case_name;
                         });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
