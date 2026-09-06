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

/// @file score_api_cipher_example.cpp
/// @brief Demonstrates symmetric encryption and decryption using the score::crypto API.
///
/// Shows:
///   - AES key generation via IKeyManagementContext::GenerateKey (ephemeral path)
///   - Key loading from a named key slot via ResolveResource + LoadKey
///   - Streaming encryption (Init → Update* → Finalize) and decryption
///   - Single-shot encryption / decryption via SingleShot()
///   - Context reuse via Reset()
///   - That a wrong key or tampered ciphertext does not yield the plaintext
///   - Agreement with the NIST CAVP AES-CBC vectors under the vectors' own key
///
/// Both key sources are exercised, and each establishes what it can:
///
///   * With a generated key the ciphertext is unpredictable, so correctness is
///     established by round-tripping — decrypt(encrypt(m)) == m — over the NIST
///     plaintexts, plus the usual tamper checks.
///   * With the NIST key loaded from a key slot the expected ciphertext is
///     known, so the test is a real known-answer test against CAVP.
///
/// @note CAVP ciphertexts carry no padding while these contexts always apply
///       PKCS#7, so an encryption produces the vector's ciphertext followed by
///       one extra padding block. See the reference.md beside each vector set.

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/api/config/cipher_context_config.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/config/random_context_config.hpp"
#include "score/crypto/src/api/contexts/i_cipher_context.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_random_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace score::crypto;
using tests::utility::print_hex;
using tests::utility::read_bin;

namespace
{

// =========================================================================
// NIST CAVP AES-CBC vectors
// =========================================================================

const std::string kCipherVectorRoot = "/opt/crypto/tests/test_vectors/block_cipher/";

/// One CAVS multi-block message test record: key, IV, plaintext and the
/// unpadded ciphertext CAVP expects for them.
struct NistCbcVector
{
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> iv;
    std::vector<std::uint8_t> plaintext;
    std::vector<std::uint8_t> ciphertext;
};

/// Reads one vector of a mode directory, e.g. ("CBC-AES128", "vector2").
/// Records a gtest failure and returns false when a file is missing, which means
/// the vectors were not deployed.
bool LoadNistCbcVector(const std::string& mode, const std::string& prefix, NistCbcVector& out)
{
    const std::string base = kCipherVectorRoot + mode + "/" + prefix + "_";

    out.key = read_bin(base + "key.bin");
    out.iv = read_bin(base + "iv.bin");
    out.plaintext = read_bin(base + "plaintext.bin");
    out.ciphertext = read_bin(base + "ciphertext.bin");

    EXPECT_FALSE(out.key.empty()) << "missing " << base << "key.bin";
    EXPECT_FALSE(out.iv.empty()) << "missing " << base << "iv.bin";
    EXPECT_FALSE(out.plaintext.empty()) << "missing " << base << "plaintext.bin";
    EXPECT_FALSE(out.ciphertext.empty()) << "missing " << base << "ciphertext.bin";
    EXPECT_EQ(out.plaintext.size(), out.ciphertext.size()) << "CAVP records are unpadded, so the sizes must match";

    return !out.plaintext.empty() && (out.plaintext.size() == out.ciphertext.size());
}

// =========================================================================
// Parameterized Test Data
// =========================================================================

/// @brief Parameters for cipher tests using a generated (ephemeral) key.
///
/// The key is random per run, so the ciphertext cannot be compared against the
/// vector — only the round trip and the tamper behaviour can.
struct CipherTestData
{
    std::string test_case_name;
    std::optional<ProviderType> provider_type;
    std::string cipher_algorithm;  ///< e.g. "AES-256-CBC"
    std::string key_algorithm;     ///< e.g. "AES-256-CBC"
    std::size_t iv_size;           ///< 16 for CBC/CTR, 0 for ECB
    bool block_padded;             ///< true when Finalize() emits a padding block
    std::string vector_dir;        ///< CAVP directory the messages come from
};

/// @brief Parameters for cipher tests using the CAVP key loaded from a slot.
///
/// With the vector's own key the expected ciphertext is known, so these cases
/// are known-answer tests rather than round-trip tests.
struct KeySlotCipherTestData
{
    std::string test_case_name;
    std::optional<ProviderType> provider_type;
    std::string cipher_algorithm;
    std::string vector_dir;
    std::string vector_prefix;  ///< which vector of that directory the slot holds
    std::string key_slot_name;
};

// =========================================================================
// Helpers
// =========================================================================

/// Creates a cipher context for one direction over the given key.
std::unique_ptr<ICipherContext> MakeCipherContext(ICryptoContext& ctx,
                                                  const std::string& algorithm,
                                                  const std::optional<ProviderType>& provider_type,
                                                  const CryptoResourceGuard& key,
                                                  CipherDirection direction)
{
    CipherContextConfig config;
    config.SetAlgorithm(algorithm).SetKey(key).SetDirection(direction);
    if (provider_type.has_value())
    {
        config.SetProviderType(provider_type.value());
    }

    auto result = ctx.CreateCipherContext(config);
    EXPECT_TRUE(result.has_value()) << "Failed to create cipher context for " << algorithm;
    if (!result.has_value())
    {
        return nullptr;
    }
    return std::move(result.value());
}

/// Streaming transform: Init(iv) → Update(chunk1) → Update(chunk2) → Finalize.
/// Returns the concatenation of everything the context produced.
void StreamingTransform(ICipherContext& cipher,
                        const std::vector<std::uint8_t>& iv,
                        const std::vector<std::uint8_t>& input,
                        std::size_t block_size,
                        std::vector<std::uint8_t>& output)
{
    output.clear();

    // IV-less modes (ECB) must pass std::nullopt rather than an empty span.
    std::optional<score::cpp::span<const std::uint8_t>> iv_arg{};
    if (!iv.empty())
    {
        iv_arg = score::cpp::span<const std::uint8_t>{iv.data(), iv.size()};
    }
    ASSERT_TRUE(cipher.Init(iv_arg)) << "Cipher Init failed";

    // Split mid-message rather than on a block boundary: that leaves a partial
    // block for the cipher to buffer across the two Update calls, which is the
    // interesting path. Both chunks must be non-empty — an Update with no data
    // is not a meaningful request and the daemon rejects it.
    ASSERT_GE(input.size(), 2U) << "Test input must be at least two bytes";
    const auto split = static_cast<std::ptrdiff_t>(input.size() / 2U);
    const std::vector<std::uint8_t> chunk1(input.begin(), input.begin() + split);
    const std::vector<std::uint8_t> chunk2(input.begin() + split, input.end());

    // Worst case one extra block per Update plus one on Finalize.
    std::vector<std::uint8_t> scratch(input.size() + (2U * block_size));

    auto n1 = cipher.Update({chunk1.data(), chunk1.size()}, {scratch.data(), scratch.size()});
    ASSERT_TRUE(n1.has_value()) << "Cipher Update (chunk 1) failed";
    output.insert(output.end(), scratch.begin(), scratch.begin() + static_cast<std::ptrdiff_t>(n1.value()));

    auto n2 = cipher.Update({chunk2.data(), chunk2.size()}, {scratch.data(), scratch.size()});
    ASSERT_TRUE(n2.has_value()) << "Cipher Update (chunk 2) failed";
    output.insert(output.end(), scratch.begin(), scratch.begin() + static_cast<std::ptrdiff_t>(n2.value()));

    auto n3 = cipher.Finalize({scratch.data(), scratch.size()});
    ASSERT_TRUE(n3.has_value()) << "Cipher Finalize failed";
    output.insert(output.end(), scratch.begin(), scratch.begin() + static_cast<std::ptrdiff_t>(n3.value()));
}

/// Reset → SingleShot(iv, input) and return the produced bytes.
void SingleShotTransform(ICipherContext& cipher,
                         const std::vector<std::uint8_t>& iv,
                         const std::vector<std::uint8_t>& input,
                         std::size_t block_size,
                         std::vector<std::uint8_t>& output)
{
    ASSERT_TRUE(cipher.Reset()) << "Reset before SingleShot failed";

    std::vector<std::uint8_t> scratch(input.size() + (2U * block_size));
    auto n = cipher.SingleShot({iv.data(), iv.size()}, {input.data(), input.size()}, {scratch.data(), scratch.size()});
    ASSERT_TRUE(n.has_value()) << "Cipher SingleShot failed";

    output.assign(scratch.begin(), scratch.begin() + static_cast<std::ptrdiff_t>(n.value()));
}

/// The leading bytes of a PKCS#7-padded ciphertext are the unpadded CAVP
/// ciphertext; the trailing block is the padding this stack adds.
void ExpectMatchesNistCiphertext(const std::vector<std::uint8_t>& produced, const NistCbcVector& vector)
{
    ASSERT_GE(produced.size(), vector.ciphertext.size()) << "Ciphertext is shorter than the CAVP vector";

    const std::vector<std::uint8_t> prefix(produced.begin(),
                                           produced.begin() + static_cast<std::ptrdiff_t>(vector.ciphertext.size()));
    print_hex("Produced", prefix, prefix.size());
    print_hex("CAVP    ", vector.ciphertext, vector.ciphertext.size());
    EXPECT_EQ(prefix, vector.ciphertext) << "Ciphertext does not match the NIST CAVP vector";
}

/// Explicit key release and assertion.
void ReleaseAndAssertKey(CryptoResourceGuard& key)
{
    auto release_result = key.Release();
    ASSERT_TRUE(release_result.has_value()) << "Key release failed";
    EXPECT_FALSE(key.IsActive()) << "Key should be inactive after Release";
}

// =========================================================================
// Test 1: encrypt / decrypt round trip with a generated key
// =========================================================================

class CipherRoundTripTest : public ::testing::TestWithParam<CipherTestData>
{
};

TEST_P(CipherRoundTripTest, EncryptDecryptRoundTrip)
{
    const auto test_data = GetParam();

    // The messages come from the CAVP records of this mode: a single block and a
    // four-block message. Their content does not matter under a random key, but
    // taking them from the vectors keeps both tests on the same inputs.
    NistCbcVector short_vector;
    NistCbcVector long_vector;
    ASSERT_TRUE(LoadNistCbcVector(test_data.vector_dir, "vector1", short_vector));
    ASSERT_TRUE(LoadNistCbcVector(test_data.vector_dir, "vector2", long_vector));

    const auto& plaintext = long_vector.plaintext;
    const auto& plaintext_alt = short_vector.plaintext;

    // =========================================================================
    // 1. Create the crypto stack and a crypto context
    // =========================================================================
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    auto& stack = stack_result.value();

    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    auto& ctx = ctx_result.value();

    // =========================================================================
    // 2. Generate an ephemeral AES key permitted to encrypt and decrypt
    // =========================================================================
    KeyManagementContextConfig key_mgmt_config;
    if (test_data.provider_type.has_value())
    {
        key_mgmt_config.SetProviderType(test_data.provider_type.value());
    }

    auto key_mgmt_result = ctx->CreateKeyManagementContext(key_mgmt_config);
    ASSERT_TRUE(key_mgmt_result.has_value()) << "Failed to create key management context";
    auto& key_mgmt = key_mgmt_result.value();

    GenerateKeyParams key_gen_params;
    key_gen_params.SetAlgorithm(test_data.key_algorithm)
        .SetPermissions(KeyOperationPermission::kEncrypt | KeyOperationPermission::kDecrypt);

    auto key_result = key_mgmt->GenerateKey(key_gen_params);
    ASSERT_TRUE(key_result.has_value()) << "Failed to generate cipher key";
    auto key = std::move(key_result.value());
    ASSERT_TRUE(key.IsActive()) << "Key guard should be active after generation";

    // =========================================================================
    // 3. Obtain a random IV of the length the algorithm requires
    // =========================================================================
    std::vector<std::uint8_t> iv(test_data.iv_size, 0U);
    if (test_data.iv_size > 0U)
    {
        RandomContextConfig random_config;
        if (test_data.provider_type.has_value())
        {
            random_config.SetProviderType(test_data.provider_type.value());
        }
        auto random_result = ctx->CreateRandomContext(random_config);
        ASSERT_TRUE(random_result.has_value()) << "Failed to create random context";

        auto generated = random_result.value()->Generate({iv.data(), iv.size()});
        ASSERT_TRUE(generated.has_value()) << "Failed to generate IV";
        ASSERT_EQ(generated.value(), test_data.iv_size);
        print_hex("IV", iv, iv.size());
    }

    // =========================================================================
    // 4. Streaming encryption
    // =========================================================================
    auto encrypt_ctx =
        MakeCipherContext(*ctx, test_data.cipher_algorithm, test_data.provider_type, key, CipherDirection::kEncrypt);
    ASSERT_NE(encrypt_ctx, nullptr);

    const std::size_t block_size = encrypt_ctx->GetOutputSize();
    ASSERT_GT(block_size, 0U) << "Cipher block size query failed";

    std::vector<std::uint8_t> ciphertext;
    ASSERT_NO_FATAL_FAILURE(StreamingTransform(*encrypt_ctx, iv, plaintext, block_size, ciphertext));
    print_hex("Ciphertext", ciphertext, ciphertext.size());

    ASSERT_FALSE(ciphertext.empty());
    EXPECT_NE(ciphertext, plaintext) << "Ciphertext must not equal plaintext";

    // A padded block mode grows the message; a stream mode keeps it the same size.
    if (test_data.block_padded)
    {
        EXPECT_GT(ciphertext.size(), plaintext.size()) << "Padded mode should append a padding block";
        EXPECT_EQ(ciphertext.size() % block_size, 0U) << "Padded ciphertext must be a whole number of blocks";
    }
    else
    {
        EXPECT_EQ(ciphertext.size(), plaintext.size()) << "Stream mode must preserve the message length";
    }

    // Under a random key the CAVP ciphertext must not appear — this is the
    // control for the known-answer test below, which uses the CAVP key.
    if (ciphertext.size() >= long_vector.ciphertext.size())
    {
        const std::vector<std::uint8_t> prefix(
            ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(long_vector.ciphertext.size()));
        EXPECT_NE(prefix, long_vector.ciphertext) << "A random key reproduced the CAVP ciphertext";
    }

    // =========================================================================
    // 5. Streaming decryption recovers the plaintext
    // =========================================================================
    auto decrypt_ctx =
        MakeCipherContext(*ctx, test_data.cipher_algorithm, test_data.provider_type, key, CipherDirection::kDecrypt);
    ASSERT_NE(decrypt_ctx, nullptr);

    std::vector<std::uint8_t> recovered;
    ASSERT_NO_FATAL_FAILURE(StreamingTransform(*decrypt_ctx, iv, ciphertext, block_size, recovered));
    EXPECT_EQ(recovered, plaintext) << "Decryption did not recover the original plaintext";

    // =========================================================================
    // 6. Single-shot encryption produces the same ciphertext as streaming
    // =========================================================================
    std::vector<std::uint8_t> ciphertext_ss;
    ASSERT_NO_FATAL_FAILURE(SingleShotTransform(*encrypt_ctx, iv, plaintext, block_size, ciphertext_ss));
    EXPECT_EQ(ciphertext_ss, ciphertext) << "SingleShot and streaming encryption must agree";

    // =========================================================================
    // 7. Single-shot decryption round trip
    // =========================================================================
    std::vector<std::uint8_t> recovered_ss;
    ASSERT_NO_FATAL_FAILURE(SingleShotTransform(*decrypt_ctx, iv, ciphertext_ss, block_size, recovered_ss));
    EXPECT_EQ(recovered_ss, plaintext) << "SingleShot decryption did not recover the plaintext";

    // =========================================================================
    // 8. Context reuse via Reset() with a different message
    // =========================================================================
    std::vector<std::uint8_t> ciphertext_alt;
    ASSERT_NO_FATAL_FAILURE(SingleShotTransform(*encrypt_ctx, iv, plaintext_alt, block_size, ciphertext_alt));
    EXPECT_NE(ciphertext_alt, ciphertext) << "A different message must produce different ciphertext";

    std::vector<std::uint8_t> recovered_alt;
    ASSERT_NO_FATAL_FAILURE(SingleShotTransform(*decrypt_ctx, iv, ciphertext_alt, block_size, recovered_alt));
    EXPECT_EQ(recovered_alt, plaintext_alt) << "Round trip after Reset failed";

    // =========================================================================
    // 9. A different IV yields different ciphertext for the same message
    // =========================================================================
    if (test_data.iv_size > 0U)
    {
        std::vector<std::uint8_t> other_iv = iv;
        other_iv[0] ^= 0xFFU;

        std::vector<std::uint8_t> ciphertext_other_iv;
        ASSERT_NO_FATAL_FAILURE(
            SingleShotTransform(*encrypt_ctx, other_iv, plaintext, block_size, ciphertext_other_iv));
        EXPECT_NE(ciphertext_other_iv, ciphertext) << "Changing the IV must change the ciphertext";
    }

    // =========================================================================
    // 10. Tampered ciphertext must not decrypt back to the plaintext
    // =========================================================================
    //
    // A padded mode detects the tampering and fails outright; a stream mode has
    // no integrity check and simply yields different bytes. Both outcomes are
    // acceptable — what must never happen is recovering the original message.
    std::vector<std::uint8_t> tampered = ciphertext;
    tampered[0] ^= 0xFFU;

    ASSERT_TRUE(decrypt_ctx->Reset()) << "Reset before tampered decrypt failed";
    std::vector<std::uint8_t> tampered_out(tampered.size() + (2U * block_size));
    auto tampered_result = decrypt_ctx->SingleShot(
        {iv.data(), iv.size()}, {tampered.data(), tampered.size()}, {tampered_out.data(), tampered_out.size()});

    if (tampered_result.has_value())
    {
        tampered_out.resize(tampered_result.value());
        EXPECT_NE(tampered_out, plaintext) << "Tampered ciphertext must not decrypt to the original plaintext";
    }

    // =========================================================================
    // 11. Explicit key release
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(ReleaseAndAssertKey(key));
}

// =========================================================================
// Test 2: known-answer test with the CAVP key loaded from a key slot
// =========================================================================

class KeySlotCipherTest : public ::testing::TestWithParam<KeySlotCipherTestData>
{
};

TEST_P(KeySlotCipherTest, MatchesNistVector)
{
    const auto test_data = GetParam();

    NistCbcVector vector;
    ASSERT_TRUE(LoadNistCbcVector(test_data.vector_dir, test_data.vector_prefix, vector));

    // =========================================================================
    // 1. Create the crypto stack and a crypto context
    // =========================================================================
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    auto& stack = stack_result.value();

    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    auto& ctx = ctx_result.value();

    // =========================================================================
    // 2. Load the CAVP key from its pre-provisioned key slot
    // =========================================================================
    //
    // The slot's deployment descriptor points at the vector's own key file, so
    // the daemon encrypts under exactly the key NIST used — which is what makes
    // the expected ciphertext below reproducible. The application never sees the
    // key material.
    KeyManagementContextConfig key_mgmt_config;
    if (test_data.provider_type.has_value())
    {
        key_mgmt_config.SetProviderType(test_data.provider_type.value());
    }

    auto key_mgmt_result = ctx->CreateKeyManagementContext(key_mgmt_config);
    ASSERT_TRUE(key_mgmt_result.has_value()) << "Failed to create key management context";
    auto& key_mgmt = key_mgmt_result.value();

    auto slot_result = ctx->ResolveResource(test_data.key_slot_name, ResourceType::kKeySlot);
    ASSERT_TRUE(slot_result.has_value()) << "Failed to resolve key slot: " << test_data.key_slot_name;

    auto key_result = key_mgmt->LoadKey(slot_result.value());
    ASSERT_TRUE(key_result.has_value()) << "Failed to load key from slot: " << test_data.key_slot_name;
    auto key = std::move(key_result.value());
    ASSERT_TRUE(key.IsActive()) << "Key guard should be active after loading from slot";

    // =========================================================================
    // 3. Encrypt the CAVP plaintext under the CAVP IV
    // =========================================================================
    auto encrypt_ctx =
        MakeCipherContext(*ctx, test_data.cipher_algorithm, test_data.provider_type, key, CipherDirection::kEncrypt);
    ASSERT_NE(encrypt_ctx, nullptr);

    const std::size_t block_size = encrypt_ctx->GetOutputSize();
    ASSERT_GT(block_size, 0U) << "Cipher block size query failed";

    std::vector<std::uint8_t> ciphertext;
    ASSERT_NO_FATAL_FAILURE(SingleShotTransform(*encrypt_ctx, vector.iv, vector.plaintext, block_size, ciphertext));

    // PKCS#7 appends a full block to a whole-block message, so the produced
    // ciphertext is the vector's followed by one more block.
    EXPECT_EQ(ciphertext.size(), vector.ciphertext.size() + block_size)
        << "Padded ciphertext should be one block longer than the CAVP vector";
    ASSERT_NO_FATAL_FAILURE(ExpectMatchesNistCiphertext(ciphertext, vector));

    // =========================================================================
    // 4. Streaming encryption agrees with the vector too
    // =========================================================================
    //
    // Streaming buffers a partial block across the two Update calls, so it is a
    // different code path to SingleShot and worth checking against the vector
    // rather than only against SingleShot's own output.
    std::vector<std::uint8_t> ciphertext_streamed;
    ASSERT_TRUE(encrypt_ctx->Reset()) << "Reset before streaming encryption failed";
    ASSERT_NO_FATAL_FAILURE(
        StreamingTransform(*encrypt_ctx, vector.iv, vector.plaintext, block_size, ciphertext_streamed));
    EXPECT_EQ(ciphertext_streamed, ciphertext) << "Streaming and single-shot encryption must agree";

    // =========================================================================
    // 5. Decryption recovers the CAVP plaintext
    // =========================================================================
    auto decrypt_ctx =
        MakeCipherContext(*ctx, test_data.cipher_algorithm, test_data.provider_type, key, CipherDirection::kDecrypt);
    ASSERT_NE(decrypt_ctx, nullptr);

    std::vector<std::uint8_t> recovered;
    ASSERT_NO_FATAL_FAILURE(SingleShotTransform(*decrypt_ctx, vector.iv, ciphertext, block_size, recovered));
    EXPECT_EQ(recovered, vector.plaintext) << "Decryption did not recover the CAVP plaintext";

    // =========================================================================
    // 6. The unpadded CAVP ciphertext on its own does not decrypt
    // =========================================================================
    //
    // Documented consequence of always-on PKCS#7: the vector's ciphertext has no
    // padding block, so the padding check has nothing valid to strip. Whether
    // that surfaces as an error or as different bytes, the plaintext must not
    // come back — feeding CAVP ciphertext straight to a decrypt context is a
    // usage error, not a supported path.
    {
        ASSERT_TRUE(decrypt_ctx->Reset()) << "Reset before unpadded decrypt failed";
        std::vector<std::uint8_t> out(vector.ciphertext.size() + (2U * block_size));
        auto result = decrypt_ctx->SingleShot({vector.iv.data(), vector.iv.size()},
                                              {vector.ciphertext.data(), vector.ciphertext.size()},
                                              {out.data(), out.size()});
        if (result.has_value())
        {
            out.resize(result.value());
            EXPECT_NE(out, vector.plaintext) << "Unpadded CAVP ciphertext must not decrypt cleanly";
        }
    }

    // =========================================================================
    // 7. A different IV breaks agreement with the vector
    // =========================================================================
    //
    // Confirms the IV really reached the cipher rather than the match in step 3
    // coming from somewhere else.
    {
        std::vector<std::uint8_t> other_iv = vector.iv;
        other_iv[0] ^= 0xFFU;

        std::vector<std::uint8_t> ciphertext_other_iv;
        ASSERT_NO_FATAL_FAILURE(
            SingleShotTransform(*encrypt_ctx, other_iv, vector.plaintext, block_size, ciphertext_other_iv));
        EXPECT_NE(ciphertext_other_iv, ciphertext) << "Changing the IV must change the ciphertext";
    }

    // =========================================================================
    // 8. Explicit key release
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(ReleaseAndAssertKey(key));
}

// =========================================================================
// Test Vector Constants
// =========================================================================

constexpr std::size_t kAesIvSize = 16U;

// The slot holding each mode's CAVP key. All are OpenSSL slots: the key material
// is a file the daemon imports, which is what FileBackedSlotHandler does.
const std::string kAes128CbcKeySlot = "AES128_CBC_IntegrationTestKey_OpenSSL";
const std::string kAes192CbcKeySlot = "AES192_CBC_IntegrationTestKey_OpenSSL";
const std::string kAes256CbcKeySlot = "AES256_CBC_IntegrationTestKey_OpenSSL";

/// The slots are provisioned with the four-block vector's key.
const std::string kKeySlotVector = "vector2";

// =========================================================================
// Test Suites
// =========================================================================

// Symmetric ciphers are provided only by the OpenSSL (software) provider, so
// every case pins ProviderType::kSoftware. Leaving the provider unset would
// resolve to the daemon's DEFAULT provider — currently SoftHSM — which offers
// no cipher handler.
INSTANTIATE_TEST_SUITE_P(CbcOnSoftwareProvider,
                         CipherRoundTripTest,
                         ::testing::Values(CipherTestData{"AES256_CBC_SoftwareProvider",
                                                          ProviderType::kSoftware,
                                                          "AES-256-CBC",
                                                          "AES-256-CBC",
                                                          kAesIvSize,
                                                          true,
                                                          "CBC-AES256"},
                                           CipherTestData{"AES192_CBC_SoftwareProvider",
                                                          ProviderType::kSoftware,
                                                          "AES-192-CBC",
                                                          "AES-192-CBC",
                                                          kAesIvSize,
                                                          true,
                                                          "CBC-AES192"},
                                           CipherTestData{"AES128_CBC_SoftwareProvider",
                                                          ProviderType::kSoftware,
                                                          "AES-128-CBC",
                                                          "AES-128-CBC",
                                                          kAesIvSize,
                                                          true,
                                                          "CBC-AES128"}),
                         [](const testing::TestParamInfo<CipherRoundTripTest::ParamType>& info) {
                             return info.param.test_case_name;
                         });

INSTANTIATE_TEST_SUITE_P(NistVectorsOnSoftwareProvider,
                         KeySlotCipherTest,
                         ::testing::Values(KeySlotCipherTestData{"AES256_CBC_KeySlot_SoftwareProvider",
                                                                 ProviderType::kSoftware,
                                                                 "AES-256-CBC",
                                                                 "CBC-AES256",
                                                                 kKeySlotVector,
                                                                 kAes256CbcKeySlot},
                                           KeySlotCipherTestData{"AES192_CBC_KeySlot_SoftwareProvider",
                                                                 ProviderType::kSoftware,
                                                                 "AES-192-CBC",
                                                                 "CBC-AES192",
                                                                 kKeySlotVector,
                                                                 kAes192CbcKeySlot},
                                           KeySlotCipherTestData{"AES128_CBC_KeySlot_SoftwareProvider",
                                                                 ProviderType::kSoftware,
                                                                 "AES-128-CBC",
                                                                 "CBC-AES128",
                                                                 kKeySlotVector,
                                                                 kAes128CbcKeySlot}),
                         [](const testing::TestParamInfo<KeySlotCipherTest::ParamType>& info) {
                             return info.param.test_case_name;
                         });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
