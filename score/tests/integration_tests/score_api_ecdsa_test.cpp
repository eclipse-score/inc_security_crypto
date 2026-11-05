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

/// @file score_api_ecdsa_example.cpp
/// @brief Demonstrates ECDSA key generation, signing and verification using the
///        score::crypto API.
///
/// Shows:
///   - Asymmetric key-pair generation on P-256, P-384 and P-521 via
///     IKeyManagementContext::GenerateKey (ephemeral path)
///   - Key loading from a named key slot via ResolveResource + LoadKey, for both
///     a NIST key pair and a public-key-only slot
///   - Streaming signature generation (Init → Update* → SignFinalize)
///   - Streaming verification (Init → Update* → VerifyFinalize)
///   - Single-shot signing and verification
///   - Rejection of a tampered signature and of a tampered message
///   - Verification of the NIST FIPS 186-4 CAVP signatures, including a record
///     NIST authored to be rejected
///   - Every NIST SigVer record of the twelve catalog curve/digest pairs, over
///     the message and over its digest (SignatureInputMode::kPrehashed)
///   - Signatures over a message and over its digest being interchangeable,
///     and a digest of the wrong length being refused
///   - Context reuse via Reset()
///
/// One generated key resource represents the whole pair: a sign context binds
/// its private half, a verify context its public half.
///
/// @par What the NIST vectors establish here
///
/// ECDSA is randomised, so re-signing a CAVP message does not reproduce the
/// CAVP signature — the per-message secret `k` is not settable through this API,
/// and must not be. The vectors are therefore used on the verification side: a
/// `SigGen` record's published signature must verify under its published key,
/// and a `SigVer` record marked `Result = F` must not. Signing is checked by
/// verifying what was just signed.
///
/// @note NIST's largest prime curve is P-521 (not P-512), so that is the curve
///       used for the highest-strength cases here.

#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_sign_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/result/result.h"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace score::crypto;
using tests::utility::print_hex;
using tests::utility::read_bin;

namespace
{

#ifdef __QNXNTO__
constexpr auto kControlSocketEndpoint = "unix:///opt/crypto_daemon.sock";
#else
constexpr auto kControlSocketEndpoint = "unix:///tmp/crypto_daemon.sock";
#endif

// =========================================================================
// NIST FIPS 186-4 CAVP vectors
// =========================================================================

/// Resolves a test-vector path against the deployment layout.
///
/// The ITF harness deploys the vectors under the install directory and points
/// TEST_VECTORS_DIR at them; the fallback is where the harness places them by
/// default, so the binary is still runnable by hand on a deployed target.
std::string GetTestVectorPath(const std::string_view relative_path)
{
    const char* dir = std::getenv("TEST_VECTORS_DIR");
    return std::string{dir != nullptr ? dir : "/opt/crypto/share/test_vectors"} + std::string{relative_path};
}

/// One curve/digest pair's vector set: a SigGen record that must verify and a
/// SigVer record NIST marked as a failure.
struct NistEcdsaVector
{
    std::vector<std::uint8_t> message;            ///< SigGen Msg
    std::vector<std::uint8_t> signature;          ///< SigGen (R, S) in P1363 form
    std::vector<std::uint8_t> invalid_message;    ///< SigVer Msg of the Result = F record
    std::vector<std::uint8_t> invalid_signature;  ///< its (R, S), which must not verify
};

/// Reads the vector set of one curve/digest directory, e.g. "P256-SHA256".
/// Records a gtest failure and returns false when a file is missing, which means
/// the vectors were not deployed.
bool LoadNistEcdsaVector(const std::string& curve_dir, std::size_t signature_size, NistEcdsaVector& out)
{
    const std::string dir = GetTestVectorPath("/ecdsa/") + curve_dir + "/";

    out.message = read_bin(dir + "siggen_message.bin");
    out.signature = read_bin(dir + "siggen_signature.bin");
    out.invalid_message = read_bin(dir + "sigver_invalid_message.bin");
    out.invalid_signature = read_bin(dir + "sigver_invalid_signature.bin");

    EXPECT_FALSE(out.message.empty()) << "missing " << dir << "siggen_message.bin";
    EXPECT_FALSE(out.invalid_message.empty()) << "missing " << dir << "sigver_invalid_message.bin";
    EXPECT_EQ(out.signature.size(), signature_size) << "unexpected P1363 length in " << dir;
    EXPECT_EQ(out.invalid_signature.size(), signature_size) << "unexpected P1363 length in " << dir;

    return !out.message.empty() && (out.signature.size() == signature_size) &&
           (out.invalid_signature.size() == signature_size);
}

// =========================================================================
// Parameterized Test Data
// =========================================================================

/// @brief Parameters for ECDSA tests over a generated (ephemeral) key pair.
struct EcdsaTestData
{
    std::string test_case_name;
    std::optional<ProviderType> provider_type;
    std::string key_algorithm;        ///< e.g. "ECDSA-P256"
    std::string signature_algorithm;  ///< e.g. "ECDSA-P256-SHA256"
    std::size_t expected_signature_size;
    std::string vector_dir;  ///< CAVP directory the messages come from
};

/// @brief Parameters for ECDSA tests over a key pair loaded from a key slot.
///
/// With NIST's own key pair in the slot, the CAVP signature becomes an expected
/// value rather than just a shape to check.
struct KeySlotEcdsaTestData
{
    std::string test_case_name;
    std::optional<ProviderType> provider_type;
    std::string signature_algorithm;
    std::size_t expected_signature_size;
    std::string vector_dir;
    std::string key_slot_name;         ///< slot holding the SigGen key pair
    std::string public_key_slot_name;  ///< VERIFY-only slot holding the SigVer failure key
};

struct PrehashedEcdsaTestData
{
    std::string test_case_name;
    std::string hash_algorithm;
    std::string signature_algorithm;
    std::size_t signature_size;
    std::string vector_dir;
    std::string key_slot_name;
};

// =========================================================================
// Helpers
// =========================================================================

std::unique_ptr<ISignContext> MakeSignContext(ICryptoContext& ctx,
                                              const std::string& algorithm,
                                              const std::optional<ProviderType>& provider_type,
                                              const CryptoResourceGuard& key)
{
    SignContextConfig config;
    config.SetAlgorithm(algorithm).SetKey(key);
    if (provider_type.has_value())
    {
        config.SetProviderType(provider_type.value());
    }

    auto result = ctx.CreateSignContext(config);
    EXPECT_TRUE(result.has_value()) << "Failed to create sign context for " << algorithm;
    if (!result.has_value())
    {
        return nullptr;
    }
    return std::move(result.value());
}

std::unique_ptr<IVerifySignatureContext> MakeVerifyContext(ICryptoContext& ctx,
                                                           const std::string& algorithm,
                                                           const std::optional<ProviderType>& provider_type,
                                                           const CryptoResourceGuard& key)
{
    VerifySignatureContextConfig config;
    config.SetAlgorithm(algorithm).SetKey(key);
    if (provider_type.has_value())
    {
        config.SetProviderType(provider_type.value());
    }

    auto result = ctx.CreateVerifySignatureContext(config);
    EXPECT_TRUE(result.has_value()) << "Failed to create verify context for " << algorithm;
    if (!result.has_value())
    {
        return nullptr;
    }
    return std::move(result.value());
}

/// Reset → Init → Update(chunk1) → Update(chunk2) → SignFinalize.
void StreamingSign(ISignContext& sign,
                   const std::vector<std::uint8_t>& message,
                   std::size_t signature_size,
                   std::vector<std::uint8_t>& signature)
{
    signature.assign(signature_size, 0U);

    ASSERT_TRUE(sign.Reset()) << "Reset before signing failed";
    ASSERT_TRUE(sign.Init()) << "Sign Init failed";

    const auto split = static_cast<std::ptrdiff_t>(message.size()) / 2;
    const std::vector<std::uint8_t> chunk1(message.begin(), message.begin() + split);
    const std::vector<std::uint8_t> chunk2(message.begin() + split, message.end());

    ASSERT_TRUE(sign.Update({chunk1.data(), chunk1.size()})) << "Sign Update (chunk 1) failed";
    ASSERT_TRUE(sign.Update({chunk2.data(), chunk2.size()})) << "Sign Update (chunk 2) failed";

    auto written = sign.SignFinalize({signature.data(), signature.size()});
    ASSERT_TRUE(written.has_value()) << "SignFinalize failed";
    ASSERT_EQ(written.value(), signature_size) << "Unexpected ECDSA signature length";

    print_hex("Signature", signature, signature.size());
}

/// Reset → Init → Update(message) → VerifyFinalize(signature).
void StreamingVerify(IVerifySignatureContext& verify,
                     const std::vector<std::uint8_t>& message,
                     const std::vector<std::uint8_t>& signature,
                     bool expected_valid)
{
    ASSERT_TRUE(verify.Reset()) << "Reset before verification failed";
    ASSERT_TRUE(verify.Init()) << "Verify Init failed";
    ASSERT_TRUE(verify.Update({message.data(), message.size()})) << "Verify Update failed";

    auto result = verify.VerifyFinalize({signature.data(), signature.size()});
    ASSERT_TRUE(result.has_value()) << "VerifyFinalize call failed";
    EXPECT_EQ(result.value(), expected_valid)
        << "Signature verification returned " << result.value() << ", expected " << expected_valid;
}

/// Resolves a named slot and loads the key material it holds.
score::Result<CryptoResourceGuard> LoadKeyFromSlot(ICryptoContext& ctx,
                                                   IKeyManagementContext& key_mgmt,
                                                   const std::string& slot_name)
{
    auto slot = ctx.ResolveResource(slot_name, ResourceType::kKeySlot);
    EXPECT_TRUE(slot.has_value()) << "Failed to resolve key slot: " << slot_name;
    if (!slot.has_value())
    {
        return score::Result<CryptoResourceGuard>{score::unexpect, slot.error()};
    }
    return key_mgmt.LoadKey(slot.value());
}

/// Explicit key release and assertion.
void ReleaseAndAssertKey(CryptoResourceGuard& key)
{
    auto release_result = key.Release();
    ASSERT_TRUE(release_result.has_value()) << "Key release failed";
    EXPECT_FALSE(key.IsActive()) << "Key should be inactive after Release";
}

// =========================================================================
// Test 1: ECDSA key generation, sign and verify with an ephemeral key pair
// =========================================================================

class EcdsaSignVerifyTest : public ::testing::TestWithParam<EcdsaTestData>
{
};

TEST_P(EcdsaSignVerifyTest, GenerateSignAndVerify)
{
    const auto test_data = GetParam();

    // The two messages come from the CAVP records of this curve. Their content
    // does not matter under a freshly generated key, but taking them from the
    // vectors keeps both ECDSA tests on the same inputs.
    NistEcdsaVector vector;
    ASSERT_TRUE(LoadNistEcdsaVector(test_data.vector_dir, test_data.expected_signature_size, vector));

    const auto& message = vector.message;
    const auto& message_alt = vector.invalid_message;

    // =========================================================================
    // 1. Create the crypto stack and a crypto context
    // =========================================================================
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    auto& stack = stack_result.value();

    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    auto& ctx = ctx_result.value();

    // =========================================================================
    // 2. Generate an ECDSA key pair
    // =========================================================================
    //
    // The returned guard names one daemon resource that carries both halves:
    // the sign context below binds the private key, the verify context the
    // public key, without the application ever handling key material.
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
        .SetPermissions(KeyOperationPermission::kSign)
        .SetPublicKeyPermissions(KeyOperationPermission::kVerify);

    auto key_result = key_mgmt->GenerateKey(key_gen_params);
    ASSERT_TRUE(key_result.has_value()) << "Failed to generate ECDSA key pair for " << test_data.key_algorithm;
    auto key = std::move(key_result.value());
    ASSERT_TRUE(key.IsActive()) << "Key guard should be active after generation";

    // =========================================================================
    // 3. Create the sign and verify contexts
    // =========================================================================
    auto sign_ctx = MakeSignContext(*ctx, test_data.signature_algorithm, test_data.provider_type, key);
    ASSERT_NE(sign_ctx, nullptr);
    auto verify_ctx = MakeVerifyContext(*ctx, test_data.signature_algorithm, test_data.provider_type, key);
    ASSERT_NE(verify_ctx, nullptr);

    // =========================================================================
    // 4. The reported signature size matches the curve
    // =========================================================================
    //
    // Signatures are the fixed-length IEEE P1363 form r‖s, so the size is
    // exactly twice the field size — 64, 96 or 132 bytes.
    EXPECT_EQ(sign_ctx->GetSignatureSize(), test_data.expected_signature_size)
        << "Unexpected signature size for " << test_data.signature_algorithm;

    // =========================================================================
    // 5. Streaming sign, then streaming verify
    // =========================================================================
    std::vector<std::uint8_t> signature;
    ASSERT_NO_FATAL_FAILURE(StreamingSign(*sign_ctx, message, test_data.expected_signature_size, signature));
    ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, message, signature, true));

    // The CAVP signature belongs to NIST's key pair, not this generated one, so
    // it must not verify here. That the same bytes *do* verify under the slot
    // key in the test below is what tells the two apart.
    ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, message, vector.signature, false));

    // =========================================================================
    // 6. A tampered signature must not verify
    // =========================================================================
    {
        std::vector<std::uint8_t> tampered = signature;
        tampered[0] ^= 0xFFU;  // corrupt r
        ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, message, tampered, false));

        std::vector<std::uint8_t> tampered_s = signature;
        tampered_s[tampered_s.size() - 1U] ^= 0xFFU;  // corrupt s
        ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, message, tampered_s, false));
    }

    // =========================================================================
    // 7. A different message must not verify against the same signature
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, message_alt, signature, false));

    // =========================================================================
    // 8. Single-shot signing and verification
    // =========================================================================
    {
        ASSERT_TRUE(sign_ctx->Reset()) << "Reset before SingleShot sign failed";

        std::vector<std::uint8_t> ss_signature(test_data.expected_signature_size, 0U);
        auto written =
            sign_ctx->SingleShot({message.data(), message.size()}, {ss_signature.data(), ss_signature.size()});
        ASSERT_TRUE(written.has_value()) << "SingleShot signing failed";
        EXPECT_EQ(written.value(), test_data.expected_signature_size);

        ASSERT_TRUE(verify_ctx->Reset()) << "Reset before SingleShot verify failed";
        auto verified =
            verify_ctx->SingleShot({message.data(), message.size()}, {ss_signature.data(), ss_signature.size()});
        ASSERT_TRUE(verified.has_value()) << "SingleShot verification call failed";
        EXPECT_TRUE(verified.value()) << "SingleShot signature should verify";

        // ECDSA is randomised: two signatures over the same message under the
        // same key differ, yet both verify. That is expected, not a defect.
        EXPECT_NE(ss_signature, signature) << "Two ECDSA signatures over one message should differ";
        ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, message, ss_signature, true));

        // Single-shot verification runs EVP_DigestVerify, a different provider
        // call from the streaming sequence, so its rejection path needs its own
        // cases: a positive-only test would also pass on an implementation that
        // returned true unconditionally.
        {
            std::vector<std::uint8_t> tampered = ss_signature;
            tampered[0] ^= 0xFFU;  // corrupt r

            ASSERT_TRUE(verify_ctx->Reset()) << "Reset before tampered SingleShot verify failed";
            auto rejected =
                verify_ctx->SingleShot({message.data(), message.size()}, {tampered.data(), tampered.size()});
            ASSERT_TRUE(rejected.has_value()) << "A corrupt signature is a verdict, not a call failure";
            EXPECT_FALSE(rejected.value()) << "SingleShot must reject a tampered signature";
        }
        {
            ASSERT_TRUE(verify_ctx->Reset()) << "Reset before wrong-message SingleShot verify failed";
            auto rejected = verify_ctx->SingleShot({message_alt.data(), message_alt.size()},
                                                   {ss_signature.data(), ss_signature.size()});
            ASSERT_TRUE(rejected.has_value()) << "A mismatching message is a verdict, not a call failure";
            EXPECT_FALSE(rejected.value()) << "SingleShot must reject a signature over a different message";
        }
    }

    // =========================================================================
    // 9. Context reuse via Reset() with a different message
    // =========================================================================
    std::vector<std::uint8_t> signature_alt;
    ASSERT_NO_FATAL_FAILURE(StreamingSign(*sign_ctx, message_alt, test_data.expected_signature_size, signature_alt));
    ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, message_alt, signature_alt, true));

    // The signature over the first message must still not verify the second.
    ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, message, signature_alt, false));

    // =========================================================================
    // 10. Reset mid-stream discards partial work
    // =========================================================================
    {
        ASSERT_TRUE(sign_ctx->Reset());
        ASSERT_TRUE(sign_ctx->Init());
        ASSERT_TRUE(sign_ctx->Update({message.data(), message.size()}));
        ASSERT_TRUE(sign_ctx->Reset()) << "Mid-stream Reset failed";

        // After discarding the first message, sign the alternative one and
        // confirm the result authenticates that message and not the first.
        std::vector<std::uint8_t> after_abort;
        ASSERT_NO_FATAL_FAILURE(StreamingSign(*sign_ctx, message_alt, test_data.expected_signature_size, after_abort));
        ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, message_alt, after_abort, true));
        ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, message, after_abort, false));
    }

    // =========================================================================
    // 11. A signature from an unrelated key pair must not verify
    // =========================================================================
    {
        auto other_key_result = key_mgmt->GenerateKey(key_gen_params);
        ASSERT_TRUE(other_key_result.has_value()) << "Failed to generate second ECDSA key pair";
        auto other_key = std::move(other_key_result.value());

        auto other_sign_ctx = MakeSignContext(*ctx, test_data.signature_algorithm, test_data.provider_type, other_key);
        ASSERT_NE(other_sign_ctx, nullptr);

        std::vector<std::uint8_t> foreign_signature;
        ASSERT_NO_FATAL_FAILURE(
            StreamingSign(*other_sign_ctx, message, test_data.expected_signature_size, foreign_signature));

        // Same message, valid signature — but made with a different key.
        ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, message, foreign_signature, false));
    }

    // =========================================================================
    // 12. Explicit key release
    // =========================================================================
    //
    // The contexts hold their own reference to the bound key material, so
    // releasing the guard here is safe and mirrors the MAC example.
    ASSERT_NO_FATAL_FAILURE(ReleaseAndAssertKey(key));
}

// =========================================================================
// Test 2: NIST CAVP verification with the key pair loaded from a key slot
// =========================================================================

class KeySlotEcdsaTest : public ::testing::TestWithParam<KeySlotEcdsaTestData>
{
};

TEST_P(KeySlotEcdsaTest, VerifiesNistVectors)
{
    const auto test_data = GetParam();

    NistEcdsaVector vector;
    ASSERT_TRUE(LoadNistEcdsaVector(test_data.vector_dir, test_data.expected_signature_size, vector));

    // =========================================================================
    // 1. Create the crypto stack and a crypto context
    // =========================================================================
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    auto& stack = stack_result.value();

    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    auto& ctx = ctx_result.value();

    // =========================================================================
    // 2. Load NIST's key pair from its pre-provisioned key slot
    // =========================================================================
    //
    // The slot's deployment descriptor points at the DER encoding of the CAVP
    // private key, so the daemon holds NIST's key pair: its private half signs
    // and its public half verifies, and the application never sees either.
    KeyManagementContextConfig key_mgmt_config;
    if (test_data.provider_type.has_value())
    {
        key_mgmt_config.SetProviderType(test_data.provider_type.value());
    }

    auto key_mgmt_result = ctx->CreateKeyManagementContext(key_mgmt_config);
    ASSERT_TRUE(key_mgmt_result.has_value()) << "Failed to create key management context";
    auto& key_mgmt = key_mgmt_result.value();

    auto key_result = LoadKeyFromSlot(*ctx, *key_mgmt, test_data.key_slot_name);
    ASSERT_TRUE(key_result.has_value()) << "Failed to load key from slot: " << test_data.key_slot_name;
    auto key = std::move(key_result.value());
    ASSERT_TRUE(key.IsActive()) << "Key guard should be active after loading from slot";

    // =========================================================================
    // 3. The published CAVP signature verifies under the published key
    // =========================================================================
    //
    // This is the known-answer half of the ECDSA testing: bytes NIST produced,
    // verified by this stack, with no value this stack computed in between.
    auto verify_ctx = MakeVerifyContext(*ctx, test_data.signature_algorithm, test_data.provider_type, key);
    ASSERT_NE(verify_ctx, nullptr);

    print_hex("CAVP signature", vector.signature, vector.signature.size());
    ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, vector.message, vector.signature, true));

    // Single-shot verification of the same vector.
    {
        ASSERT_TRUE(verify_ctx->Reset()) << "Reset before SingleShot verify failed";
        auto verified = verify_ctx->SingleShot({vector.message.data(), vector.message.size()},
                                               {vector.signature.data(), vector.signature.size()});
        ASSERT_TRUE(verified.has_value()) << "SingleShot verification call failed";
        EXPECT_TRUE(verified.value()) << "SingleShot verification of the CAVP signature failed";
    }

    // =========================================================================
    // 4. Corrupting either half of the CAVP signature breaks verification
    // =========================================================================
    {
        std::vector<std::uint8_t> tampered_r = vector.signature;
        tampered_r[0] ^= 0xFFU;
        ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, vector.message, tampered_r, false));

        std::vector<std::uint8_t> tampered_s = vector.signature;
        tampered_s[tampered_s.size() - 1U] ^= 0xFFU;
        ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, vector.message, tampered_s, false));
    }

    // =========================================================================
    // 5. The CAVP signature does not authenticate a different message
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, vector.invalid_message, vector.signature, false));

    // =========================================================================
    // 6. Signing with the slot key produces a signature that verifies
    // =========================================================================
    //
    // NIST's per-message secret is not settable here, so the signature differs
    // from the CAVP one every run. What is checkable is that it verifies under
    // the same public half that just accepted NIST's own signature.
    auto sign_ctx = MakeSignContext(*ctx, test_data.signature_algorithm, test_data.provider_type, key);
    ASSERT_NE(sign_ctx, nullptr);

    std::vector<std::uint8_t> signature;
    ASSERT_NO_FATAL_FAILURE(StreamingSign(*sign_ctx, vector.message, test_data.expected_signature_size, signature));
    EXPECT_NE(signature, vector.signature) << "A randomised signature reproduced the CAVP value";
    ASSERT_NO_FATAL_FAILURE(StreamingVerify(*verify_ctx, vector.message, signature, true));

    // =========================================================================
    // 7. A VERIFY-only slot rejects the NIST failure record
    // =========================================================================
    //
    // This slot holds only the public half — a SubjectPublicKeyInfo blob — of a
    // SigVer record NIST marked `Result = F`. Unlike a bit-flipped signature it
    // is a well-formed value authored to be rejected, and it is the only case
    // that exercises importing a public key on its own.
    auto public_key_result = LoadKeyFromSlot(*ctx, *key_mgmt, test_data.public_key_slot_name);
    ASSERT_TRUE(public_key_result.has_value()) << "Failed to load key from slot: " << test_data.public_key_slot_name;
    auto public_key = std::move(public_key_result.value());
    ASSERT_TRUE(public_key.IsActive()) << "Public key guard should be active after loading from slot";

    auto public_verify_ctx =
        MakeVerifyContext(*ctx, test_data.signature_algorithm, test_data.provider_type, public_key);
    ASSERT_NE(public_verify_ctx, nullptr);

    ASSERT_NO_FATAL_FAILURE(
        StreamingVerify(*public_verify_ctx, vector.invalid_message, vector.invalid_signature, false));

    // =========================================================================
    // 8. A VERIFY-only slot cannot be used to sign
    // =========================================================================
    //
    // The slot grants VERIFY alone, so the daemon must refuse the sign context
    // at creation rather than at the first Update.
    {
        SignContextConfig config;
        config.SetAlgorithm(test_data.signature_algorithm).SetKey(public_key);
        if (test_data.provider_type.has_value())
        {
            config.SetProviderType(test_data.provider_type.value());
        }

        auto refused = ctx->CreateSignContext(config);
        EXPECT_FALSE(refused.has_value()) << "A VERIFY-only key slot must not yield a sign context";
    }

    // =========================================================================
    // 9. Explicit key release
    // =========================================================================
    ASSERT_NO_FATAL_FAILURE(ReleaseAndAssertKey(public_key));
    ASSERT_NO_FATAL_FAILURE(ReleaseAndAssertKey(key));
}

// =========================================================================
// Test 3: ECDSA prehashed input derived from NIST SigGen messages
// =========================================================================

class EcdsaPrehashedTest : public ::testing::TestWithParam<PrehashedEcdsaTestData>
{
};

TEST_P(EcdsaPrehashedTest, UsesProvisionedNistVectorDigest)
{
    const auto test_data = GetParam();
    const auto vector_path = GetTestVectorPath("/ecdsa/") + test_data.vector_dir + "/";
    const auto message = read_bin(vector_path + "siggen_message.bin");
    const auto nist_signature = read_bin(vector_path + "siggen_signature.bin");
    ASSERT_FALSE(message.empty());
    ASSERT_EQ(nist_signature.size(), test_data.signature_size);

    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint);
    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value());
    auto context_result = stack_result.value()->CreateCryptoContext();
    ASSERT_TRUE(context_result.has_value());
    auto& context = context_result.value();

    KeyManagementContextConfig key_config;
    key_config.SetProviderType(ProviderType::kSoftware);
    auto key_context_result = context->CreateKeyManagementContext(key_config);
    ASSERT_TRUE(key_context_result.has_value());

    auto key_result = LoadKeyFromSlot(*context, *key_context_result.value(), test_data.key_slot_name);
    ASSERT_TRUE(key_result.has_value());
    auto key = std::move(key_result.value());

    HashContextConfig hash_config;
    hash_config.SetAlgorithm(test_data.hash_algorithm).SetProviderType(ProviderType::kSoftware);
    auto hash_result = context->CreateHashContext(hash_config);
    ASSERT_TRUE(hash_result.has_value());
    auto hash = std::move(hash_result.value());
    std::vector<std::uint8_t> digest(hash->GetDigestSize());
    auto digest_result = hash->SingleShot({message.data(), message.size()}, {digest.data(), digest.size()});
    ASSERT_TRUE(digest_result.has_value());
    ASSERT_EQ(digest_result.value(), digest.size());

    VerifySignatureContextConfig verify_config;
    verify_config.SetAlgorithm(test_data.signature_algorithm)
        .SetKey(key)
        .SetInputMode(SignatureInputMode::kPrehashed)
        .SetProviderType(ProviderType::kSoftware);
    auto verify_result = context->CreateVerifySignatureContext(verify_config);
    ASSERT_TRUE(verify_result.has_value());
    auto verify = std::move(verify_result.value());

    ASSERT_TRUE(verify->Init());
    ASSERT_TRUE(verify->Update({digest.data(), digest.size()}));
    auto verified = verify->VerifyFinalize({nist_signature.data(), nist_signature.size()});
    ASSERT_TRUE(verified.has_value());
    EXPECT_TRUE(verified.value());
}

// =========================================================================
// Test 4: every NIST SigVer record of every catalog curve/digest pair
// =========================================================================
//
// SigVer.rsp holds, per pair, 15 records NIST authored for verifiers: 3 valid
// signatures and 12 that must be rejected because the message, R, S or Q was
// changed. Each public key is imported at runtime as a raw SEC1 point, so no
// key slot is needed per record.

/// @brief Parameters for one curve/digest pair of the catalog.
struct EcdsaPairTestData
{
    std::string test_case_name;
    std::string section;              ///< SigVer.rsp header, e.g. "[P-256,SHA-224]"
    std::string key_algorithm;        ///< e.g. "ECDSA-P256"
    std::string signature_algorithm;  ///< e.g. "ECDSA-P256-SHA224"
    std::string hash_algorithm;       ///< e.g. "SHA224"
    std::size_t field_size;           ///< 32, 48 or 66 bytes
};

struct SigVerRecord
{
    std::vector<std::uint8_t> message;
    std::vector<std::uint8_t> public_point;  ///< 0x04 || Qx || Qy
    std::vector<std::uint8_t> signature;     ///< R || S in P1363 form
    bool expected_valid{false};
    std::string result;  ///< NIST's Result line, e.g. "F (2 - R changed)"
};

/// Decodes @p hex, left-padding to @p size bytes; P-521 values are listed with
/// an odd number of digits. An empty result means the value does not fit.
std::vector<std::uint8_t> HexToBytes(std::string_view hex, std::size_t size)
{
    std::string digits(hex);
    if (size != 0U)
    {
        if (digits.size() > (2U * size))
        {
            return {};
        }
        digits.insert(0U, (2U * size) - digits.size(), '0');
    }
    else if ((digits.size() % 2U) != 0U)
    {
        digits.insert(0U, 1U, '0');
    }

    std::vector<std::uint8_t> bytes;
    bytes.reserve(digits.size() / 2U);
    for (std::size_t i = 0U; i < digits.size(); i += 2U)
    {
        bytes.push_back(static_cast<std::uint8_t>(std::stoul(digits.substr(i, 2U), nullptr, 16)));
    }
    return bytes;
}

/// Reads the records of one section of the deployed SigVer.rsp.
std::vector<SigVerRecord> LoadSigVerSection(const std::string& section, std::size_t field_size)
{
    std::ifstream file(GetTestVectorPath("/ecdsa/SigVer/SigVer.rsp"));
    EXPECT_TRUE(file.is_open()) << "missing ecdsa/SigVer/SigVer.rsp";

    std::vector<SigVerRecord> records;
    SigVerRecord current;
    std::vector<std::uint8_t> qx;
    std::vector<std::uint8_t> qy;
    std::vector<std::uint8_t> r;
    bool in_section = false;
    std::string line;
    while (std::getline(file, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }
        if (!line.empty() && line.front() == '[')
        {
            in_section = (line == section);
            continue;
        }
        const auto separator = line.find(" = ");
        if (!in_section || (separator == std::string::npos))
        {
            continue;
        }
        const std::string key = line.substr(0U, separator);
        const std::string value = line.substr(separator + 3U);
        if (key == "Msg")
        {
            current = SigVerRecord{};
            current.message = HexToBytes(value, 0U);
        }
        else if (key == "Qx")
        {
            qx = HexToBytes(value, field_size);
        }
        else if (key == "Qy")
        {
            qy = HexToBytes(value, field_size);
        }
        else if (key == "R")
        {
            r = HexToBytes(value, field_size);
        }
        else if (key == "S")
        {
            const auto s = HexToBytes(value, field_size);
            current.signature = r;
            current.signature.insert(current.signature.end(), s.begin(), s.end());
        }
        else if (key == "Result")
        {
            current.public_point.assign(1U, 0x04U);
            current.public_point.insert(current.public_point.end(), qx.begin(), qx.end());
            current.public_point.insert(current.public_point.end(), qy.begin(), qy.end());
            current.expected_valid = (value.front() == 'P');
            current.result = value;
            records.push_back(current);
        }
    }
    return records;
}

/// A crypto context with a software-provider key-management context.
struct SoftwareSession
{
    ICryptoStack::Uptr stack;
    ICryptoContext::Uptr ctx;
    std::unique_ptr<IKeyManagementContext> key_mgmt;
};

void OpenSoftwareSession(SoftwareSession& session)
{
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(kControlSocketEndpoint);
    auto stack_result = CreateCryptoStack(stack_config);
    ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
    session.stack = std::move(stack_result.value());

    auto ctx_result = session.stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
    session.ctx = std::move(ctx_result.value());

    KeyManagementContextConfig key_mgmt_config;
    key_mgmt_config.SetProviderType(ProviderType::kSoftware);
    auto key_mgmt_result = session.ctx->CreateKeyManagementContext(key_mgmt_config);
    ASSERT_TRUE(key_mgmt_result.has_value()) << "Failed to create key management context";
    session.key_mgmt = std::move(key_mgmt_result.value());
}

void Digest(ICryptoContext& ctx,
            const std::string& hash_algorithm,
            const std::vector<std::uint8_t>& message,
            std::vector<std::uint8_t>& digest)
{
    HashContextConfig config;
    config.SetAlgorithm(hash_algorithm).SetProviderType(ProviderType::kSoftware);
    auto hash_result = ctx.CreateHashContext(config);
    ASSERT_TRUE(hash_result.has_value()) << "Failed to create hash context for " << hash_algorithm;
    auto& hash = hash_result.value();

    digest.assign(hash->GetDigestSize(), 0U);
    auto written = hash->SingleShot({message.data(), message.size()}, {digest.data(), digest.size()});
    ASSERT_TRUE(written.has_value()) << "Hashing failed";
    ASSERT_EQ(written.value(), digest.size());
}

std::unique_ptr<ISignContext> MakeModeSignContext(ICryptoContext& ctx,
                                                  const std::string& algorithm,
                                                  SignatureInputMode mode,
                                                  const CryptoResourceGuard& key)
{
    SignContextConfig config;
    config.SetAlgorithm(algorithm).SetKey(key).SetInputMode(mode).SetProviderType(ProviderType::kSoftware);
    auto result = ctx.CreateSignContext(config);
    EXPECT_TRUE(result.has_value()) << "Failed to create sign context for " << algorithm;
    return result.has_value() ? std::move(result.value()) : nullptr;
}

std::unique_ptr<IVerifySignatureContext> MakeModeVerifyContext(ICryptoContext& ctx,
                                                               const std::string& algorithm,
                                                               SignatureInputMode mode,
                                                               const CryptoResourceGuard& key)
{
    VerifySignatureContextConfig config;
    config.SetAlgorithm(algorithm).SetKey(key).SetInputMode(mode).SetProviderType(ProviderType::kSoftware);
    auto result = ctx.CreateVerifySignatureContext(config);
    EXPECT_TRUE(result.has_value()) << "Failed to create verify context for " << algorithm;
    return result.has_value() ? std::move(result.value()) : nullptr;
}

/// A refused call returns an error, never a signature or a verdict.
template <typename T>
void ExpectRefused(const score::Result<T>& result)
{
    EXPECT_FALSE(result.has_value()) << "call succeeded but should have been refused";
}

/// Single-shot verification; a call error fails the test.
void SingleShotVerify(IVerifySignatureContext& verify,
                      const std::vector<std::uint8_t>& data,
                      const std::vector<std::uint8_t>& signature,
                      bool expected_valid)
{
    ASSERT_TRUE(verify.Reset()) << "Reset before SingleShot verify failed";
    auto result = verify.SingleShot({data.data(), data.size()}, {signature.data(), signature.size()});
    ASSERT_TRUE(result.has_value()) << "SingleShot verification call failed";
    EXPECT_EQ(result.value(), expected_valid);
}

class EcdsaNistSigVerTest : public ::testing::TestWithParam<EcdsaPairTestData>
{
};

TEST_P(EcdsaNistSigVerTest, VerdictMatchesEveryRecordInBothInputModes)
{
    const auto test_data = GetParam();
    const auto records = LoadSigVerSection(test_data.section, test_data.field_size);
    ASSERT_EQ(records.size(), 15U) << "SigVer.rsp holds 15 records per section";

    SoftwareSession session;
    ASSERT_NO_FATAL_FAILURE(OpenSoftwareSession(session));
    auto& ctx = *session.ctx;

    std::size_t valid_records = 0U;
    for (std::size_t i = 0U; i < records.size(); ++i)
    {
        const auto& record = records[i];
        SCOPED_TRACE(test_data.section + " record " + std::to_string(i) + ": Result = " + record.result);
        ASSERT_EQ(record.signature.size(), 2U * test_data.field_size);
        ASSERT_EQ(record.public_point.size(), 1U + (2U * test_data.field_size));

        ImportKeyParams import_params;
        import_params.SetKeyData(record.public_point.data(), record.public_point.size())
            .SetFormat(FormatType::kRaw)
            .SetAlgorithm(test_data.signature_algorithm)
            .SetPermissions(KeyOperationPermission::kVerify);
        auto key_result = session.key_mgmt->ImportKey(import_params);
        if (!key_result.has_value())
        {
            // A changed Q may leave the curve; refusing that key is a rejection too.
            EXPECT_FALSE(record.expected_valid) << "a valid record's public key was refused";
            continue;
        }
        auto key = std::move(key_result.value());
        valid_records += record.expected_valid ? 1U : 0U;

        auto message_verify =
            MakeModeVerifyContext(ctx, test_data.signature_algorithm, SignatureInputMode::kMessage, key);
        ASSERT_NE(message_verify, nullptr);
        ASSERT_NO_FATAL_FAILURE(
            StreamingVerify(*message_verify, record.message, record.signature, record.expected_valid));
        ASSERT_NO_FATAL_FAILURE(
            SingleShotVerify(*message_verify, record.message, record.signature, record.expected_valid));

        std::vector<std::uint8_t> digest;
        ASSERT_NO_FATAL_FAILURE(Digest(ctx, test_data.hash_algorithm, record.message, digest));
        auto digest_verify =
            MakeModeVerifyContext(ctx, test_data.signature_algorithm, SignatureInputMode::kPrehashed, key);
        ASSERT_NE(digest_verify, nullptr);
        ASSERT_NO_FATAL_FAILURE(StreamingVerify(*digest_verify, digest, record.signature, record.expected_valid));
        ASSERT_NO_FATAL_FAILURE(SingleShotVerify(*digest_verify, digest, record.signature, record.expected_valid));
    }
    EXPECT_EQ(valid_records, 3U) << "SigVer.rsp holds 3 valid records per section";
}

// =========================================================================
// Test 5: signatures carry across input modes; digest length is enforced
// =========================================================================

class EcdsaInputModeTest : public ::testing::TestWithParam<EcdsaPairTestData>
{
  protected:
    void SetUp() override
    {
        const auto& test_data = GetParam();
        ASSERT_NO_FATAL_FAILURE(OpenSoftwareSession(session_));

        GenerateKeyParams key_gen_params;
        key_gen_params.SetAlgorithm(test_data.key_algorithm)
            .SetPermissions(KeyOperationPermission::kSign)
            .SetPublicKeyPermissions(KeyOperationPermission::kVerify);
        auto key_result = session_.key_mgmt->GenerateKey(key_gen_params);
        ASSERT_TRUE(key_result.has_value()) << "Failed to generate " << test_data.key_algorithm;
        key_.emplace(std::move(key_result.value()));

        const auto records = LoadSigVerSection(test_data.section, test_data.field_size);
        ASSERT_FALSE(records.empty());
        message_ = records.front().message;
        ASSERT_NO_FATAL_FAILURE(Digest(*session_.ctx, test_data.hash_algorithm, message_, digest_));
    }

    SoftwareSession session_;
    std::optional<CryptoResourceGuard> key_;
    std::vector<std::uint8_t> message_;
    std::vector<std::uint8_t> digest_;
};

TEST_P(EcdsaInputModeTest, SignatureOverMessageAndOverItsDigestAreInterchangeable)
{
    const auto test_data = GetParam();
    auto& ctx = *session_.ctx;
    const std::size_t signature_size = 2U * test_data.field_size;

    auto message_sign = MakeModeSignContext(ctx, test_data.signature_algorithm, SignatureInputMode::kMessage, *key_);
    ASSERT_NE(message_sign, nullptr);
    auto digest_sign = MakeModeSignContext(ctx, test_data.signature_algorithm, SignatureInputMode::kPrehashed, *key_);
    ASSERT_NE(digest_sign, nullptr);
    auto message_verify =
        MakeModeVerifyContext(ctx, test_data.signature_algorithm, SignatureInputMode::kMessage, *key_);
    ASSERT_NE(message_verify, nullptr);
    auto digest_verify =
        MakeModeVerifyContext(ctx, test_data.signature_algorithm, SignatureInputMode::kPrehashed, *key_);
    ASSERT_NE(digest_verify, nullptr);

    std::vector<std::uint8_t> over_message;
    ASSERT_NO_FATAL_FAILURE(StreamingSign(*message_sign, message_, signature_size, over_message));

    std::vector<std::uint8_t> over_digest(signature_size, 0U);
    ASSERT_TRUE(digest_sign->Reset());
    auto written = digest_sign->SingleShot({digest_.data(), digest_.size()}, {over_digest.data(), over_digest.size()});
    ASSERT_TRUE(written.has_value()) << "SingleShot signing of a digest failed";
    ASSERT_EQ(written.value(), signature_size);

    // Signing a digest is signing the message it was taken from.
    for (const auto* signature : {&over_message, &over_digest})
    {
        ASSERT_NO_FATAL_FAILURE(StreamingVerify(*message_verify, message_, *signature, true));
        ASSERT_NO_FATAL_FAILURE(SingleShotVerify(*digest_verify, digest_, *signature, true));
    }

    std::vector<std::uint8_t> tampered = digest_;
    tampered[0] ^= 0x01U;
    ASSERT_NO_FATAL_FAILURE(SingleShotVerify(*digest_verify, tampered, over_message, false));
    ASSERT_NO_FATAL_FAILURE(StreamingVerify(*digest_verify, tampered, over_digest, false));
}

TEST_P(EcdsaInputModeTest, DigestOfAnyOtherLengthIsRefused)
{
    const auto test_data = GetParam();
    auto& ctx = *session_.ctx;
    const std::size_t signature_size = 2U * test_data.field_size;

    auto digest_sign = MakeModeSignContext(ctx, test_data.signature_algorithm, SignatureInputMode::kPrehashed, *key_);
    ASSERT_NE(digest_sign, nullptr);
    auto digest_verify =
        MakeModeVerifyContext(ctx, test_data.signature_algorithm, SignatureInputMode::kPrehashed, *key_);
    ASSERT_NE(digest_verify, nullptr);

    std::vector<std::uint8_t> valid_signature(signature_size, 0U);
    ASSERT_TRUE(digest_sign->Reset());
    auto signed_digest =
        digest_sign->SingleShot({digest_.data(), digest_.size()}, {valid_signature.data(), valid_signature.size()});
    ASSERT_TRUE(signed_digest.has_value());

    std::vector<std::uint8_t> longer = digest_;
    longer.push_back(0x00U);
    const std::vector<std::vector<std::uint8_t>> wrong_lengths = {
        std::vector<std::uint8_t>(digest_.begin(), digest_.end() - 1),
        longer,
        std::vector<std::uint8_t>{},
    };

    for (const auto& input : wrong_lengths)
    {
        SCOPED_TRACE("digest of " + std::to_string(input.size()) + " bytes, expected " +
                     std::to_string(digest_.size()));
        std::vector<std::uint8_t> signature(signature_size, 0U);

        // Single-shot: an error, never a signature or a verdict.
        ASSERT_TRUE(digest_sign->Reset());
        ExpectRefused(digest_sign->SingleShot({input.data(), input.size()}, {signature.data(), signature.size()}));
        ASSERT_TRUE(digest_verify->Reset());
        ExpectRefused(
            digest_verify->SingleShot({input.data(), input.size()}, {valid_signature.data(), valid_signature.size()}));

        // Streaming: an overlong digest fails at Update, a short one at Finalize.
        const bool overlong = input.size() > digest_.size();
        ASSERT_TRUE(digest_sign->Reset());
        ASSERT_TRUE(digest_sign->Init());
        auto sign_update = digest_sign->Update({input.data(), input.size()});
        if (overlong)
        {
            ExpectRefused(sign_update);
        }
        else
        {
            ASSERT_TRUE(sign_update.has_value());
            ExpectRefused(digest_sign->SignFinalize({signature.data(), signature.size()}));
        }

        ASSERT_TRUE(digest_verify->Reset());
        ASSERT_TRUE(digest_verify->Init());
        auto verify_update = digest_verify->Update({input.data(), input.size()});
        if (overlong)
        {
            ExpectRefused(verify_update);
        }
        else
        {
            ASSERT_TRUE(verify_update.has_value());
            ExpectRefused(digest_verify->VerifyFinalize({valid_signature.data(), valid_signature.size()}));
        }
    }
}

// =========================================================================
// Test Vector Constants
// =========================================================================

// P1363 signature sizes: 2 * field size.
constexpr std::size_t kP256SignatureSize = 64U;
constexpr std::size_t kP384SignatureSize = 96U;
constexpr std::size_t kP521SignatureSize = 132U;

// =========================================================================
// Test Suites
// =========================================================================

// ECDSA is provided only by the OpenSSL (software) provider, so every case pins
// ProviderType::kSoftware. Leaving the provider unset resolves to the daemon's
// DEFAULT provider — currently SoftHSM — which offers neither EC key generation
// nor a signature handler.
INSTANTIATE_TEST_SUITE_P(CurvesOnSoftwareProvider,
                         EcdsaSignVerifyTest,
                         ::testing::Values(
                             EcdsaTestData{
                                 "ECDSA_P256_SHA256_SoftwareProvider",
                                 ProviderType::kSoftware,
                                 "ECDSA-P256",
                                 "ECDSA-P256-SHA256",
                                 kP256SignatureSize,
                                 "P256-SHA256",
                             },
                             EcdsaTestData{
                                 "ECDSA_P384_SHA384_SoftwareProvider",
                                 ProviderType::kSoftware,
                                 "ECDSA-P384",
                                 "ECDSA-P384-SHA384",
                                 kP384SignatureSize,
                                 "P384-SHA384",
                             },
                             EcdsaTestData{
                                 "ECDSA_P384_SHA512_SoftwareProvider",
                                 ProviderType::kSoftware,
                                 "ECDSA-P384",
                                 "ECDSA-P384-SHA512",
                                 kP384SignatureSize,
                                 "P384-SHA512",
                             },
                             EcdsaTestData{
                                 "ECDSA_P521_SHA512_SoftwareProvider",
                                 ProviderType::kSoftware,
                                 "ECDSA-P521",
                                 "ECDSA-P521-SHA512",
                                 kP521SignatureSize,
                                 "P521-SHA512",
                             },
                             // Curve and hash need not match in strength.
                             EcdsaTestData{
                                 "ECDSA_P256_SHA384_SoftwareProvider",
                                 ProviderType::kSoftware,
                                 "ECDSA-P256",
                                 "ECDSA-P256-SHA384",
                                 kP256SignatureSize,
                                 "P256-SHA256",
                             }),
                         [](const testing::TestParamInfo<EcdsaSignVerifyTest::ParamType>& info) {
                             return info.param.test_case_name;
                         });

INSTANTIATE_TEST_SUITE_P(NistVectorsOnSoftwareProvider,
                         KeySlotEcdsaTest,
                         ::testing::Values(
                             KeySlotEcdsaTestData{
                                 "ECDSA_P256_SHA256_KeySlot_SoftwareProvider",
                                 ProviderType::kSoftware,
                                 "ECDSA-P256-SHA256",
                                 kP256SignatureSize,
                                 "P256-SHA256",
                                 "ECDSA_P256_IntegrationTestKey_OpenSSL",
                                 "ECDSA_P256_PublicKeySlot_OpenSSL",
                             },
                             KeySlotEcdsaTestData{
                                 "ECDSA_P384_SHA384_KeySlot_SoftwareProvider",
                                 ProviderType::kSoftware,
                                 "ECDSA-P384-SHA384",
                                 kP384SignatureSize,
                                 "P384-SHA384",
                                 "ECDSA_P384_IntegrationTestKey_OpenSSL",
                                 "ECDSA_P384_PublicKeySlot_OpenSSL",
                             },
                             KeySlotEcdsaTestData{
                                 "ECDSA_P384_SHA512_KeySlot_SoftwareProvider",
                                 ProviderType::kSoftware,
                                 "ECDSA-P384-SHA512",
                                 kP384SignatureSize,
                                 "P384-SHA512",
                                 "ECDSA_P384_SHA512_IntegrationTestKey_OpenSSL",
                                 "ECDSA_P384_SHA512_PublicKeySlot_OpenSSL",
                             },
                             KeySlotEcdsaTestData{
                                 "ECDSA_P521_SHA512_KeySlot_SoftwareProvider",
                                 ProviderType::kSoftware,
                                 "ECDSA-P521-SHA512",
                                 kP521SignatureSize,
                                 "P521-SHA512",
                                 "ECDSA_P521_IntegrationTestKey_OpenSSL",
                                 "ECDSA_P521_PublicKeySlot_OpenSSL",
                             }),
                         [](const testing::TestParamInfo<KeySlotEcdsaTest::ParamType>& info) {
                             return info.param.test_case_name;
                         });

INSTANTIATE_TEST_SUITE_P(PrehashedOnSoftwareProvider,
                         EcdsaPrehashedTest,
                         ::testing::Values(PrehashedEcdsaTestData{"ECDSA_P256_SHA256_Prehashed",
                                                                  "SHA256",
                                                                  "ECDSA-P256-SHA256",
                                                                  kP256SignatureSize,
                                                                  "P256-SHA256",
                                                                  "ECDSA_P256_IntegrationTestKey_OpenSSL"},
                                           PrehashedEcdsaTestData{"ECDSA_P384_SHA384_Prehashed",
                                                                  "SHA384",
                                                                  "ECDSA-P384-SHA384",
                                                                  kP384SignatureSize,
                                                                  "P384-SHA384",
                                                                  "ECDSA_P384_IntegrationTestKey_OpenSSL"},
                                           PrehashedEcdsaTestData{"ECDSA_P521_SHA512_Prehashed",
                                                                  "SHA512",
                                                                  "ECDSA-P521-SHA512",
                                                                  kP521SignatureSize,
                                                                  "P521-SHA512",
                                                                  "ECDSA_P521_IntegrationTestKey_OpenSSL"}),
                         [](const testing::TestParamInfo<EcdsaPrehashedTest::ParamType>& info) {
                             return info.param.test_case_name;
                         });

/// The twelve ECDSA rows of the algorithm catalog: P-256, P-384 and P-521, each
/// with SHA-224, SHA-256, SHA-384 and SHA-512.
const auto kCatalogEcdsaPairs = ::testing::Values(
    EcdsaPairTestData{"P256_SHA224", "[P-256,SHA-224]", "ECDSA-P256", "ECDSA-P256-SHA224", "SHA224", 32U},
    EcdsaPairTestData{"P256_SHA256", "[P-256,SHA-256]", "ECDSA-P256", "ECDSA-P256-SHA256", "SHA256", 32U},
    EcdsaPairTestData{"P256_SHA384", "[P-256,SHA-384]", "ECDSA-P256", "ECDSA-P256-SHA384", "SHA384", 32U},
    EcdsaPairTestData{"P256_SHA512", "[P-256,SHA-512]", "ECDSA-P256", "ECDSA-P256-SHA512", "SHA512", 32U},
    EcdsaPairTestData{"P384_SHA224", "[P-384,SHA-224]", "ECDSA-P384", "ECDSA-P384-SHA224", "SHA224", 48U},
    EcdsaPairTestData{"P384_SHA256", "[P-384,SHA-256]", "ECDSA-P384", "ECDSA-P384-SHA256", "SHA256", 48U},
    EcdsaPairTestData{"P384_SHA384", "[P-384,SHA-384]", "ECDSA-P384", "ECDSA-P384-SHA384", "SHA384", 48U},
    EcdsaPairTestData{"P384_SHA512", "[P-384,SHA-512]", "ECDSA-P384", "ECDSA-P384-SHA512", "SHA512", 48U},
    EcdsaPairTestData{"P521_SHA224", "[P-521,SHA-224]", "ECDSA-P521", "ECDSA-P521-SHA224", "SHA224", 66U},
    EcdsaPairTestData{"P521_SHA256", "[P-521,SHA-256]", "ECDSA-P521", "ECDSA-P521-SHA256", "SHA256", 66U},
    EcdsaPairTestData{"P521_SHA384", "[P-521,SHA-384]", "ECDSA-P521", "ECDSA-P521-SHA384", "SHA384", 66U},
    EcdsaPairTestData{"P521_SHA512", "[P-521,SHA-512]", "ECDSA-P521", "ECDSA-P521-SHA512", "SHA512", 66U});

const auto kPairName = [](const testing::TestParamInfo<EcdsaPairTestData>& info) {
    return info.param.test_case_name;
};

INSTANTIATE_TEST_SUITE_P(CatalogPairsOnSoftwareProvider, EcdsaNistSigVerTest, kCatalogEcdsaPairs, kPairName);
INSTANTIATE_TEST_SUITE_P(CatalogPairsOnSoftwareProvider, EcdsaInputModeTest, kCatalogEcdsaPairs, kPairName);

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
