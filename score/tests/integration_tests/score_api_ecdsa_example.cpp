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

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_sign_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/result/result.h"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
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
// NIST FIPS 186-4 CAVP vectors
// =========================================================================

const std::string kEcdsaVectorRoot = "/opt/crypto/tests/test_vectors/ecdsa/";

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
    const std::string dir = kEcdsaVectorRoot + curve_dir + "/";

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
    stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");

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
    stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");

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
                                 "ECDSA_P521_SHA512_SoftwareProvider",
                                 ProviderType::kSoftware,
                                 "ECDSA-P521",
                                 "ECDSA-P521-SHA512",
                                 kP521SignatureSize,
                                 "P521-SHA512",
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

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
