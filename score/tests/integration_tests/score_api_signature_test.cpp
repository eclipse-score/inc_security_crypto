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

#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_sign_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/span.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace score::crypto;
using tests::utility::read_bin;

namespace
{
#ifdef __QNXNTO__
constexpr auto kControlSocketEndpoint = "unix:///opt/crypto_daemon.sock";
#else
constexpr auto kControlSocketEndpoint = "unix:///tmp/crypto_daemon.sock";
#endif

struct SignatureCase
{
    std::string name;
    std::string key_slot;
    std::string key_algorithm;
    std::string signature_algorithm;
    SignatureInputMode input_mode;
    std::size_t signature_size;
    std::string digest_hex;
    bool supported{true};
};

std::vector<SignatureCase> SignatureCases();

std::string GetTestVectorPath()
{
    const char* directory = std::getenv("TEST_VECTORS_DIR");
    return std::string{directory != nullptr ? directory : "/opt/crypto/share/test_vectors"};
}

std::vector<std::uint8_t> FromHex(std::string_view hex)
{
    std::vector<std::uint8_t> result;
    result.reserve(hex.size() / 2U);
    for (std::size_t i = 0U; i < hex.size(); i += 2U)
    {
        const auto nibble = [](char value) -> std::uint8_t {
            if (value >= '0' && value <= '9')
                return static_cast<std::uint8_t>(value - '0');
            if (value >= 'a' && value <= 'f')
                return static_cast<std::uint8_t>(value - 'a' + 10);
            return static_cast<std::uint8_t>(value - 'A' + 10);
        };
        result.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4U) | nibble(hex[i + 1U])));
    }
    return result;
}

std::unique_ptr<ISignContext> MakeSignContext(ICryptoContext& context,
                                              const SignatureCase& test_case,
                                              const CryptoResourceGuard& key)
{
    SignContextConfig config;
    config.SetAlgorithm(test_case.signature_algorithm).SetKey(key).SetInputMode(test_case.input_mode);
    config.SetProviderType(ProviderType::kSoftware);
    auto result = context.CreateSignContext(config);
    if (!result.has_value())
        return nullptr;
    return std::move(result.value());
}

std::unique_ptr<IVerifySignatureContext> MakeVerifyContext(ICryptoContext& context,
                                                           const SignatureCase& test_case,
                                                           const CryptoResourceGuard& key)
{
    VerifySignatureContextConfig config;
    config.SetAlgorithm(test_case.signature_algorithm).SetKey(key).SetInputMode(test_case.input_mode);
    config.SetProviderType(ProviderType::kSoftware);
    auto result = context.CreateVerifySignatureContext(config);
    if (!result.has_value())
        return nullptr;
    return std::move(result.value());
}

/// Resolves a configured vector key slot and loads its key material.
score::Result<CryptoResourceGuard> LoadKeySlot(ICryptoContext& context,
                                               IKeyManagementContext& key_context,
                                               std::string_view slot_name)
{
    auto slot = context.ResolveResource(std::string{slot_name}, ResourceType::kKeySlot);
    if (!slot.has_value())
    {
        return score::Result<CryptoResourceGuard>{score::unexpect, slot.error()};
    }
    return key_context.LoadKey(slot.value());
}

class SignatureIntegrationTest : public ::testing::TestWithParam<SignatureCase>
{
  protected:
    static void SetUpTestSuite()
    {
        CryptoStackConfig stack_config;
        stack_config.SetConnectionEndpoint(kControlSocketEndpoint);
        auto stack_result = CreateCryptoStack(stack_config);
        ASSERT_TRUE(stack_result.has_value());
        stack_ = std::move(stack_result.value());

        auto context_result = stack_->CreateCryptoContext();
        ASSERT_TRUE(context_result.has_value());
        context_ = std::move(context_result.value());

        KeyManagementContextConfig key_config;
        key_config.SetProviderType(ProviderType::kSoftware);
        auto key_context_result = context_->CreateKeyManagementContext(key_config);
        ASSERT_TRUE(key_context_result.has_value());
        key_context_ = std::move(key_context_result.value());

        for (const auto& test_case : SignatureCases())
        {
            if (keys_.find(test_case.key_algorithm) != keys_.end())
                continue;
            auto key_result = LoadKeySlot(*context_, *key_context_, test_case.key_slot);
            ASSERT_TRUE(key_result.has_value()) << test_case.key_slot;
            keys_.emplace(test_case.key_algorithm, std::move(key_result.value()));
        }
    }

    static void TearDownTestSuite()
    {
        keys_.clear();
        key_context_.reset();
        context_.reset();
        stack_.reset();
    }

    void RunSignAndVerify(const SignatureCase& test_case, bool streaming)
    {
        const auto message = test_case.key_algorithm == "Ed25519"
                                 ? read_bin(GetTestVectorPath() + "/ed25519/RFC8032/message.bin")
                                 : std::vector<std::uint8_t>{'a', 'b', 'c'};
        const auto input =
            test_case.input_mode == SignatureInputMode::kPrehashed ? FromHex(test_case.digest_hex) : message;

        ASSERT_NE(context_, nullptr);
        ASSERT_NE(keys_.find(test_case.key_algorithm), keys_.end());
        auto& context = context_;
        const auto& key = keys_.at(test_case.key_algorithm);

        if (!test_case.supported)
        {
            auto sign_context = MakeSignContext(*context, test_case, key);
            EXPECT_EQ(sign_context, nullptr) << test_case.name;
            return;
        }

        auto sign_context = MakeSignContext(*context, test_case, key);
        ASSERT_NE(sign_context, nullptr) << test_case.name;
        auto verify_context = MakeVerifyContext(*context, test_case, key);
        ASSERT_NE(verify_context, nullptr) << test_case.name;
        EXPECT_EQ(sign_context->GetSignatureSize(), test_case.signature_size);

        if (streaming && test_case.key_algorithm == "Ed25519")
        {
            EXPECT_FALSE(sign_context->Init().has_value()) << test_case.name;
            EXPECT_FALSE(verify_context->Init().has_value()) << test_case.name;
            return;
        }

        std::vector<std::uint8_t> signature(test_case.signature_size);
        std::optional<score::Result<std::size_t>> written;
        if (streaming)
        {
            ASSERT_TRUE(sign_context->Init().has_value()) << test_case.name;
            ASSERT_TRUE(sign_context->Update({input.data(), input.size()}).has_value()) << test_case.name;
            written.emplace(sign_context->SignFinalize({signature.data(), signature.size()}));
        }
        else
        {
            written.emplace(
                sign_context->SingleShot({input.data(), input.size()}, {signature.data(), signature.size()}));
        }
        ASSERT_TRUE(written->has_value()) << test_case.name;
        EXPECT_EQ(written->value(), test_case.signature_size);

        std::optional<score::Result<bool>> verified;
        if (streaming)
        {
            ASSERT_TRUE(verify_context->Init().has_value()) << test_case.name;
            ASSERT_TRUE(verify_context->Update({input.data(), input.size()}).has_value()) << test_case.name;
            verified.emplace(verify_context->VerifyFinalize({signature.data(), signature.size()}));
        }
        else
        {
            verified.emplace(
                verify_context->SingleShot({input.data(), input.size()}, {signature.data(), signature.size()}));
        }
        ASSERT_TRUE(verified->has_value()) << test_case.name;
        EXPECT_TRUE(verified->value()) << test_case.name;
    }

    void RunRejectsTamperedSignature(const SignatureCase& test_case, bool streaming)
    {
        const auto message = test_case.key_algorithm == "Ed25519"
                                 ? read_bin(GetTestVectorPath() + "/ed25519/RFC8032/message.bin")
                                 : std::vector<std::uint8_t>{'a', 'b', 'c'};
        const auto input =
            test_case.input_mode == SignatureInputMode::kPrehashed ? FromHex(test_case.digest_hex) : message;
        ASSERT_NE(context_, nullptr);
        ASSERT_NE(keys_.find(test_case.key_algorithm), keys_.end());
        const auto& key = keys_.at(test_case.key_algorithm);
        auto sign_context = MakeSignContext(*context_, test_case, key);
        auto verify_context = MakeVerifyContext(*context_, test_case, key);
        if (!test_case.supported)
        {
            EXPECT_EQ(sign_context, nullptr) << test_case.name;
            EXPECT_EQ(verify_context, nullptr) << test_case.name;
            return;
        }
        ASSERT_NE(sign_context, nullptr) << test_case.name;
        ASSERT_NE(verify_context, nullptr) << test_case.name;

        std::vector<std::uint8_t> signature(test_case.signature_size);
        if (streaming)
        {
            ASSERT_TRUE(sign_context->Init().has_value());
            ASSERT_TRUE(sign_context->Update({input.data(), input.size()}).has_value());
            ASSERT_TRUE(sign_context->SignFinalize({signature.data(), signature.size()}).has_value());
            signature[0U] ^= 0x01U;
            ASSERT_TRUE(verify_context->Init().has_value());
            ASSERT_TRUE(verify_context->Update({input.data(), input.size()}).has_value());
            auto result = verify_context->VerifyFinalize({signature.data(), signature.size()});
            ASSERT_TRUE(result.has_value()) << test_case.name;
            EXPECT_FALSE(result.value()) << test_case.name;
        }
        else
        {
            ASSERT_TRUE(sign_context->SingleShot({input.data(), input.size()}, {signature.data(), signature.size()})
                            .has_value());
            signature[0U] ^= 0x01U;
            auto result =
                verify_context->SingleShot({input.data(), input.size()}, {signature.data(), signature.size()});
            ASSERT_TRUE(result.has_value()) << test_case.name;
            EXPECT_FALSE(result.value()) << test_case.name;
        }
    }

    /// The empty message is a valid input (RFC 8032 has a zero-byte Ed25519 vector). Test single-shot
    /// for Ed25519, and streaming paths for algorithms that support them.
    void RunEmptyMessage(const SignatureCase& test_case)
    {
        ASSERT_NE(context_, nullptr);
        ASSERT_NE(keys_.find(test_case.key_algorithm), keys_.end());
        const auto& key = keys_.at(test_case.key_algorithm);
        auto sign_context = MakeSignContext(*context_, test_case, key);
        auto verify_context = MakeVerifyContext(*context_, test_case, key);
        ASSERT_NE(sign_context, nullptr) << test_case.name;
        ASSERT_NE(verify_context, nullptr) << test_case.name;

        const score::cpp::span<const std::uint8_t> empty{};

        // Single-shot sign.
        std::vector<std::uint8_t> ss_signature(test_case.signature_size);
        auto ss_written = sign_context->SingleShot(empty, {ss_signature.data(), ss_signature.size()});
        ASSERT_TRUE(ss_written.has_value()) << test_case.name;
        EXPECT_EQ(ss_written.value(), test_case.signature_size);

        if (test_case.key_algorithm == "Ed25519")
        {
            const score::cpp::span<const std::uint8_t> signature_span{ss_signature.data(), ss_signature.size()};
            auto verified = verify_context->SingleShot(empty, signature_span);
            ASSERT_TRUE(verified.has_value()) << test_case.name;
            EXPECT_TRUE(verified.value()) << test_case.name;

            ss_signature[0U] ^= 0x01U;
            auto tampered = verify_context->SingleShot(empty, {ss_signature.data(), ss_signature.size()});
            ASSERT_TRUE(tampered.has_value()) << test_case.name;
            EXPECT_FALSE(tampered.value()) << test_case.name;
            return;
        }

        // Streaming sign: Init -> Update(empty) -> Finalize.
        std::vector<std::uint8_t> update_signature(test_case.signature_size);
        ASSERT_TRUE(sign_context->Init().has_value()) << test_case.name;
        ASSERT_TRUE(sign_context->Update(empty).has_value()) << test_case.name;
        ASSERT_TRUE(sign_context->SignFinalize({update_signature.data(), update_signature.size()}).has_value())
            << test_case.name;

        // Streaming sign: Init -> Finalize (no Update).
        std::vector<std::uint8_t> finalize_signature(test_case.signature_size);
        ASSERT_TRUE(sign_context->Init().has_value()) << test_case.name;
        ASSERT_TRUE(sign_context->SignFinalize({finalize_signature.data(), finalize_signature.size()}).has_value())
            << test_case.name;

        for (const auto* signature : {&ss_signature, &update_signature, &finalize_signature})
        {
            const score::cpp::span<const std::uint8_t> signature_span{signature->data(), signature->size()};

            auto ss_verified = verify_context->SingleShot(empty, signature_span);
            ASSERT_TRUE(ss_verified.has_value()) << test_case.name;
            EXPECT_TRUE(ss_verified.value()) << test_case.name;

            ASSERT_TRUE(verify_context->Init().has_value()) << test_case.name;
            ASSERT_TRUE(verify_context->Update(empty).has_value()) << test_case.name;
            auto update_verified = verify_context->VerifyFinalize(signature_span);
            ASSERT_TRUE(update_verified.has_value()) << test_case.name;
            EXPECT_TRUE(update_verified.value()) << test_case.name;

            ASSERT_TRUE(verify_context->Init().has_value()) << test_case.name;
            auto finalize_verified = verify_context->VerifyFinalize(signature_span);
            ASSERT_TRUE(finalize_verified.has_value()) << test_case.name;
            EXPECT_TRUE(finalize_verified.value()) << test_case.name;
        }

        // A tampered signature must still be rejected for the empty message.
        ss_signature[0U] ^= 0x01U;
        auto tampered = verify_context->SingleShot(empty, {ss_signature.data(), ss_signature.size()});
        ASSERT_TRUE(tampered.has_value()) << test_case.name;
        EXPECT_FALSE(tampered.value()) << test_case.name;
    }

    /// A digest is never empty, so zero-length input in prehashed mode must be rejected on both the
    /// sign and verify side, for single-shot and streaming (Update(empty) and Init -> Finalize).
    void RunRejectsEmptyPrehashed(const SignatureCase& test_case)
    {
        ASSERT_NE(context_, nullptr);
        ASSERT_NE(keys_.find(test_case.key_algorithm), keys_.end());
        const auto& key = keys_.at(test_case.key_algorithm);
        auto sign_context = MakeSignContext(*context_, test_case, key);
        auto verify_context = MakeVerifyContext(*context_, test_case, key);
        ASSERT_NE(sign_context, nullptr) << test_case.name;
        ASSERT_NE(verify_context, nullptr) << test_case.name;

        const score::cpp::span<const std::uint8_t> empty{};
        std::vector<std::uint8_t> signature(test_case.signature_size);
        const score::cpp::span<std::uint8_t> signature_out{signature.data(), signature.size()};
        const score::cpp::span<const std::uint8_t> signature_in{signature.data(), signature.size()};

        // Single-shot.
        EXPECT_FALSE(sign_context->SingleShot(empty, signature_out).has_value()) << test_case.name;
        EXPECT_FALSE(verify_context->SingleShot(empty, signature_in).has_value()) << test_case.name;

        // Streaming: Init -> Update(empty) -> Finalize.
        ASSERT_TRUE(sign_context->Init().has_value()) << test_case.name;
        ASSERT_TRUE(sign_context->Update(empty).has_value()) << test_case.name;
        EXPECT_FALSE(sign_context->SignFinalize(signature_out).has_value()) << test_case.name;
        ASSERT_TRUE(verify_context->Init().has_value()) << test_case.name;
        ASSERT_TRUE(verify_context->Update(empty).has_value()) << test_case.name;
        EXPECT_FALSE(verify_context->VerifyFinalize(signature_in).has_value()) << test_case.name;

        // Streaming: Init -> Finalize (no Update).
        ASSERT_TRUE(sign_context->Init().has_value()) << test_case.name;
        EXPECT_FALSE(sign_context->SignFinalize(signature_out).has_value()) << test_case.name;
        ASSERT_TRUE(verify_context->Init().has_value()) << test_case.name;
        EXPECT_FALSE(verify_context->VerifyFinalize(signature_in).has_value()) << test_case.name;
    }

    void RunEd25519KnownAnswer(const SignatureCase& test_case)
    {
        ASSERT_EQ(test_case.key_algorithm, "Ed25519");
        ASSERT_NE(context_, nullptr);
        ASSERT_NE(keys_.find(test_case.key_algorithm), keys_.end());

        const auto message = read_bin(GetTestVectorPath() + "/ed25519/RFC8032/message.bin");
        const auto expected = read_bin(GetTestVectorPath() + "/ed25519/RFC8032/signature.bin");
        const auto& key = keys_.at(test_case.key_algorithm);
        auto sign_context = MakeSignContext(*context_, test_case, key);
        ASSERT_NE(sign_context, nullptr);
        ASSERT_EQ(expected.size(), test_case.signature_size);

        std::vector<std::uint8_t> signature(test_case.signature_size);
        auto result = sign_context->SingleShot({message.data(), message.size()}, {signature.data(), signature.size()});
        ASSERT_TRUE(result.has_value());
        ASSERT_EQ(result.value(), expected.size());
        EXPECT_EQ(signature, expected);
    }

    static ICryptoStack::Uptr stack_;
    static ICryptoContext::Uptr context_;
    static IKeyManagementContext::Uptr key_context_;
    static std::map<std::string, CryptoResourceGuard> keys_;
};

ICryptoStack::Uptr SignatureIntegrationTest::stack_;
ICryptoContext::Uptr SignatureIntegrationTest::context_;
IKeyManagementContext::Uptr SignatureIntegrationTest::key_context_;
std::map<std::string, CryptoResourceGuard> SignatureIntegrationTest::keys_;

TEST_P(SignatureIntegrationTest, SignAndVerifyStreaming)
{
    RunSignAndVerify(GetParam(), true);
}

TEST_P(SignatureIntegrationTest, SignAndVerifySS)
{
    RunSignAndVerify(GetParam(), false);
}

TEST_P(SignatureIntegrationTest, RejectsTamperedSignatureStreaming)
{
    if (GetParam().key_algorithm == "Ed25519")
    {
        GTEST_SKIP() << "Ed25519 does not support streaming signatures";
    }
    RunRejectsTamperedSignature(GetParam(), true);
}

TEST_P(SignatureIntegrationTest, RejectsTamperedSignatureSS)
{
    RunRejectsTamperedSignature(GetParam(), false);
}

TEST_P(SignatureIntegrationTest, SignAndVerifyEmptyMessage)
{
    const auto& test_case = GetParam();
    if (!test_case.supported)
    {
        GTEST_SKIP() << test_case.name << ": configuration is unsupported (expected to be rejected)";
    }
    if (test_case.input_mode != SignatureInputMode::kMessage)
    {
        GTEST_SKIP() << test_case.name << ": prehashed input cannot be empty (see RejectsEmptyPrehashedInput)";
    }
    RunEmptyMessage(test_case);
}

TEST_P(SignatureIntegrationTest, RejectsEmptyPrehashedInput)
{
    const auto& test_case = GetParam();
    if (!test_case.supported)
    {
        GTEST_SKIP() << test_case.name << ": configuration is unsupported (expected to be rejected)";
    }
    if (test_case.input_mode != SignatureInputMode::kPrehashed)
    {
        GTEST_SKIP() << test_case.name << ": message mode accepts empty input (see SignAndVerifyEmptyMessage)";
    }
    RunRejectsEmptyPrehashed(test_case);
}

class Ed25519SignatureTest : public SignatureIntegrationTest
{
};

TEST_P(Ed25519SignatureTest, RejectsStreaming)
{
    const auto& test_case = GetParam();
    ASSERT_NE(context_, nullptr);
    const auto& key = keys_.at(test_case.key_algorithm);
    auto sign_context = MakeSignContext(*context_, test_case, key);
    auto verify_context = MakeVerifyContext(*context_, test_case, key);
    ASSERT_NE(sign_context, nullptr);
    ASSERT_NE(verify_context, nullptr);
    EXPECT_FALSE(sign_context->Init().has_value()) << test_case.name;
    EXPECT_FALSE(verify_context->Init().has_value()) << test_case.name;
}

TEST_P(Ed25519SignatureTest, GeneratesExpectedSignatureSS)
{
    RunEd25519KnownAnswer(GetParam());
}

std::vector<SignatureCase> SignatureCases()
{
    // Aggregate field order: name, key_slot, key_algorithm, signature_algorithm, input_mode,
    // signature_size, digest_hex, supported.
    return {
        {"RSA4096_SHA256_Message",
         "RSA4096_PSS_NIST_IntegrationTestKey_OpenSSL",
         "RSA-4096",
         "RSA-PSS-4096-SHA256",
         SignatureInputMode::kMessage,
         512U,
         "",
         true},
        {"RSA4096_SHA256_Prehashed",
         "RSA4096_PSS_NIST_IntegrationTestKey_OpenSSL",
         "RSA-4096",
         "RSA-PSS-4096-SHA256",
         SignatureInputMode::kPrehashed,
         512U,
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         true},
        {"RSA4096_SHA384_Message",
         "RSA4096_PSS_NIST_IntegrationTestKey_OpenSSL",
         "RSA-4096",
         "RSA-PSS-4096-SHA384",
         SignatureInputMode::kMessage,
         512U,
         "",
         true},
        {"RSA4096_SHA384_Prehashed",
         "RSA4096_PSS_NIST_IntegrationTestKey_OpenSSL",
         "RSA-4096",
         "RSA-PSS-4096-SHA384",
         SignatureInputMode::kPrehashed,
         512U,
         "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
         true},
        {"RSA4096_SHA512_Message",
         "RSA4096_PSS_NIST_IntegrationTestKey_OpenSSL",
         "RSA-4096",
         "RSA-PSS-4096-SHA512",
         SignatureInputMode::kMessage,
         512U,
         "",
         true},
        {"RSA4096_SHA512_Prehashed",
         "RSA4096_PSS_NIST_IntegrationTestKey_OpenSSL",
         "RSA-4096",
         "RSA-PSS-4096-SHA512",
         SignatureInputMode::kPrehashed,
         512U,
         "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
         "454d4423643ce80e2a9ac94fa54ca49f",
         true},

        {"Ed25519_Message",
         "Ed25519_RFC8032_IntegrationTestKey_OpenSSL",
         "Ed25519",
         "Ed25519",
         SignatureInputMode::kMessage,
         64U,
         "",
         true},
        {"Ed25519_Prehashed_Rejected",
         "Ed25519_RFC8032_IntegrationTestKey_OpenSSL",
         "Ed25519",
         "Ed25519",
         SignatureInputMode::kPrehashed,
         64U,
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         false},
    };
}

struct RsaPssVector
{
    std::string_view key_slot;
    std::string_view directory;
    std::string_view algorithm;
    std::size_t message_size;
    std::size_t signature_size;
};

std::string GetRsaPssVectorPath(const RsaPssVector& vector)
{
    return GetTestVectorPath() + "/rsa/" + std::string{vector.directory} + "/";
}

class RsaPssVectorTest : public ::testing::TestWithParam<RsaPssVector>
{
  protected:
    void SetUp() override
    {
        CryptoStackConfig stack_config;
        stack_config.SetConnectionEndpoint(kControlSocketEndpoint);
        auto stack_result = CreateCryptoStack(stack_config);
        ASSERT_TRUE(stack_result.has_value());
        stack_ = std::move(stack_result.value());

        auto context_result = stack_->CreateCryptoContext();
        ASSERT_TRUE(context_result.has_value());
        context_ = std::move(context_result.value());

        KeyManagementContextConfig key_config;
        key_config.SetProviderType(ProviderType::kSoftware);
        auto key_context_result = context_->CreateKeyManagementContext(key_config);
        ASSERT_TRUE(key_context_result.has_value());
        key_context_ = std::move(key_context_result.value());

        auto key_result = LoadKeySlot(*context_, *key_context_, GetParam().key_slot);
        ASSERT_TRUE(key_result.has_value());
        key_ = std::move(key_result.value());

        const auto vector_path = GetRsaPssVectorPath(GetParam());
        message_ = read_bin(vector_path + "message.bin");
        signature_ = read_bin(vector_path + "signature.bin");
        ASSERT_EQ(message_.size(), GetParam().message_size);
        ASSERT_EQ(signature_.size(), GetParam().signature_size);
    }

    void TearDown() override
    {
        if (key_.has_value())
        {
            const auto release_result = key_->Release();
            EXPECT_TRUE(release_result.has_value());
        }
        key_context_.reset();
        context_.reset();
        stack_.reset();
    }

    ICryptoStack::Uptr stack_;
    ICryptoContext::Uptr context_;
    IKeyManagementContext::Uptr key_context_;
    std::optional<CryptoResourceGuard> key_;
    std::vector<std::uint8_t> message_;
    std::vector<std::uint8_t> signature_;
};

TEST_P(RsaPssVectorTest, VerifiesNistSignatureSingleShotAndRejectsTampering)
{
    VerifySignatureContextConfig config;
    config.SetAlgorithm(std::string{GetParam().algorithm}).SetKey(*key_).SetProviderType(ProviderType::kSoftware);
    auto verify_result = context_->CreateVerifySignatureContext(config);
    ASSERT_TRUE(verify_result.has_value());
    auto verify = std::move(verify_result.value());

    auto valid = verify->SingleShot({message_.data(), message_.size()}, {signature_.data(), signature_.size()});
    ASSERT_TRUE(valid.has_value());
    EXPECT_TRUE(valid.value());

    signature_[0U] ^= 0x01U;
    ASSERT_TRUE(verify->Reset());
    auto invalid = verify->SingleShot({message_.data(), message_.size()}, {signature_.data(), signature_.size()});
    ASSERT_TRUE(invalid.has_value());
    EXPECT_FALSE(invalid.value());
}

TEST_P(RsaPssVectorTest, VerifiesNistSignatureStreaming)
{
    VerifySignatureContextConfig config;
    config.SetAlgorithm(std::string{GetParam().algorithm}).SetKey(*key_).SetProviderType(ProviderType::kSoftware);
    auto verify_result = context_->CreateVerifySignatureContext(config);
    ASSERT_TRUE(verify_result.has_value());
    auto verify = std::move(verify_result.value());

    ASSERT_TRUE(verify->Init());
    const auto split = message_.size() / 2U;
    ASSERT_TRUE(verify->Update({message_.data(), split}));
    ASSERT_TRUE(verify->Update({message_.data() + split, message_.size() - split}));
    auto valid = verify->VerifyFinalize({signature_.data(), signature_.size()});
    ASSERT_TRUE(valid.has_value());
    EXPECT_TRUE(valid.value());
}

TEST_P(RsaPssVectorTest, RejectsTamperedSignatureStreaming)
{
    VerifySignatureContextConfig config;
    config.SetAlgorithm(std::string{GetParam().algorithm}).SetKey(*key_).SetProviderType(ProviderType::kSoftware);
    auto verify_result = context_->CreateVerifySignatureContext(config);
    ASSERT_TRUE(verify_result.has_value());
    auto verify = std::move(verify_result.value());

    signature_[0U] ^= 0x01U;
    ASSERT_TRUE(verify->Init());
    const auto split = message_.size() / 2U;
    ASSERT_TRUE(verify->Update({message_.data(), split}));
    ASSERT_TRUE(verify->Update({message_.data() + split, message_.size() - split}));
    auto invalid = verify->VerifyFinalize({signature_.data(), signature_.size()});
    ASSERT_TRUE(invalid.has_value());
    EXPECT_FALSE(invalid.value());
}

INSTANTIATE_TEST_SUITE_P(NistVectors,
                         RsaPssVectorTest,
                         ::testing::Values(RsaPssVector{"RSA_PSS_2048_SHA256_PublicKeySlot_OpenSSL",
                                                        "RSA2048-SHA256-Positive",
                                                        "RSA-PSS-2048-SHA256",
                                                        128U,
                                                        256U},
                                           RsaPssVector{"RSA_PSS_3072_SHA384_PublicKeySlot_OpenSSL",
                                                        "RSA3072-SHA384-Positive",
                                                        "RSA-PSS-3072-SHA384",
                                                        128U,
                                                        384U}));

INSTANTIATE_TEST_SUITE_P(AllAlgorithms,
                         SignatureIntegrationTest,
                         ::testing::ValuesIn(SignatureCases()),
                         [](const ::testing::TestParamInfo<SignatureCase>& info) {
                             return info.param.name;
                         });

INSTANTIATE_TEST_SUITE_P(Ed25519,
                         Ed25519SignatureTest,
                         ::testing::Values(SignatureCases().at(6U)),
                         [](const ::testing::TestParamInfo<SignatureCase>& info) {
                             return info.param.name;
                         });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
