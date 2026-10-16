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

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace score::crypto;

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
    std::string key_algorithm;
    std::string signature_algorithm;
    SignatureInputMode input_mode;
    std::size_t signature_size;
    std::string digest_hex;
    bool supported{true};
};

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

        // ECDSA is covered by score_api_ecdsa_test.cpp. RSA-2048 and RSA-3072
        // use provisioned NIST vector keys; only RSA-4096 has no imported
        // vector key and therefore needs an ephemeral key here. Ed25519 also
        // remains generated-key coverage until provisioned vectors are added.
        for (const auto& algorithm : {"RSA-4096", "Ed25519"})
        {
            GenerateKeyParams key_params;
            key_params.SetAlgorithm(algorithm)
                .SetPermissions(KeyOperationPermission::kSign)
                .SetPublicKeyPermissions(KeyOperationPermission::kVerify);
            auto key_result = key_context_->GenerateKey(key_params);
            ASSERT_TRUE(key_result.has_value()) << algorithm;
            keys_.emplace(algorithm, std::move(key_result.value()));
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
        constexpr std::string_view message_text = "abc";
        const std::vector<std::uint8_t> message(message_text.begin(), message_text.end());
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

        std::vector<std::uint8_t> signature(test_case.signature_size);
        const auto split = input.size() / 2U;
        std::optional<score::Result<std::size_t>> written;
        if (streaming)
        {
            ASSERT_TRUE(sign_context->Init().has_value()) << test_case.name;
            ASSERT_TRUE(sign_context->Update({input.data(), split}).has_value()) << test_case.name;
            ASSERT_TRUE(sign_context->Update({input.data() + split, input.size() - split}).has_value())
                << test_case.name;
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
            ASSERT_TRUE(verify_context->Update({input.data(), split}).has_value()) << test_case.name;
            ASSERT_TRUE(verify_context->Update({input.data() + split, input.size() - split}).has_value())
                << test_case.name;
            verified.emplace(verify_context->VerifyFinalize({signature.data(), signature.size()}));
        }
        else
        {
            verified.emplace(
                verify_context->SingleShot({input.data(), input.size()}, {signature.data(), signature.size()}));
        }
        ASSERT_TRUE(verified->has_value()) << test_case.name;
        EXPECT_TRUE(verified->value()) << test_case.name;

        signature[0U] ^= 0x01U;
        if (streaming)
        {
            ASSERT_TRUE(verify_context->Reset());
            ASSERT_TRUE(verify_context->Init().has_value()) << test_case.name;
            ASSERT_TRUE(verify_context->Update({input.data(), split}).has_value()) << test_case.name;
            ASSERT_TRUE(verify_context->Update({input.data() + split, input.size() - split}).has_value())
                << test_case.name;
            verified.emplace(verify_context->VerifyFinalize({signature.data(), signature.size()}));
        }
        else
        {
            ASSERT_TRUE(verify_context->Reset());
            verified.emplace(
                verify_context->SingleShot({input.data(), input.size()}, {signature.data(), signature.size()}));
        }
        ASSERT_TRUE(verified->has_value()) << test_case.name;
        EXPECT_FALSE(verified->value()) << test_case.name;
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

std::vector<SignatureCase> SignatureCases()
{
    return {
        // ECDSA is covered by score_api_ecdsa_test.cpp. RSA-2048 and RSA-3072
        // are covered by provisioned NIST vector tests.
        {"RSA4096_SHA256_Message", "RSA-4096", "RSA-PSS-4096-SHA256", SignatureInputMode::kMessage, 512U, "", true},
        {"RSA4096_SHA256_Prehashed",
         "RSA-4096",
         "RSA-PSS-4096-SHA256",
         SignatureInputMode::kPrehashed,
         512U,
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         true},
        {"RSA4096_SHA384_Message", "RSA-4096", "RSA-PSS-4096-SHA384", SignatureInputMode::kMessage, 512U, "", true},
        {"RSA4096_SHA384_Prehashed",
         "RSA-4096",
         "RSA-PSS-4096-SHA384",
         SignatureInputMode::kPrehashed,
         512U,
         "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
         true},
        {"RSA4096_SHA512_Message", "RSA-4096", "RSA-PSS-4096-SHA512", SignatureInputMode::kMessage, 512U, "", true},
        {"RSA4096_SHA512_Prehashed",
         "RSA-4096",
         "RSA-PSS-4096-SHA512",
         SignatureInputMode::kPrehashed,
         512U,
         "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
         "454d4423643ce80e2a9ac94fa54ca49f",
         true},

        {"Ed25519_Message", "Ed25519", "Ed25519", SignatureInputMode::kMessage, 64U, "", true},
        {"Ed25519_Prehashed_Rejected",
         "Ed25519",
         "Ed25519",
         SignatureInputMode::kPrehashed,
         64U,
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         false},
    };
}

INSTANTIATE_TEST_SUITE_P(AllAlgorithms,
                         SignatureIntegrationTest,
                         ::testing::ValuesIn(SignatureCases()),
                         [](const ::testing::TestParamInfo<SignatureCase>& info) {
                             return info.param.name;
                         });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
