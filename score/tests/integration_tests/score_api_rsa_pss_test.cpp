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
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/result/result.h"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
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

struct RsaPssVector
{
    std::string_view key_slot;
    std::string_view directory;
    std::string_view algorithm;
    std::size_t message_size;
    std::size_t signature_size;
};

std::string GetTestVectorPath(const RsaPssVector& vector)
{
    const char* directory = std::getenv("TEST_VECTORS_DIR");
    return std::string{directory != nullptr ? directory : "/opt/crypto/share/test_vectors"} + "/rsa/" +
           std::string{vector.directory} + "/";
}

score::Result<CryptoResourceGuard> LoadVerificationKey(ICryptoContext& context,
                                                       IKeyManagementContext& key_management,
                                                       std::string_view key_slot)
{
    auto slot = context.ResolveResource(std::string{key_slot}, ResourceType::kKeySlot);
    if (!slot.has_value())
    {
        return score::Result<CryptoResourceGuard>{score::unexpect, slot.error()};
    }
    return key_management.LoadKey(slot.value());
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

        auto key_result = LoadVerificationKey(*context_, *key_context_, GetParam().key_slot);
        ASSERT_TRUE(key_result.has_value());
        key_ = std::move(key_result.value());

        const auto vector_path = GetTestVectorPath(GetParam());
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

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
