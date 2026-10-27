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

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/sign_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/verify_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/provider_openssl.hpp"

namespace common = score::crypto::daemon::common;
namespace key_management = score::crypto::daemon::key_management;
namespace provider = score::crypto::daemon::provider;
namespace handler = score::crypto::daemon::provider::handler;
namespace sign_ops = handler::sign_handler_operations;
namespace verify_ops = handler::verify_handler_operations;

namespace
{

using SignatureInputMode = score::crypto::SignatureInputMode;
using Permission = score::crypto::KeyOperationPermission;

struct SignatureCase
{
    std::string name;
    std::string key_algorithm;
    std::string signature_algorithm;
    SignatureInputMode input_mode;
    std::size_t signature_size;
    std::vector<std::uint8_t> input;
    bool supported{true};
};

std::vector<std::uint8_t> Sha256()
{
    return {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
}

std::vector<std::uint8_t> Sha384()
{
    return {0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
            0x27, 0x2c, 0x32, 0xab, 0x0e, 0xdd, 0x16, 0x31, 0xa8, 0xb6, 0x05, 0xa4, 0x3f, 0xf5, 0xbe, 0xd8,
            0x08, 0x60, 0x72, 0xba, 0x1e, 0x7c, 0xc2, 0x35, 0x8b, 0xae, 0xca, 0x13, 0x4c, 0x82, 0x5a, 0x7a};
}

std::vector<std::uint8_t> Sha512()
{
    return {0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};
}

std::vector<std::uint8_t> Message()
{
    return {'a', 'b', 'c'};
}

std::vector<SignatureCase> SignatureCases()
{
    const auto message = Message();
    const auto sha256 = Sha256();
    const auto sha384 = Sha384();
    const auto sha512 = Sha512();
    std::vector<SignatureCase> cases;

    const auto add = [&cases, &message](std::string name,
                                        std::string key,
                                        std::string signature,
                                        SignatureInputMode mode,
                                        std::size_t size,
                                        std::vector<std::uint8_t> digest = {}) {
        cases.push_back({std::move(name),
                         std::move(key),
                         std::move(signature),
                         mode,
                         size,
                         mode == SignatureInputMode::kMessage ? message : std::move(digest),
                         true});
    };
    add("ECDSA_P256_SHA256_Message", "ECDSA-P256", "ECDSA-P256-SHA256", SignatureInputMode::kMessage, 64U);
    add("ECDSA_P384_SHA384_Message", "ECDSA-P384", "ECDSA-P384-SHA384", SignatureInputMode::kMessage, 96U);
    add("ECDSA_P521_SHA512_Message", "ECDSA-P521", "ECDSA-P521-SHA512", SignatureInputMode::kMessage, 132U);
    add("ECDSA_P256_SHA256_Prehashed", "ECDSA-P256", "ECDSA-P256-SHA256", SignatureInputMode::kPrehashed, 64U, sha256);
    add("ECDSA_P384_SHA384_Prehashed", "ECDSA-P384", "ECDSA-P384-SHA384", SignatureInputMode::kPrehashed, 96U, sha384);
    add("ECDSA_P521_SHA512_Prehashed", "ECDSA-P521", "ECDSA-P521-SHA512", SignatureInputMode::kPrehashed, 132U, sha512);

    for (const auto& [key, size] : {std::pair<std::string, std::size_t>{"RSA-2048", 256U},
                                    std::pair<std::string, std::size_t>{"RSA-3072", 384U},
                                    std::pair<std::string, std::size_t>{"RSA-4096", 512U}})
    {
        add(key + "_SHA256_Message", key, "RSA-PSS-" + key.substr(4) + "-SHA256", SignatureInputMode::kMessage, size);
        add(key + "_SHA256_Prehashed",
            key,
            "RSA-PSS-" + key.substr(4) + "-SHA256",
            SignatureInputMode::kPrehashed,
            size,
            sha256);
        add(key + "_SHA384_Message", key, "RSA-PSS-" + key.substr(4) + "-SHA384", SignatureInputMode::kMessage, size);
        add(key + "_SHA384_Prehashed",
            key,
            "RSA-PSS-" + key.substr(4) + "-SHA384",
            SignatureInputMode::kPrehashed,
            size,
            sha384);
        add(key + "_SHA512_Message", key, "RSA-PSS-" + key.substr(4) + "-SHA512", SignatureInputMode::kMessage, size);
        add(key + "_SHA512_Prehashed",
            key,
            "RSA-PSS-" + key.substr(4) + "-SHA512",
            SignatureInputMode::kPrehashed,
            size,
            sha512);
    }
    add("Ed25519_Message", "Ed25519", "Ed25519", SignatureInputMode::kMessage, 64U);
    auto rejected = SignatureCase{
        "Ed25519_Prehashed_Rejected", "Ed25519", "Ed25519", SignatureInputMode::kPrehashed, 64U, sha256, false};
    cases.push_back(std::move(rejected));
    return cases;
}

class ProviderSignatureTest : public ::testing::TestWithParam<SignatureCase>
{
  protected:
    static void SetUpTestSuite()
    {
        provider_ = std::make_shared<provider::score_provider::openssl::OpenSSL>();
        ASSERT_TRUE(provider_->Initialize(provider::ProviderInitContext{0, "OPENSSL"}));
        key_factory_ = provider_->GetKeyFactory();
        ASSERT_NE(key_factory_, nullptr);
        for (const auto& algorithm :
             {"ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "RSA-2048", "RSA-3072", "RSA-4096", "Ed25519"})
        {
            key_management::KeyGenerationRequest request;
            request.algorithm = algorithm;
            request.permissions = Permission::kSign;
            request.public_key_permissions = Permission::kVerify;
            auto result = key_factory_->GenerateKey(request);
            ASSERT_TRUE(result.has_value()) << algorithm;
            keys_.emplace(algorithm, std::move(result.value()));
        }
    }

    static void TearDownTestSuite()
    {
        keys_.clear();
        key_factory_.reset();
        if (provider_ != nullptr)
        {
            provider_->Shutdown();
            provider_.reset();
        }
    }

    static handler::Handler::Sptr CreateHandler(const std::string& type, const SignatureCase& test_case)
    {
        auto factory = provider_->GetCryptoHandlerFactory();
        EXPECT_NE(factory, nullptr);
        auto result = factory->CreateHandler(type, test_case.signature_algorithm);
        EXPECT_TRUE(result.has_value()) << test_case.name;
        return result.has_value() ? result.value() : nullptr;
    }

    static handler::InitializationParams InitParams(const SignatureCase& test_case,
                                                    const key_management::IKeyHandler& key)
    {
        handler::InitializationParams params;
        params.provider_id = provider_->GetProviderId();
        params.context_node_id = 1U;
        params.key_node_id = 1U;
        params.bound_key_handler = &key;
        params.context_creation_params.resize(7U);
        params.context_creation_params[5U] = common::NoParam{};
        params.context_creation_params[6U] = static_cast<std::uint8_t>(test_case.input_mode);
        return params;
    }

    static common::ResponseParameters Execute(handler::Handler& crypto_handler,
                                              common::OperationActor actor,
                                              common::OperationAction action,
                                              common::RequestParameters request = {})
    {
        common::OperationIdentifier operation{actor, action};
        auto result = crypto_handler.Execute(operation, request);
        EXPECT_TRUE(result.has_value());
        return result.has_value() ? result.value() : common::ResponseParameters{};
    }

    static std::shared_ptr<provider::IProvider> provider_;
    static std::shared_ptr<key_management::IKeyFactory> key_factory_;
    static std::map<std::string, key_management::IKeyHandler::Sptr> keys_;
};

std::shared_ptr<provider::IProvider> ProviderSignatureTest::provider_;
std::shared_ptr<key_management::IKeyFactory> ProviderSignatureTest::key_factory_;
std::map<std::string, key_management::IKeyHandler::Sptr> ProviderSignatureTest::keys_;

TEST_P(ProviderSignatureTest, SignAndVerifySingleShot)
{
    const auto& test_case = GetParam();
    const auto& key = *keys_.at(test_case.key_algorithm);
    auto sign = CreateHandler("SIGN", test_case);
    auto verify = CreateHandler("VERIFY", test_case);
    ASSERT_NE(sign, nullptr);
    ASSERT_NE(verify, nullptr);

    const auto params = InitParams(test_case, key);
    const auto sign_init = sign->InitializeContext(params);
    const auto verify_init = verify->InitializeContext(params);
    if (!test_case.supported)
    {
        EXPECT_FALSE(sign_init.has_value()) << test_case.name;
        EXPECT_FALSE(verify_init.has_value()) << test_case.name;
        return;
    }
    ASSERT_TRUE(sign_init.has_value()) << test_case.name;
    ASSERT_TRUE(verify_init.has_value()) << test_case.name;

    std::vector<std::uint8_t> signature(test_case.signature_size);
    const auto input = score::cpp::span<const std::uint8_t>{test_case.input.data(), test_case.input.size()};
    auto output = score::cpp::span<std::uint8_t>{signature.data(), signature.size()};
    auto signed_response = Execute(*sign, common::actors::OP_ACTOR_SIGN_HANDLER, sign_ops::SIGN_SS, {input, output});
    ASSERT_EQ(std::get<std::uint64_t>(signed_response.at(0)), test_case.signature_size);

    auto signed_input = score::cpp::span<const std::uint8_t>{signature.data(), signature.size()};
    auto verified_response =
        Execute(*verify, common::actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_SS, {input, signed_input});
    ASSERT_TRUE(std::get<bool>(verified_response.at(0))) << test_case.name;
}

TEST_P(ProviderSignatureTest, RejectsTamperedSignatureSingleShot)
{
    const auto& test_case = GetParam();
    if (!test_case.supported)
    {
        GTEST_SKIP() << "Unsupported signature configuration";
    }
    const auto& key = *keys_.at(test_case.key_algorithm);
    auto sign = CreateHandler("SIGN", test_case);
    auto verify = CreateHandler("VERIFY", test_case);
    ASSERT_NE(sign, nullptr);
    ASSERT_NE(verify, nullptr);
    const auto params = InitParams(test_case, key);
    ASSERT_TRUE(sign->InitializeContext(params).has_value());
    ASSERT_TRUE(verify->InitializeContext(params).has_value());
    const auto input = score::cpp::span<const std::uint8_t>{test_case.input.data(), test_case.input.size()};
    std::vector<std::uint8_t> signature(test_case.signature_size);
    auto signed_response = Execute(*sign,
                                   common::actors::OP_ACTOR_SIGN_HANDLER,
                                   sign_ops::SIGN_SS,
                                   {input, score::cpp::span<std::uint8_t>{signature.data(), signature.size()}});
    ASSERT_EQ(std::get<std::uint64_t>(signed_response.at(0)), test_case.signature_size);
    signature[0U] ^= 0x01U;
    ASSERT_TRUE(verify->Reset().has_value());
    auto result = Execute(*verify,
                          common::actors::OP_ACTOR_VERIFY_HANDLER,
                          verify_ops::VERIFY_SS,
                          {input, score::cpp::span<const std::uint8_t>{signature.data(), signature.size()}});
    EXPECT_FALSE(std::get<bool>(result.at(0))) << test_case.name;
}

TEST_P(ProviderSignatureTest, SignAndVerifyStreaming)
{
    const auto& test_case = GetParam();
    const auto& key = *keys_.at(test_case.key_algorithm);
    auto sign = CreateHandler("SIGN", test_case);
    auto verify = CreateHandler("VERIFY", test_case);
    ASSERT_NE(sign, nullptr);
    ASSERT_NE(verify, nullptr);
    const auto params = InitParams(test_case, key);
    const auto sign_init = sign->InitializeContext(params);
    const auto verify_init = verify->InitializeContext(params);
    if (!test_case.supported)
    {
        EXPECT_FALSE(sign_init.has_value()) << test_case.name;
        EXPECT_FALSE(verify_init.has_value()) << test_case.name;
        return;
    }
    ASSERT_TRUE(sign_init.has_value()) << test_case.name;
    ASSERT_TRUE(verify_init.has_value()) << test_case.name;

    const auto input = score::cpp::span<const std::uint8_t>{test_case.input.data(), test_case.input.size()};
    const auto split = test_case.input.size() / 2U;
    ASSERT_TRUE(Execute(*sign, common::actors::OP_ACTOR_SIGN_HANDLER, sign_ops::SIGN_INIT).empty());
    EXPECT_TRUE(Execute(*sign,
                        common::actors::OP_ACTOR_SIGN_HANDLER,
                        sign_ops::SIGN_UPDATE,
                        {score::cpp::span<const std::uint8_t>{input.data(), split}})
                    .empty());
    EXPECT_TRUE(Execute(*sign,
                        common::actors::OP_ACTOR_SIGN_HANDLER,
                        sign_ops::SIGN_UPDATE,
                        {score::cpp::span<const std::uint8_t>{input.data() + split, input.size() - split}})
                    .empty());

    std::vector<std::uint8_t> signature(test_case.signature_size);
    auto sign_response = Execute(*sign,
                                 common::actors::OP_ACTOR_SIGN_HANDLER,
                                 sign_ops::SIGN_FINALIZE,
                                 {score::cpp::span<std::uint8_t>{signature.data(), signature.size()}});
    ASSERT_EQ(std::get<std::uint64_t>(sign_response.at(0)), test_case.signature_size);

    ASSERT_TRUE(Execute(*verify, common::actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_INIT).empty());
    EXPECT_TRUE(Execute(*verify,
                        common::actors::OP_ACTOR_VERIFY_HANDLER,
                        verify_ops::VERIFY_UPDATE,
                        {score::cpp::span<const std::uint8_t>{input.data(), split}})
                    .empty());
    EXPECT_TRUE(Execute(*verify,
                        common::actors::OP_ACTOR_VERIFY_HANDLER,
                        verify_ops::VERIFY_UPDATE,
                        {score::cpp::span<const std::uint8_t>{input.data() + split, input.size() - split}})
                    .empty());
    auto verify_response = Execute(*verify,
                                   common::actors::OP_ACTOR_VERIFY_HANDLER,
                                   verify_ops::VERIFY_FINALIZE,
                                   {score::cpp::span<const std::uint8_t>{signature.data(), signature.size()}});
    EXPECT_TRUE(std::get<bool>(verify_response.at(0))) << test_case.name;
}

TEST_P(ProviderSignatureTest, RejectsTamperedSignatureStreaming)
{
    const auto& test_case = GetParam();
    if (!test_case.supported)
    {
        GTEST_SKIP() << "Unsupported signature configuration";
    }
    const auto& key = *keys_.at(test_case.key_algorithm);
    auto sign = CreateHandler("SIGN", test_case);
    auto verify = CreateHandler("VERIFY", test_case);
    ASSERT_NE(sign, nullptr);
    ASSERT_NE(verify, nullptr);
    const auto params = InitParams(test_case, key);
    ASSERT_TRUE(sign->InitializeContext(params).has_value());
    ASSERT_TRUE(verify->InitializeContext(params).has_value());
    const auto input = score::cpp::span<const std::uint8_t>{test_case.input.data(), test_case.input.size()};
    const auto split = test_case.input.size() / 2U;
    ASSERT_TRUE(Execute(*sign, common::actors::OP_ACTOR_SIGN_HANDLER, sign_ops::SIGN_INIT).empty());
    ASSERT_TRUE(Execute(*sign,
                        common::actors::OP_ACTOR_SIGN_HANDLER,
                        sign_ops::SIGN_UPDATE,
                        {score::cpp::span<const std::uint8_t>{input.data(), split}})
                    .empty());
    ASSERT_TRUE(Execute(*sign,
                        common::actors::OP_ACTOR_SIGN_HANDLER,
                        sign_ops::SIGN_UPDATE,
                        {score::cpp::span<const std::uint8_t>{input.data() + split, input.size() - split}})
                    .empty());
    std::vector<std::uint8_t> signature(test_case.signature_size);
    auto sign_response = Execute(*sign,
                                 common::actors::OP_ACTOR_SIGN_HANDLER,
                                 sign_ops::SIGN_FINALIZE,
                                 {score::cpp::span<std::uint8_t>{signature.data(), signature.size()}});
    ASSERT_EQ(std::get<std::uint64_t>(sign_response.at(0)), test_case.signature_size);
    signature[0U] ^= 0x01U;
    ASSERT_TRUE(Execute(*verify, common::actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_INIT).empty());
    ASSERT_TRUE(Execute(*verify,
                        common::actors::OP_ACTOR_VERIFY_HANDLER,
                        verify_ops::VERIFY_UPDATE,
                        {score::cpp::span<const std::uint8_t>{input.data(), split}})
                    .empty());
    ASSERT_TRUE(Execute(*verify,
                        common::actors::OP_ACTOR_VERIFY_HANDLER,
                        verify_ops::VERIFY_UPDATE,
                        {score::cpp::span<const std::uint8_t>{input.data() + split, input.size() - split}})
                    .empty());
    auto result = Execute(*verify,
                          common::actors::OP_ACTOR_VERIFY_HANDLER,
                          verify_ops::VERIFY_FINALIZE,
                          {score::cpp::span<const std::uint8_t>{signature.data(), signature.size()}});
    EXPECT_FALSE(std::get<bool>(result.at(0))) << test_case.name;
}

TEST_P(ProviderSignatureTest, RejectsEd25519MessagesAboveConfiguredLimit)
{
    const auto& test_case = GetParam();
    if (test_case.key_algorithm != "Ed25519" || !test_case.supported)
    {
        GTEST_SKIP() << "Ed25519-specific message-size limit";
    }

    const auto& key = *keys_.at(test_case.key_algorithm);
    auto sign = CreateHandler("SIGN", test_case);
    auto verify = CreateHandler("VERIFY", test_case);
    ASSERT_NE(sign, nullptr);
    ASSERT_NE(verify, nullptr);
    const auto params = InitParams(test_case, key);
    ASSERT_TRUE(sign->InitializeContext(params).has_value());
    ASSERT_TRUE(verify->InitializeContext(params).has_value());

    std::vector<std::uint8_t> maximum_message(common::kMaxEd25519MessageSize, 0U);
    const auto maximum_input = score::cpp::span<const std::uint8_t>{maximum_message.data(), maximum_message.size()};
    const std::uint8_t extra_byte{0U};
    const auto extra_input = score::cpp::span<const std::uint8_t>{&extra_byte, 1U};
    std::vector<std::uint8_t> oversized_message(common::kMaxEd25519MessageSize + 1U, 0U);
    const auto oversized_input =
        score::cpp::span<const std::uint8_t>{oversized_message.data(), oversized_message.size()};
    const common::OperationIdentifier sign_update_operation{common::actors::OP_ACTOR_SIGN_HANDLER,
                                                            sign_ops::SIGN_UPDATE};
    const common::OperationIdentifier verify_update_operation{common::actors::OP_ACTOR_VERIFY_HANDLER,
                                                              verify_ops::VERIFY_UPDATE};

    ASSERT_TRUE(Execute(*sign, common::actors::OP_ACTOR_SIGN_HANDLER, sign_ops::SIGN_INIT).empty());
    common::RequestParameters sign_max_update_request{maximum_input};
    const auto sign_max_update_result = sign->Execute(sign_update_operation, sign_max_update_request);
    ASSERT_TRUE(sign_max_update_result.has_value());
    common::RequestParameters sign_update_request{extra_input};
    const auto sign_update_result = sign->Execute(sign_update_operation, sign_update_request);
    ASSERT_FALSE(sign_update_result.has_value());
    EXPECT_EQ(sign_update_result.error(), common::DaemonErrorCode::kInvalidArgument);

    ASSERT_TRUE(Execute(*verify, common::actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_INIT).empty());
    common::RequestParameters verify_max_update_request{maximum_input};
    const auto verify_max_update_result = verify->Execute(verify_update_operation, verify_max_update_request);
    ASSERT_TRUE(verify_max_update_result.has_value());
    common::RequestParameters verify_update_request{extra_input};
    const auto verify_update_result = verify->Execute(verify_update_operation, verify_update_request);
    ASSERT_FALSE(verify_update_result.has_value());
    EXPECT_EQ(verify_update_result.error(), common::DaemonErrorCode::kInvalidArgument);

    ASSERT_TRUE(sign->Reset().has_value());
    ASSERT_TRUE(verify->Reset().has_value());
    std::vector<std::uint8_t> signature(test_case.signature_size);
    const auto signature_output = score::cpp::span<std::uint8_t>{signature.data(), signature.size()};
    const common::OperationIdentifier sign_single_shot_operation{common::actors::OP_ACTOR_SIGN_HANDLER,
                                                                 sign_ops::SIGN_SS};
    common::RequestParameters sign_single_shot_request{oversized_input, signature_output};
    const auto sign_single_shot_result = sign->Execute(sign_single_shot_operation, sign_single_shot_request);
    ASSERT_FALSE(sign_single_shot_result.has_value());
    EXPECT_EQ(sign_single_shot_result.error(), common::DaemonErrorCode::kInvalidArgument);

    const auto signature_input = score::cpp::span<const std::uint8_t>{signature.data(), signature.size()};
    const common::OperationIdentifier verify_single_shot_operation{common::actors::OP_ACTOR_VERIFY_HANDLER,
                                                                   verify_ops::VERIFY_SS};
    common::RequestParameters verify_single_shot_request{oversized_input, signature_input};
    const auto verify_single_shot_result = verify->Execute(verify_single_shot_operation, verify_single_shot_request);
    ASSERT_FALSE(verify_single_shot_result.has_value());
    EXPECT_EQ(verify_single_shot_result.error(), common::DaemonErrorCode::kInvalidArgument);
}

INSTANTIATE_TEST_SUITE_P(AllAlgorithms,
                         ProviderSignatureTest,
                         ::testing::ValuesIn(SignatureCases()),
                         [](const ::testing::TestParamInfo<SignatureCase>& info) {
                             auto name = info.param.name;
                             for (auto& character : name)
                             {
                                 if (character == '-')
                                 {
                                     character = '_';
                                 }
                             }
                             return name;
                         });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
