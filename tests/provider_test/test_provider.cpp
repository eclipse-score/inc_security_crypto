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
#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/data_manager/data_manager.hpp"
#include "score/crypto/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/daemon/provider/i_provider.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/provider_openssl.hpp"
#include "score/crypto/daemon/provider/score_provider/operations/hash/score_hash_handler.hpp"
#include "tests/utility/test_utility.hpp"

namespace common = score::crypto::daemon::common;
namespace provider = score::crypto::daemon::provider;
namespace handler = score::crypto::daemon::provider::handler;
namespace dm = score::crypto::daemon::data_manager;

namespace
{

/**
 * @brief Test fixture for Provider and Hash Operation tests
 */
class ProviderHashTest : public ::testing::Test
{
  protected:
    static void SetUpTestSuite()
    {
        // Create and initialize the OpenSSL provider
        provider_ = std::make_shared<provider::score_provider::openssl::OpenSSL>();
        ASSERT_TRUE(provider_ != nullptr);
        provider::ProviderInitContext ctx{0, "OPENSSL"};  // ID 0, name "OPENSSL"
        ASSERT_TRUE(provider_->Initialize(ctx));
    }

    static void TearDownTestSuite()
    {
        if (provider_)
        {
            provider_->Shutdown();
            provider_.reset();
        }
    }

    static std::shared_ptr<provider::IProvider> provider_;
};

// Static member initialization
std::shared_ptr<provider::IProvider> ProviderHashTest::provider_;

/**
 * @brief Test: Verify provider can be created and initialized
 */
TEST_F(ProviderHashTest, ProviderInitialization)
{
    ASSERT_TRUE(provider_ != nullptr);
    EXPECT_EQ(provider_->GetProviderId(), 0);  // OPENSSL provider ID
}

/**
 * @brief Test: Verify crypto operations can be obtained for SCORE mediator
 */
TEST_F(ProviderHashTest, GetCryptoHandlerFactoryForSCOREMediator)
{
    auto crypto_ops = provider_->GetCryptoHandlerFactory();
    ASSERT_TRUE(crypto_ops != nullptr);
}

/**
 * @brief Test: Verify hash handler can be created
 */
TEST_F(ProviderHashTest, CreateHashHandler)
{
    auto crypto_ops = provider_->GetCryptoHandlerFactory();
    ASSERT_TRUE(crypto_ops != nullptr);

    auto handler_result = crypto_ops->CreateHandler("HASH", "SHA256");
    ASSERT_TRUE(handler_result.has_value()) << "Failed to create handler for HASH/SHA256";
    EXPECT_NE(handler_result.value(), nullptr);
}

/**
 * @brief Test: Perform a single-shot SHA256 hash operation
 *
 * This test demonstrates the complete flow:
 * 1. Get crypto operations from provider via SCORE mediator
 * 2. Create a hash handler for SHA256
 * 3. Initialize the handler
 * 4. Execute a single-shot hash operation
 * 5. Verify the result
 */
TEST_F(ProviderHashTest, PerformSHA256SingleShotHashOperation)
{
    // Step 1: Get crypto handler factory from the provider
    auto crypto_ops = provider_->GetCryptoHandlerFactory();
    ASSERT_TRUE(crypto_ops != nullptr);

    // Step 2: Create the handler
    auto handler_result = crypto_ops->CreateHandler("HASH", "SHA256");
    ASSERT_TRUE(handler_result.has_value()) << "Failed to create handler for HASH/SHA256";
    auto handler = handler_result.value();
    ASSERT_TRUE(handler != nullptr);

    // Step 3: Initialize handler with algorithm configuration
    // Stream context will be created on-demand when START operation is called
    auto init_result = handler->InitializeContext(handler::InitializationParams{});
    ASSERT_TRUE(init_result.has_value());
    EXPECT_TRUE(init_result.has_value());

    // Step 4: Prepare test data
    auto input_buffer = tests::utility::read_bin("tests/test_vectors/hash/input_hello_world.bin");
    ASSERT_FALSE(input_buffer.empty());

    // Create input parameter as VirtualMemoryBufferConst
    common::VirtualMemoryBufferConst inputBuf{input_buffer.data(), input_buffer.size()};

    // Create output buffer for hash result (SHA256 produces 32 bytes)
    constexpr std::size_t kSha256DigestLen{32U};
    std::vector<uint8_t> output_buffer(kSha256DigestLen);
    common::VirtualMemoryBuffer outputBuf{output_buffer.data(), output_buffer.size()};

    // Step 4: Create operation request for single-shot hash
    common::RequestParameters op_request;
    op_request = {inputBuf, outputBuf};

    // Step 4: Execute hash operation
    common::OperationIdentifier op;
    op.operationActor = common::actors::OP_ACTOR_HASH_HANDLER;
    op.operationAction = provider::handler::hash_handler_operations::HASH_SS;
    auto execute_result = handler->Execute(op, op_request);
    ASSERT_TRUE(execute_result.has_value()) << "Execute failed";

    // Step 5: Verify output
    // SHA256("Hello, World!") loaded from test vector file
    const auto expected_hash = tests::utility::read_bin("tests/test_vectors/hash/sha256_hello_world.bin");
    ASSERT_EQ(expected_hash.size(), kSha256DigestLen);
    ASSERT_EQ(output_buffer.size(), expected_hash.size());
    EXPECT_EQ(output_buffer, expected_hash) << "Hash output does not match expected SHA256 hash";
}

/**
 * @brief Test: Perform streaming SHA256 hash operation
 *
 * This test demonstrates streaming hash:
 * 1. Initialize hash stream
 * 2. Update with data in chunks
 * 3. Finalize and get the hash
 */
TEST_F(ProviderHashTest, PerformSHA256StreamingHashOperation)
{
    // Get crypto handler factory
    auto crypto_ops = provider_->GetCryptoHandlerFactory();
    ASSERT_TRUE(crypto_ops != nullptr);

    // Create the handler
    auto handler_result = crypto_ops->CreateHandler("HASH", "SHA256");
    ASSERT_TRUE(handler_result.has_value()) << "Failed to create handler for HASH/SHA256";
    auto handler = handler_result.value();
    ASSERT_TRUE(handler != nullptr);

    // Initialize handler with algorithm selection
    // Stream context will be created automatically when HASH_INIT operation is
    // executed
    auto init_result = handler->InitializeContext(handler::InitializationParams{});
    ASSERT_TRUE(init_result.has_value());
    EXPECT_TRUE(init_result.has_value());

    // Execute HASH_INIT operation to initialize streaming context
    // HASH_INIT operation automatically creates the EVP context and transitions
    // state
    common::OperationIdentifier opId;
    opId.operationActor = common::actors::OP_ACTOR_HASH_HANDLER;
    opId.operationAction = provider::handler::hash_handler_operations::HASH_INIT;

    common::RequestParameters init_op;
    auto init_stream_result = handler->Execute(opId, init_op);
    ASSERT_TRUE(init_stream_result.has_value()) << "HASH_INIT execute failed";

    // Update with first chunk
    const std::string chunk1 = "Hello, ";
    std::vector<uint8_t> chunk1_buffer(chunk1.begin(), chunk1.end());
    common::VirtualMemoryBufferConst chunk1Buf{chunk1_buffer.data(), chunk1_buffer.size()};

    // Update operation
    common::RequestParameters update_op1;
    update_op1 = {chunk1Buf};

    opId.operationActor = common::actors::OP_ACTOR_HASH_HANDLER;
    opId.operationAction = provider::handler::hash_handler_operations::HASH_UPDATE;
    auto update_result1 = handler->Execute(opId, update_op1);
    ASSERT_TRUE(update_result1.has_value()) << "HASH_UPDATE chunk1 failed";

    // Update with second chunk
    const std::string chunk2 = "World!";
    std::vector<uint8_t> chunk2_buffer(chunk2.begin(), chunk2.end());
    common::VirtualMemoryBufferConst chunk2Buf{chunk2_buffer.data(), chunk2_buffer.size()};

    common::RequestParameters update_op2;
    update_op2 = {chunk2Buf};

    opId.operationActor = common::actors::OP_ACTOR_HASH_HANDLER;
    opId.operationAction = provider::handler::hash_handler_operations::HASH_UPDATE;
    auto update_result2 = handler->Execute(opId, update_op2);
    ASSERT_TRUE(update_result2.has_value()) << "HASH_UPDATE chunk2 failed";

    // Finalize hash
    constexpr std::size_t kSha256DigestLen{32U};
    std::vector<uint8_t> output_buffer(kSha256DigestLen);
    common::VirtualMemoryBuffer outputBuf{output_buffer.data(), output_buffer.size()};

    common::RequestParameters finalize_op;
    finalize_op = {outputBuf};

    opId.operationActor = common::actors::OP_ACTOR_HASH_HANDLER;
    opId.operationAction = provider::handler::hash_handler_operations::HASH_FINALIZE;
    auto finalize_result = handler->Execute(opId, finalize_op);
    ASSERT_TRUE(finalize_result.has_value()) << "HASH_FINALIZE failed";

    // Verify output is consistent with single-shot
    const auto expected_hash = tests::utility::read_bin("tests/test_vectors/hash/sha256_hello_world.bin");
    ASSERT_EQ(expected_hash.size(), kSha256DigestLen);
    ASSERT_EQ(output_buffer.size(), expected_hash.size());
    EXPECT_EQ(output_buffer, expected_hash) << "Streaming hash output does not match expected SHA256 hash";
}

/**
 * @brief Test: Verify handler supports multiple hash algorithms
 */
TEST_F(ProviderHashTest, VerifySupportedHashAlgorithms)
{
    auto crypto_ops = provider_->GetCryptoHandlerFactory();
    ASSERT_TRUE(crypto_ops != nullptr);

    // Expected supported algorithms
    std::vector<std::string> expected_algorithms = {"SHA256", "SHA384", "SHA512", "SHA224", "SHA1", "MD5"};
    for (const auto& algo : expected_algorithms)
    {
        auto handler_result = crypto_ops->CreateHandler("HASH", algo);
        EXPECT_TRUE(handler_result.has_value()) << "Algorithm " << algo << " not supported for HASH handler";
    }
}

/**
 * @brief Test: Verify CreateHandler returns error for unsupported handler
 */
TEST_F(ProviderHashTest, CreateHandlerUnsupportedHandler)
{
    auto crypto_ops = provider_->GetCryptoHandlerFactory();
    ASSERT_TRUE(crypto_ops != nullptr);

    auto handler_result = crypto_ops->CreateHandler("UNSUPPORTED_HANDLER", "SHA256");
    EXPECT_FALSE(handler_result.has_value()) << "Should return error for unsupported handler";
}

/**
 * @brief Test: Verify CreateHandler returns error for unsupported algorithm
 */
TEST_F(ProviderHashTest, CreateHandlerUnsupportedAlgorithm)
{
    auto crypto_ops = provider_->GetCryptoHandlerFactory();
    ASSERT_TRUE(crypto_ops != nullptr);

    auto handler_result = crypto_ops->CreateHandler("HASH", "UNSUPPORTED_ALGO");
    EXPECT_FALSE(handler_result.has_value()) << "Should return error for unsupported algorithm";
}

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
