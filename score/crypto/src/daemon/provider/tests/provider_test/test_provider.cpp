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
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/hash/openssl_hash_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/provider_openssl.hpp"
#include "score/tests/utility/test_utility.hpp"

namespace common = score::crypto::daemon::common;
namespace provider = score::crypto::daemon::provider;
namespace handler = score::crypto::daemon::provider::handler;
namespace ops = score::crypto::daemon::provider::handler::hash_handler_operations;

namespace
{

struct HashAlgorithmTestData
{
    const char* algorithm;
    std::size_t digest_size;
    const char* hello_digest_path;
    const char* complete_digest_path;
    const char* empty_digest_path;
    const char* abc_digest_path;
};

struct HashVector
{
    const char* input_path;
    const char* digest_path;
};

common::OperationIdentifier MakeHashOp(const common::OperationAction action)
{
    common::OperationIdentifier operation{};
    operation.operationActor = common::actors::OP_ACTOR_HASH_HANDLER;
    operation.operationAction = action;
    return operation;
}

int FailingDigestUpdate(EVP_MD_CTX* /*context*/, const void* /*data*/, const std::size_t /*size*/)
{
    return 0;
}

class OpenSslProviderEnvironment final : public ::testing::Environment
{
  public:
    void SetUp() override
    {
        provider_ = std::make_shared<provider::score_provider::openssl::OpenSSL>();
        ASSERT_NE(provider_, nullptr);
        provider::ProviderInitContext context{0, "OPENSSL"};
        ASSERT_TRUE(provider_->Initialize(context));
    }

    void TearDown() override
    {
        if (provider_ != nullptr)
        {
            provider_->Shutdown();
            provider_.reset();
        }
    }

    static const std::shared_ptr<provider::IProvider>& GetProvider()
    {
        return provider_;
    }

  private:
    static std::shared_ptr<provider::IProvider> provider_;
};

std::shared_ptr<provider::IProvider> OpenSslProviderEnvironment::provider_;

class ProviderHashTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        provider_ = OpenSslProviderEnvironment::GetProvider();
        ASSERT_NE(provider_, nullptr);
    }

    std::shared_ptr<provider::IProvider> provider_;
};

class ProviderHashAlgorithmTest : public ProviderHashTest, public ::testing::WithParamInterface<HashAlgorithmTestData>
{
};

TEST_F(ProviderHashTest, ProviderInitialization)
{
    ASSERT_NE(provider_, nullptr);
    EXPECT_EQ(provider_->GetProviderId(), 0);
    EXPECT_NE(provider_->GetCryptoHandlerFactory(), nullptr);
}

TEST_F(ProviderHashTest, MigrationTargetMetadata)
{
    EXPECT_TRUE(common::IsRecommendedHashAlgorithm("SHA256"));
    EXPECT_TRUE(common::IsRecommendedHashAlgorithm("SHA384"));
    EXPECT_TRUE(common::IsRecommendedHashAlgorithm("SHA512"));

    EXPECT_FALSE(common::IsRecommendedHashAlgorithm("SHA224"));
    EXPECT_FALSE(common::IsRecommendedHashAlgorithm("SHA1"));
    EXPECT_FALSE(common::IsRecommendedHashAlgorithm("MD5"));
    EXPECT_FALSE(common::IsRecommendedHashAlgorithm("UNSUPPORTED_ALGORITHM"));
    EXPECT_FALSE(common::LookupDigestSize("UNSUPPORTED_ALGORITHM").has_value());
}

TEST_P(ProviderHashAlgorithmTest, SupportsSingleShotStreamingResetAndDigestSize)
{
    const auto& testData = GetParam();
    auto factory = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(factory, nullptr);

    auto handlerResult = factory->CreateHandler("HASH", testData.algorithm);
    ASSERT_TRUE(handlerResult.has_value()) << "Failed to create HASH/" << testData.algorithm;
    auto hashHandler = handlerResult.value();
    ASSERT_NE(hashHandler, nullptr);
    ASSERT_TRUE(hashHandler->InitializeContext(handler::InitializationParams{}).has_value());

    const std::vector<HashVector> vectors{
        {"score/tests/test_vectors/hash/input_hello_world.bin", testData.hello_digest_path},
        {"score/tests/test_vectors/hash/input_complete_data.bin", testData.complete_digest_path},
        {"score/tests/test_vectors/hash/input_empty.bin", testData.empty_digest_path},
        {"score/tests/test_vectors/hash/input_abc.bin", testData.abc_digest_path},
    };

    for (const auto& vector : vectors)
    {
        SCOPED_TRACE(std::string{testData.algorithm} + " / " + vector.input_path);
        const auto input = tests::utility::read_bin(vector.input_path);
        const auto expectedDigest = tests::utility::read_bin(vector.digest_path);
        ASSERT_EQ(expectedDigest.size(), testData.digest_size);

        std::vector<std::uint8_t> output(testData.digest_size, 0U);
        common::RequestParameters request{
            score::cpp::span<const std::uint8_t>{input.data(), input.size()},
            score::cpp::span<std::uint8_t>{output.data(), output.size()},
        };

        const auto result = hashHandler->Execute(MakeHashOp(ops::HASH_SS), request);
        ASSERT_TRUE(result.has_value()) << "Single-shot hash failed";
        ASSERT_EQ(result.value().size(), 1U);
        const auto* bytesWritten = std::get_if<std::uint64_t>(&result.value().front());
        ASSERT_NE(bytesWritten, nullptr);
        EXPECT_EQ(*bytesWritten, testData.digest_size);
        EXPECT_EQ(output, expectedDigest);
    }

    common::RequestParameters digestSizeRequest{};
    const auto digestSizeResult = hashHandler->Execute(MakeHashOp(ops::HASH_GET_DIGEST_SIZE), digestSizeRequest);
    ASSERT_TRUE(digestSizeResult.has_value());
    ASSERT_EQ(digestSizeResult.value().size(), 1U);
    const auto* digestSize = std::get_if<std::uint64_t>(&digestSizeResult.value().front());
    ASSERT_NE(digestSize, nullptr);
    EXPECT_EQ(*digestSize, testData.digest_size);

    common::RequestParameters initRequest{};
    const auto empty = tests::utility::read_bin("score/tests/test_vectors/hash/input_empty.bin");
    const auto expectedEmpty = tests::utility::read_bin(testData.empty_digest_path);
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    common::RequestParameters emptyUpdate{
        score::cpp::span<const std::uint8_t>{empty.data(), empty.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), emptyUpdate).has_value());
    std::vector<std::uint8_t> emptyStreamingOutput(testData.digest_size, 0U);
    common::RequestParameters emptyFinalize{
        score::cpp::span<std::uint8_t>{emptyStreamingOutput.data(), emptyStreamingOutput.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), emptyFinalize).has_value());
    EXPECT_EQ(emptyStreamingOutput, expectedEmpty);

    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    std::vector<std::uint8_t> zeroUpdateOutput(testData.digest_size, 0U);
    common::RequestParameters zeroUpdateFinalize{
        score::cpp::span<std::uint8_t>{zeroUpdateOutput.data(), zeroUpdateOutput.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), zeroUpdateFinalize).has_value());
    EXPECT_EQ(zeroUpdateOutput, expectedEmpty) << "Init followed directly by Finalize must hash empty input";

    const auto hello = tests::utility::read_bin("score/tests/test_vectors/hash/input_hello_world.bin");
    const auto expectedHello = tests::utility::read_bin(testData.hello_digest_path);
    ASSERT_FALSE(hello.empty());
    ASSERT_EQ(expectedHello.size(), testData.digest_size);

    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());

    const auto split = static_cast<std::ptrdiff_t>(hello.size() / 2U);
    const std::vector<std::uint8_t> firstChunk{hello.begin(), hello.begin() + split};
    const std::vector<std::uint8_t> secondChunk{hello.begin() + split, hello.end()};
    common::RequestParameters firstUpdate{
        score::cpp::span<const std::uint8_t>{firstChunk.data(), firstChunk.size()},
    };
    common::RequestParameters secondUpdate{
        score::cpp::span<const std::uint8_t>{secondChunk.data(), secondChunk.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), firstUpdate).has_value());
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), secondUpdate).has_value());

    std::vector<std::uint8_t> streamingOutput(testData.digest_size, 0U);
    common::RequestParameters finalizeRequest{
        score::cpp::span<std::uint8_t>{streamingOutput.data(), streamingOutput.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), finalizeRequest).has_value());
    EXPECT_EQ(streamingOutput, expectedHello);

    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), firstUpdate).has_value());
    common::RequestParameters resetRequest{};
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_RESET), resetRequest).has_value());

    const auto complete = tests::utility::read_bin("score/tests/test_vectors/hash/input_complete_data.bin");
    const auto expectedComplete = tests::utility::read_bin(testData.complete_digest_path);
    ASSERT_FALSE(complete.empty());
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    common::RequestParameters completeUpdate{
        score::cpp::span<const std::uint8_t>{complete.data(), complete.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), completeUpdate).has_value());
    std::vector<std::uint8_t> resetOutput(testData.digest_size, 0U);
    common::RequestParameters resetFinalize{
        score::cpp::span<std::uint8_t>{resetOutput.data(), resetOutput.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), resetFinalize).has_value());
    EXPECT_EQ(resetOutput, expectedComplete);

    std::vector<std::uint8_t> undersizedOutput(testData.digest_size - 1U, 0U);
    common::RequestParameters undersizedRequest{
        score::cpp::span<const std::uint8_t>{hello.data(), hello.size()},
        score::cpp::span<std::uint8_t>{undersizedOutput.data(), undersizedOutput.size()},
    };
    const auto undersizedSingleShot = hashHandler->Execute(MakeHashOp(ops::HASH_SS), undersizedRequest);
    ASSERT_FALSE(undersizedSingleShot.has_value());
    EXPECT_EQ(undersizedSingleShot.error(), common::DaemonErrorCode::kInsufficientBufferSize);

    // An undersized streaming output is a retryable caller error. Finalize
    // must not discard the active digest operation.
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    common::RequestParameters retryUpdate{
        score::cpp::span<const std::uint8_t>{hello.data(), hello.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), retryUpdate).has_value());
    common::RequestParameters undersizedFinalize{
        score::cpp::span<std::uint8_t>{undersizedOutput.data(), undersizedOutput.size()},
    };
    const auto failedFinalize = hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), undersizedFinalize);
    ASSERT_FALSE(failedFinalize.has_value());
    EXPECT_EQ(failedFinalize.error(), common::DaemonErrorCode::kInsufficientBufferSize);

    std::vector<std::uint8_t> retryOutput(testData.digest_size, 0U);
    common::RequestParameters retryFinalize{
        score::cpp::span<std::uint8_t>{retryOutput.data(), retryOutput.size()},
    };
    const auto retryResult = hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), retryFinalize);
    ASSERT_TRUE(retryResult.has_value()) << "Finalize retry failed after an undersized output buffer";
    EXPECT_EQ(retryOutput, expectedHello);
}

TEST_F(ProviderHashTest, RetainsLegacyAlgorithmsForCompatibility)
{
    auto factory = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(factory, nullptr);

    for (const char* algorithm : {"SHA224", "SHA1", "MD5"})
    {
        EXPECT_TRUE(factory->CreateHandler("HASH", algorithm).has_value())
            << "Legacy algorithm unexpectedly removed: " << algorithm;
    }
}

TEST_F(ProviderHashTest, RejectsUnsupportedHandlerAndAlgorithm)
{
    auto factory = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(factory, nullptr);

    EXPECT_FALSE(factory->CreateHandler("UNSUPPORTED_HANDLER", "SHA256").has_value());
    EXPECT_FALSE(factory->CreateHandler("HASH", "UNSUPPORTED_ALGORITHM").has_value());
}

TEST_F(ProviderHashTest, ReportsHashStreamStateViolations)
{
    auto factory = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(factory, nullptr);
    auto handlerResult = factory->CreateHandler("HASH", "SHA256");
    ASSERT_TRUE(handlerResult.has_value());
    auto hashHandler = handlerResult.value();
    ASSERT_TRUE(hashHandler->InitializeContext(handler::InitializationParams{}).has_value());

    const std::array<std::uint8_t, 1U> input{0x42U};
    common::RequestParameters updateRequest{
        score::cpp::span<const std::uint8_t>{input.data(), input.size()},
    };
    const auto updateBeforeInit = hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), updateRequest);
    ASSERT_FALSE(updateBeforeInit.has_value());
    EXPECT_EQ(updateBeforeInit.error(), common::DaemonErrorCode::kStreamNotInitialized);

    std::array<std::uint8_t, 32U> output{};
    common::RequestParameters finalizeRequest{
        score::cpp::span<std::uint8_t>{output.data(), output.size()},
    };
    const auto finalizeBeforeInit = hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), finalizeRequest);
    ASSERT_FALSE(finalizeBeforeInit.has_value());
    EXPECT_EQ(finalizeBeforeInit.error(), common::DaemonErrorCode::kStreamNotInitialized);

    common::RequestParameters initRequest{};
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    EXPECT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value())
        << "Init on an active stream must restart it";
}

TEST_F(ProviderHashTest, RejectsMalformedHashRequestShapesWithoutConsumingStream)
{
    auto factory = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(factory, nullptr);
    auto handlerResult = factory->CreateHandler("HASH", "SHA256");
    ASSERT_TRUE(handlerResult.has_value());
    auto hashHandler = handlerResult.value();
    ASSERT_TRUE(hashHandler->InitializeContext(handler::InitializationParams{}).has_value());

    const std::array<std::uint8_t, 1U> input{0x42U};
    std::array<std::uint8_t, 32U> output{};

    common::RequestParameters invalidInit{std::uint64_t{1U}};
    const auto invalidInitResult = hashHandler->Execute(MakeHashOp(ops::HASH_INIT), invalidInit);
    ASSERT_FALSE(invalidInitResult.has_value());
    EXPECT_EQ(invalidInitResult.error(), common::DaemonErrorCode::kInvalidArgument);

    common::RequestParameters invalidSingleShot{
        score::cpp::span<const std::uint8_t>{input.data(), input.size()},
        score::cpp::span<std::uint8_t>{output.data(), output.size()},
        std::uint64_t{1U},
    };
    const auto invalidSingleShotResult = hashHandler->Execute(MakeHashOp(ops::HASH_SS), invalidSingleShot);
    ASSERT_FALSE(invalidSingleShotResult.has_value());
    EXPECT_EQ(invalidSingleShotResult.error(), common::DaemonErrorCode::kInvalidArgument);

    common::RequestParameters invalidDigestSize{std::uint64_t{1U}};
    const auto invalidDigestSizeResult = hashHandler->Execute(MakeHashOp(ops::HASH_GET_DIGEST_SIZE), invalidDigestSize);
    ASSERT_FALSE(invalidDigestSizeResult.has_value());
    EXPECT_EQ(invalidDigestSizeResult.error(), common::DaemonErrorCode::kInvalidArgument);

    common::RequestParameters initRequest{};
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());

    common::RequestParameters invalidUpdate{
        score::cpp::span<const std::uint8_t>{input.data(), input.size()},
        std::uint64_t{1U},
    };
    const auto invalidUpdateResult = hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), invalidUpdate);
    ASSERT_FALSE(invalidUpdateResult.has_value());
    EXPECT_EQ(invalidUpdateResult.error(), common::DaemonErrorCode::kInvalidArgument);

    common::RequestParameters updateRequest{
        score::cpp::span<const std::uint8_t>{input.data(), input.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), updateRequest).has_value());

    common::RequestParameters invalidReset{std::uint64_t{1U}};
    const auto invalidResetResult = hashHandler->Execute(MakeHashOp(ops::HASH_RESET), invalidReset);
    ASSERT_FALSE(invalidResetResult.has_value());
    EXPECT_EQ(invalidResetResult.error(), common::DaemonErrorCode::kInvalidArgument);

    common::RequestParameters invalidFinalize{
        score::cpp::span<std::uint8_t>{output.data(), output.size()},
        std::uint64_t{1U},
    };
    const auto invalidFinalizeResult = hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), invalidFinalize);
    ASSERT_FALSE(invalidFinalizeResult.has_value());
    EXPECT_EQ(invalidFinalizeResult.error(), common::DaemonErrorCode::kInvalidArgument);

    common::RequestParameters finalizeRequest{
        score::cpp::span<std::uint8_t>{output.data(), output.size()},
    };
    EXPECT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), finalizeRequest).has_value());
}

TEST_F(ProviderHashTest, SupportsIndependentInterleavedHashContexts)
{
    auto factory = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(factory, nullptr);

    auto sha256Result = factory->CreateHandler("HASH", "SHA256");
    auto sha384Result = factory->CreateHandler("HASH", "SHA384");
    ASSERT_TRUE(sha256Result.has_value());
    ASSERT_TRUE(sha384Result.has_value());
    auto sha256 = sha256Result.value();
    auto sha384 = sha384Result.value();
    ASSERT_TRUE(sha256->InitializeContext(handler::InitializationParams{}).has_value());
    ASSERT_TRUE(sha384->InitializeContext(handler::InitializationParams{}).has_value());

    common::RequestParameters initRequest{};
    ASSERT_TRUE(sha256->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    ASSERT_TRUE(sha384->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());

    const auto input = tests::utility::read_bin("score/tests/test_vectors/hash/input_hello_world.bin");
    ASSERT_FALSE(input.empty());
    const auto split = static_cast<std::ptrdiff_t>(input.size() / 2U);
    const std::vector<std::uint8_t> firstChunk{input.begin(), input.begin() + split};
    const std::vector<std::uint8_t> secondChunk{input.begin() + split, input.end()};
    common::RequestParameters firstUpdate{
        score::cpp::span<const std::uint8_t>{firstChunk.data(), firstChunk.size()},
    };
    common::RequestParameters secondUpdate{
        score::cpp::span<const std::uint8_t>{secondChunk.data(), secondChunk.size()},
    };

    ASSERT_TRUE(sha256->Execute(MakeHashOp(ops::HASH_UPDATE), firstUpdate).has_value());
    ASSERT_TRUE(sha384->Execute(MakeHashOp(ops::HASH_UPDATE), firstUpdate).has_value());
    ASSERT_TRUE(sha384->Execute(MakeHashOp(ops::HASH_UPDATE), secondUpdate).has_value());
    ASSERT_TRUE(sha256->Execute(MakeHashOp(ops::HASH_UPDATE), secondUpdate).has_value());

    std::vector<std::uint8_t> sha256Output(32U, 0U);
    std::vector<std::uint8_t> sha384Output(48U, 0U);
    common::RequestParameters sha256Finalize{
        score::cpp::span<std::uint8_t>{sha256Output.data(), sha256Output.size()},
    };
    common::RequestParameters sha384Finalize{
        score::cpp::span<std::uint8_t>{sha384Output.data(), sha384Output.size()},
    };
    ASSERT_TRUE(sha384->Execute(MakeHashOp(ops::HASH_FINALIZE), sha384Finalize).has_value());
    ASSERT_TRUE(sha256->Execute(MakeHashOp(ops::HASH_FINALIZE), sha256Finalize).has_value());

    EXPECT_EQ(sha256Output, tests::utility::read_bin("score/tests/test_vectors/hash/sha256_hello_world.bin"));
    EXPECT_EQ(sha384Output, tests::utility::read_bin("score/tests/test_vectors/hash/sha384_hello_world.bin"));
}

TEST(OpenSslHashHandlerErrorTest, DigestUpdateFailureAbortsStreamAndAllowsReuse)
{
    using HashExecutor = provider::score_provider::operations::hash::HashExecutor;
    using OpenSslHashHandler = provider::score_provider::openssl::handler::OpenSslHashHandler;

    OpenSslHashHandler hashHandler{std::make_unique<HashExecutor>(), "SHA256", &FailingDigestUpdate};
    ASSERT_TRUE(hashHandler.InitializeContext(handler::InitializationParams{}).has_value());

    const std::array<std::uint8_t, 1U> input{0x42U};
    common::RequestParameters initRequest{};
    ASSERT_TRUE(hashHandler.Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());

    common::RequestParameters updateRequest{
        score::cpp::span<const std::uint8_t>{input.data(), input.size()},
    };
    const auto failedUpdate = hashHandler.Execute(MakeHashOp(ops::HASH_UPDATE), updateRequest);
    ASSERT_FALSE(failedUpdate.has_value());
    EXPECT_EQ(failedUpdate.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(hashHandler.GetOperationState(), common::StreamOperationState::IDLE);

    ASSERT_TRUE(hashHandler.Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    std::array<std::uint8_t, 32U> output{};
    common::RequestParameters finalizeRequest{
        score::cpp::span<std::uint8_t>{output.data(), output.size()},
    };
    ASSERT_TRUE(hashHandler.Execute(MakeHashOp(ops::HASH_FINALIZE), finalizeRequest).has_value());
    const std::vector<std::uint8_t> actualDigest{output.begin(), output.end()};
    EXPECT_EQ(actualDigest, tests::utility::read_bin("score/tests/test_vectors/hash/sha256_empty.bin"));
}

INSTANTIATE_TEST_SUITE_P(
    BaselibsMigrationAlgorithms,
    ProviderHashAlgorithmTest,
    ::testing::Values(HashAlgorithmTestData{"SHA256",
                                            32U,
                                            "score/tests/test_vectors/hash/sha256_hello_world.bin",
                                            "score/tests/test_vectors/hash/sha256_complete_data.bin",
                                            "score/tests/test_vectors/hash/sha256_empty.bin",
                                            "score/tests/test_vectors/hash/sha256_abc.bin"},
                      HashAlgorithmTestData{"SHA384",
                                            48U,
                                            "score/tests/test_vectors/hash/sha384_hello_world.bin",
                                            "score/tests/test_vectors/hash/sha384_complete_data.bin",
                                            "score/tests/test_vectors/hash/sha384_empty.bin",
                                            "score/tests/test_vectors/hash/sha384_abc.bin"},
                      HashAlgorithmTestData{"SHA512",
                                            64U,
                                            "score/tests/test_vectors/hash/sha512_hello_world.bin",
                                            "score/tests/test_vectors/hash/sha512_complete_data.bin",
                                            "score/tests/test_vectors/hash/sha512_empty.bin",
                                            "score/tests/test_vectors/hash/sha512_abc.bin"}),
    [](const ::testing::TestParamInfo<HashAlgorithmTestData>& info) {
        return info.param.algorithm;
    });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new OpenSslProviderEnvironment{});
    return RUN_ALL_TESTS();
}
