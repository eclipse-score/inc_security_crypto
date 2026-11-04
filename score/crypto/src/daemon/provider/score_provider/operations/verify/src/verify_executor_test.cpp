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

#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/verify_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"

#include <gtest/gtest.h>

namespace score::crypto::daemon::provider::score_provider::operations::verify
{
namespace
{
namespace verify_ops = handler::verify_handler_operations;
constexpr auto kVerifyActor = common::actors::OP_ACTOR_VERIFY_HANDLER;
using common::DaemonErrorCode;
using common::StreamOperationState;

class TestVerifyHandler final : public ScoreVerifyHandler
{
  public:
    TestVerifyHandler() : ScoreVerifyHandler{std::make_unique<VerifyExecutor>(), "test"} {}

    Expected<bool, DaemonErrorCode> FinalizeVerify(score::cpp::span<const std::uint8_t> signature) override
    {
        ++calls;
        received_signature = signature;
        return result;
    }

    Expected<bool, DaemonErrorCode> SingleShotVerify(score::cpp::span<const std::uint8_t>,
                                                     score::cpp::span<const std::uint8_t> signature) override
    {
        return FinalizeVerify(signature);
    }

    Expected<bool, DaemonErrorCode> result{true};
    score::cpp::span<const std::uint8_t> received_signature{};
    unsigned calls{0U};
};

class VerifyExecutorTest : public ::testing::Test
{
  protected:
    TestVerifyHandler handler_;
    const std::uint8_t signature_bytes_[2U]{1U, 2U};
    const score::cpp::span<const std::uint8_t> signature_{signature_bytes_, 2U};

    Expected<common::ResponseParameters, DaemonErrorCode> Finalize(common::RequestParameters request)
    {
        return handler_.Execute({kVerifyActor, verify_ops::VERIFY_FINALIZE}, request);
    }
};

TEST_F(VerifyExecutorTest, ReturnsValidAndInvalidSignatureResults)
{
    for (const bool valid : {true, false})
    {
        handler_.SetOperationState(StreamOperationState::STREAM_ACTIVE);
        handler_.result = valid;
        const auto result = Finalize({signature_});

        ASSERT_TRUE(result.has_value());
        ASSERT_EQ(result.value().size(), 1U);
        EXPECT_EQ(std::get<bool>(result.value()[0]), valid);
        EXPECT_EQ(handler_.received_signature.data(), signature_.data());
        EXPECT_EQ(handler_.received_signature.size(), signature_.size());
        EXPECT_EQ(handler_.GetOperationState(), StreamOperationState::IDLE);
    }
    EXPECT_EQ(handler_.calls, 2U);
}

TEST_F(VerifyExecutorTest, PreservesProviderErrorAndStreamState)
{
    handler_.SetOperationState(StreamOperationState::STREAM_ACTIVE);
    handler_.result = make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    const auto result = Finalize({signature_});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(handler_.GetOperationState(), StreamOperationState::STREAM_ACTIVE);
    EXPECT_EQ(handler_.calls, 1U);
}

TEST_F(VerifyExecutorTest, RejectsMissingSignatureWrongTypeAndExtraData)
{
    std::uint8_t output[2U]{};
    const std::pair<common::RequestParameters, DaemonErrorCode> invalid_requests[]{
        {{}, DaemonErrorCode::kInsufficientParameters},
        {{true}, DaemonErrorCode::kInvalidDataType},
        {{score::cpp::span<std::uint8_t>{output, 2U}}, DaemonErrorCode::kInvalidDataType},
        {{signature_, signature_}, DaemonErrorCode::kInvalidArgument},
    };

    handler_.SetOperationState(StreamOperationState::STREAM_ACTIVE);
    for (const auto& [request, error] : invalid_requests)
    {
        const auto result = Finalize(request);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), error);
        EXPECT_EQ(handler_.GetOperationState(), StreamOperationState::STREAM_ACTIVE);
    }
    EXPECT_EQ(handler_.calls, 0U);
}

TEST_F(VerifyExecutorTest, RejectsFinalizeWithoutActiveStream)
{
    const auto result = Finalize({signature_});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidStreamOperation);
    EXPECT_EQ(handler_.calls, 0U);
}

TEST_F(VerifyExecutorTest, SingleShotReturnsBooleanAndPreservesProviderError)
{
    common::RequestParameters request{signature_, signature_};
    for (const bool valid : {true, false})
    {
        handler_.result = valid;
        const auto result = handler_.Execute({kVerifyActor, verify_ops::VERIFY_SS}, request);
        ASSERT_TRUE(result.has_value());
        ASSERT_EQ(result.value().size(), 1U);
        EXPECT_EQ(std::get<bool>(result.value()[0]), valid);
    }

    handler_.result = make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    const auto result = handler_.Execute({kVerifyActor, verify_ops::VERIFY_SS}, request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(handler_.GetOperationState(), StreamOperationState::IDLE);
}

TEST_F(VerifyExecutorTest, BaseHandlerReportsUnsupportedFinalize)
{
    ScoreVerifyHandler base{std::make_unique<VerifyExecutor>(), "test"};
    base.SetOperationState(StreamOperationState::STREAM_ACTIVE);
    common::RequestParameters request{signature_};
    const auto result = base.Execute({kVerifyActor, verify_ops::VERIFY_FINALIZE}, request);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kUnsupportedOperation);
    EXPECT_EQ(base.GetOperationState(), StreamOperationState::STREAM_ACTIVE);
}
}  // namespace
}  // namespace score::crypto::daemon::provider::score_provider::operations::verify
