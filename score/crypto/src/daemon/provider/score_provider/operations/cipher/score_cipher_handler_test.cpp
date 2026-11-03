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

#include "score/crypto/src/daemon/provider/score_provider/operations/cipher/score_cipher_handler.hpp"

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/cipher_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/cipher/cipher_executor.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <variant>

namespace score::crypto::daemon::provider::score_provider::operations::cipher
{
namespace
{

using common::DaemonErrorCode;
using common::RequestParameters;
using common::StreamOperationState;
namespace actors = ::score::crypto::daemon::common::actors;
namespace cipher_ops = ::score::crypto::daemon::provider::handler::cipher_handler_operations;

constexpr common::OperationIdentifier kGetMaxOutputSize{actors::OP_ACTOR_CIPHER_HANDLER,
                                                        cipher_ops::CIPHER_GET_MAX_OUTPUT_SIZE};
constexpr std::uint64_t kAesBlockSize = 16U;

class ScoreCipherHandlerMaxOutputSizeTest : public ::testing::Test
{
  protected:
    static ScoreCipherHandler MakeHandler(const common::AlgorithmId& algorithm)
    {
        return ScoreCipherHandler{std::make_unique<CipherExecutor>(), algorithm};
    }

    static Expected<std::uint64_t, DaemonErrorCode> Query(ScoreCipherHandler& handler, RequestParameters request)
    {
        auto response = handler.Execute(kGetMaxOutputSize, request);
        if (!response.has_value())
        {
            return make_unexpected(response.error());
        }
        EXPECT_EQ(response.value().size(), 1U);
        const auto* const value = std::get_if<std::uint64_t>(&response.value().at(0));
        EXPECT_NE(value, nullptr) << "response param[0] must be a uint64_t";
        return (value != nullptr) ? *value : 0U;
    }
};

TEST_F(ScoreCipherHandlerMaxOutputSizeTest, EmptyInputGivesOneBlock)
{
    auto handler = MakeHandler("AES-256-CBC");
    const auto size = Query(handler, {std::uint64_t{0U}});
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), kAesBlockSize);
}

TEST_F(ScoreCipherHandlerMaxOutputSizeTest, BoundIsInputPlusOneBlock)
{
    auto handler = MakeHandler("AES-256-CBC");
    const auto size = Query(handler, {std::uint64_t{5U}});
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), 5U + kAesBlockSize);
}

TEST_F(ScoreCipherHandlerMaxOutputSizeTest, QueryLeavesStreamStateUntouched)
{
    auto handler = MakeHandler("AES-256-CBC");
    ASSERT_TRUE(Query(handler, {std::uint64_t{32U}}).has_value());
    EXPECT_EQ(handler.GetOperationState(), StreamOperationState::IDLE);
}

TEST_F(ScoreCipherHandlerMaxOutputSizeTest, MissingInputLengthIsRejected)
{
    auto handler = MakeHandler("AES-256-CBC");
    const auto size = Query(handler, {});
    ASSERT_FALSE(size.has_value());
    EXPECT_EQ(size.error(), DaemonErrorCode::kInsufficientParameters);
}

TEST_F(ScoreCipherHandlerMaxOutputSizeTest, NonIntegerInputLengthIsRejected)
{
    auto handler = MakeHandler("AES-256-CBC");
    const std::array<std::uint8_t, 4U> buffer{};
    const auto size = Query(handler, {score::cpp::span<const std::uint8_t>{buffer.data(), buffer.size()}});
    ASSERT_FALSE(size.has_value());
    EXPECT_EQ(size.error(), DaemonErrorCode::kInvalidDataType);
}

TEST_F(ScoreCipherHandlerMaxOutputSizeTest, UnknownAlgorithmIsRejected)
{
    auto handler = MakeHandler("BOGUS");
    const auto size = Query(handler, {std::uint64_t{0U}});
    ASSERT_FALSE(size.has_value());
    EXPECT_EQ(size.error(), DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(ScoreCipherHandlerMaxOutputSizeTest, LargestInputThatFitsIsAccepted)
{
    auto handler = MakeHandler("AES-256-CBC");
    const std::uint64_t input = std::numeric_limits<std::uint64_t>::max() - kAesBlockSize;
    const auto size = Query(handler, {input});
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), std::numeric_limits<std::uint64_t>::max());
}

TEST_F(ScoreCipherHandlerMaxOutputSizeTest, OverflowingInputIsRejected)
{
    auto handler = MakeHandler("AES-256-CBC");
    const std::uint64_t input = std::numeric_limits<std::uint64_t>::max() - kAesBlockSize + 1U;
    const auto size = Query(handler, {input});
    ASSERT_FALSE(size.has_value());
    EXPECT_EQ(size.error(), DaemonErrorCode::kInvalidArgument);
}

}  // namespace
}  // namespace score::crypto::daemon::provider::score_provider::operations::cipher
