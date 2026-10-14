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

#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/verify_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/verify/iav_primula_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"

#include <gtest/gtest.h>

#include <vector>

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider::score_provider::iav_primula;
using Executor = score::crypto::daemon::provider::score_provider::operations::verify::VerifyExecutor;

// ---------------------------------------------------------------------------
// Algorithm and key validation
// ---------------------------------------------------------------------------

TEST(IavPrimulaVerificationTest, RejectsUnsupportedAndMissingKeys)
{
    // ML-KEM-768 is not a supported signature-verification algorithm.
    IavPrimulaVerifyHandler unsupported_handler{std::make_unique<Executor>(), "ML-KEM-768"};
    auto unsupported_result = unsupported_handler.InitializeContext({});
    ASSERT_FALSE(unsupported_result.has_value());
    EXPECT_EQ(unsupported_result.error(), common::DaemonErrorCode::kUnsupportedAlgorithm);

    // ML-DSA-44 requires a bound verification key during initialization.
    IavPrimulaVerifyHandler handler{std::make_unique<Executor>(), "ML-DSA-44"};
    auto result = handler.InitializeContext({});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kKeySlotEmpty);
}

// ---------------------------------------------------------------------------
// Signature input validation
// ---------------------------------------------------------------------------

TEST(IavPrimulaVerificationTest, ValidatesKeyTypeAndSignatureSize)
{
    IavPrimulaVerifyHandler handler{std::make_unique<Executor>(), "ML-DSA-44"};
    // A public-only key has no native handle and cannot be used for this
    // verification operation.
    IavPrimulaKeyHandler public_key{nullptr, std::vector<std::uint8_t>(1312U), {}};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.bound_key_handler = &public_key;
    auto result = handler.InitializeContext(params);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);

    // Use a non-null sentinel to simulate a bound native key handle.
    IavPrimulaKeyHandler key{reinterpret_cast<iav_primula_key_handle*>(0x1), {}, {}};
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    const std::uint8_t message[] = {1U, 2U};
    // ML-DSA-44 signatures are 2420 bytes; ten bytes are intentionally invalid.
    std::vector<std::uint8_t> signature(10U);
    const auto input = score::cpp::span<const std::uint8_t>{message, 2U};
    auto verify =
        handler.SingleShotVerify(input, score::cpp::span<const std::uint8_t>{signature.data(), signature.size()});
    ASSERT_FALSE(verify.has_value());
    EXPECT_EQ(verify.error(), common::DaemonErrorCode::kInvalidArgument);
}

TEST(IavPrimulaVerificationTest, RejectsSingleShotRequestWithoutSignature)
{
    IavPrimulaVerifyHandler handler{std::make_unique<Executor>(), "ML-DSA-44"};
    IavPrimulaKeyHandler key{reinterpret_cast<iav_primula_key_handle*>(0x1), {}, {}};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());

    const std::uint8_t message[] = {1U, 2U};
    common::RequestParameters request{
        score::cpp::span<const std::uint8_t>{message, 2U},
    };
    common::OperationIdentifier operation{};
    operation.operationActor = common::actors::OP_ACTOR_VERIFY_HANDLER;
    operation.operationAction =
        ::score::crypto::daemon::provider::handler::verify_handler_operations::VERIFY_SS;

    auto result = handler.Execute(operation, request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInsufficientParameters);
}

TEST(IavPrimulaVerificationTest, ReportsPqcSizesAndResetsUsingUpstreamActions)
{
    namespace ops = provider::handler::verify_handler_operations;
    const std::pair<const char*, std::size_t> cases[] = {
        {"ML-DSA-44", 2420U}, {"ML-DSA-65", 3309U}, {"ML-DSA-87", 4627U}};
    for (const auto& test_case : cases)
    {
        IavPrimulaVerifyHandler handler{std::make_unique<Executor>(), test_case.first};
        EXPECT_EQ(handler.GetSignatureSize(), test_case.second);
        handler.SetOperationState(common::StreamOperationState::STREAM_ACTIVE);
        common::RequestParameters request;
        auto size = handler.Execute({common::actors::OP_ACTOR_VERIFY_HANDLER, ops::VERIFY_GET_SIZE}, request);
        ASSERT_TRUE(size.has_value());
        ASSERT_EQ(size->size(), 1U);
        EXPECT_EQ(std::get<std::uint64_t>(size->front()), test_case.second);
        EXPECT_EQ(handler.GetOperationState(), common::StreamOperationState::STREAM_ACTIVE);
        auto reset = handler.Execute({common::actors::OP_ACTOR_VERIFY_HANDLER, ops::VERIFY_RESET}, request);
        ASSERT_TRUE(reset.has_value());
        EXPECT_TRUE(reset->empty());
        EXPECT_EQ(handler.GetOperationState(), common::StreamOperationState::IDLE);
    }
    IavPrimulaVerifyHandler unsupported{std::make_unique<Executor>(), "ML-KEM-768"};
    EXPECT_EQ(unsupported.GetSignatureSize(), 0U);
}

TEST(IavPrimulaVerificationTest, PropagatesBackendFailureAndRejectsWrongActor)
{
    namespace ops = provider::handler::verify_handler_operations;
    IavPrimulaVerifyHandler handler{std::make_unique<Executor>(), "ML-DSA-44"};
    // The current FFI is a placeholder and never dereferences this sentinel.
    IavPrimulaKeyHandler key{reinterpret_cast<iav_primula_key_handle*>(0x1), {}, {}};
    provider::handler::InitializationParams params{};
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    const std::uint8_t message[] = {1U, 2U};
    const std::vector<std::uint8_t> signature(handler.GetSignatureSize());
    common::RequestParameters request{
        score::cpp::span<const std::uint8_t>{message, 2U},
        score::cpp::span<const std::uint8_t>{signature.data(), signature.size()}};
    auto result = handler.Execute({common::actors::OP_ACTOR_VERIFY_HANDLER, ops::VERIFY_SS}, request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(handler.GetOperationState(), common::StreamOperationState::IDLE);
    auto wrong_actor = handler.Execute({common::actors::OP_ACTOR_SIGN_HANDLER, ops::VERIFY_SS}, request);
    ASSERT_FALSE(wrong_actor.has_value());
    EXPECT_EQ(wrong_actor.error(), common::DaemonErrorCode::kInvalidOperation);
}
}  // namespace
