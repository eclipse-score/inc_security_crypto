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
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::verify
{

namespace handler = ::score::crypto::daemon::provider::handler;
namespace actors = ::score::crypto::daemon::common::actors;
namespace verify_ops = ::score::crypto::daemon::provider::handler::verify_handler_operations;

using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

Expected<ResponseParameters, DaemonErrorCode> VerifyExecutor::Execute(ScoreVerifyHandler& handler_ref,
                                                                      const common::OperationIdentifier& operationId,
                                                                      RequestParameters& request)
{
    // A VERIFY context is bound to the public half of the key pair, so a request
    // addressed to any other actor has reached the wrong context.
    if (operationId.operationActor != actors::OP_ACTOR_VERIFY_HANDLER)
    {
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }

    const auto action = operationId.operationAction;

    if (action == verify_ops::VERIFY_GET_SIZE)
    {
        ResponseParameters response;
        response.push_back(static_cast<std::uint64_t>(handler_ref.GetSignatureSize()));
        return response;
    }

    if (action == verify_ops::VERIFY_RESET)
    {
        auto res = handler_ref.Reset();
        if (!res.has_value())
        {
            return make_unexpected(res.error());
        }
        return ResponseParameters{};
    }

    if (action == verify_ops::VERIFY_SS)
    {
        if (handler_ref.GetOperationState() == StreamOperationState::STREAM_ACTIVE)
        {
            return make_unexpected(DaemonErrorCode::kOperationInProgress);
        }
        auto result = ExecuteSingleShot(handler_ref, request);
        // A single-shot always ends the stream, so the context is left reusable
        // even when the operation failed part-way through.
        handler_ref.SetOperationState(StreamOperationState::IDLE);
        return result;
    }

    return ExecuteStreaming(handler_ref, action, request);
}

// static
Expected<ResponseParameters, DaemonErrorCode> VerifyExecutor::ExecuteStreaming(ScoreVerifyHandler& handler_ref,
                                                                               const common::OperationAction action,
                                                                               RequestParameters& request)
{
    const StreamOperationState currentState = handler_ref.GetOperationState();
    StreamOperationState nextState = StreamOperationState::IDLE;
    const auto validation = ValidateStreamTransition(action, currentState, nextState);
    if (!validation.has_value())
    {
        return make_unexpected(validation.error());
    }

    if (action == verify_ops::VERIFY_INIT)
    {
        auto result = handler_ref.InitVerify();
        if (!result.has_value())
        {
            return make_unexpected(result.error());
        }
        handler_ref.SetOperationState(nextState);
        return ResponseParameters{};
    }

    if (action == verify_ops::VERIFY_UPDATE)
    {
        if (request.empty())
        {
            return make_unexpected(DaemonErrorCode::kInsufficientParameters);
        }
        const auto dataSpan = handler::handler_utils::CheckAndGetSpan<const std::uint8_t>(request[0]);
        if (!dataSpan.has_value())
        {
            return make_unexpected(dataSpan.error());
        }
        auto result = handler_ref.UpdateVerify(dataSpan.value());
        if (!result.has_value())
        {
            return make_unexpected(result.error());
        }
        handler_ref.SetOperationState(nextState);
        return ResponseParameters{};
    }

    // ValidateStreamTransition() only passes INIT, UPDATE and FINALIZE.
    auto result = ExecuteFinalize(handler_ref, request);
    if (result.has_value())
    {
        handler_ref.SetOperationState(nextState);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Operation implementations
// ---------------------------------------------------------------------------

// static
Expected<ResponseParameters, DaemonErrorCode> VerifyExecutor::ExecuteFinalize(ScoreVerifyHandler& handler_ref,
                                                                              RequestParameters& request)
{
    // request[0] = signature to check
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    const auto signatureSpan = handler::handler_utils::CheckAndGetSpan<const std::uint8_t>(request[0]);
    if (!signatureSpan.has_value())
    {
        return make_unexpected(signatureSpan.error());
    }

    auto verified = handler_ref.FinalizeVerify(signatureSpan.value());
    if (!verified.has_value())
    {
        return make_unexpected(verified.error());
    }

    ResponseParameters response;
    response.push_back(verified.value());
    return response;
}

// static
Expected<ResponseParameters, DaemonErrorCode> VerifyExecutor::ExecuteSingleShot(ScoreVerifyHandler& handler_ref,
                                                                                RequestParameters& request)
{
    // request[0] = message, request[1] = signature
    if (request.size() < 2U)
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    const auto dataSpan = handler::handler_utils::CheckAndGetSpan<const std::uint8_t>(request[0]);
    if (!dataSpan.has_value())
    {
        return make_unexpected(dataSpan.error());
    }
    const auto signatureSpan = handler::handler_utils::CheckAndGetSpan<const std::uint8_t>(request[1]);
    if (!signatureSpan.has_value())
    {
        return make_unexpected(signatureSpan.error());
    }

    // The whole one-shot belongs to the provider; the executor adds no steps.
    auto verified = handler_ref.SingleShotVerify(dataSpan.value(), signatureSpan.value());
    if (!verified.has_value())
    {
        return make_unexpected(verified.error());
    }

    ResponseParameters response;
    response.push_back(verified.value());
    return response;
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

// static
Expected<std::monostate, DaemonErrorCode> VerifyExecutor::ValidateStreamTransition(
    const common::OperationAction action,
    const StreamOperationState currentState,
    StreamOperationState& nextState)
{
    const auto op = handler::verify_handler_operations::ToStreamOperation(action);
    if (!op.has_value())
    {
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }

    const auto result = handler::handler_utils::ValidateStreamOperationSequence(currentState, op.value());
    if (!result.has_value())
    {
        return make_unexpected(result.error());
    }
    nextState = result.value();
    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::verify
