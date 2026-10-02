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
#include "score/crypto/src/daemon/provider/handler/operations/verify_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::verify
{
namespace handler = ::score::crypto::daemon::provider::handler;
using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;

Expected<ResponseParameters, DaemonErrorCode> VerifyExecutor::Execute(ScoreVerifyHandler& handler,
                                                                      const common::OperationIdentifier& operationId,
                                                                      RequestParameters& request)
{
    // RESET does not participate in the streaming state machine.
    if (operationId.operationAction == handler::verify_handler_operations::VERIFY_RESET)
    {
        auto result = ExecuteReset(handler, request);
        if (!result.has_value())
        {
            return make_unexpected(result.error());
        }
        return ResponseParameters{};
    }

    // A single-shot verification is only valid while no streaming operation is active.
    if (operationId.operationAction == handler::verify_handler_operations::VERIFY_SS)
    {
        StreamOperationState state = handler.GetOperationState();
        if (state != StreamOperationState::IDLE)
        {
            return make_unexpected(DaemonErrorCode::kOperationInProgress);
        }
        return ExecuteSingleShot(handler, request);
    }

    // Streaming operations must follow the valid state-machine transition before
    // the corresponding handler method is called.
    StreamOperationState currentState = handler.GetOperationState();
    StreamOperationState nextState = StreamOperationState::IDLE;
    const auto sequenceValidation = ValidateStreamTransition(operationId.operationAction, currentState, nextState);
    if (!sequenceValidation.has_value())
    {
        return make_unexpected(sequenceValidation.error());
    }

    // Finalization returns the verification result and updates the state only
    // after successful handler execution.
    if (operationId.operationAction == handler::verify_handler_operations::VERIFY_FINALIZE)
    {
        auto result = ExecuteFinalize(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
        }
        return result;
    }

    // Initialization and update return no response parameters. The stream state
    // is advanced only when the handler accepts the operation.

    if (operationId.operationAction == handler::verify_handler_operations::VERIFY_FINALIZE)
    {
        auto result = ExecuteInit(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
        }
        else
        {
            return make_unexpected(result.error());
        }
    }

    if (operationId.operationAction == handler::verify_handler_operations::VERIFY_UPDATE)
    {
        auto result = ExecuteUpdate(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
        }
        else
        {
            return make_unexpected(result.error());
        }
    }

    const auto result = [&]() -> Expected<std::monostate, DaemonErrorCode> {
        if (operationId.operationAction == handler::verify_handler_operations::VERIFY_INIT)
        {
            return ExecuteInit(handler, request);
        }
        if (operationId.operationAction == handler::verify_handler_operations::VERIFY_UPDATE)
        {
            return ExecuteUpdate(handler, request);
        }
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }();

    if (result.has_value())
    {
        handler.SetOperationState(nextState);
    }
    else
    {
        return make_unexpected(result.error());
    }

    return ResponseParameters{};
}

Expected<std::monostate, DaemonErrorCode> VerifyExecutor::ExecuteInit(ScoreVerifyHandler& handler,
                                                                      RequestParameters& request)
{
    // Initialization data is optional and is forwarded when it has the
    // expected byte-span type.
    std::optional<score::cpp::span<const std::uint8_t>> initialData;
    if (!request.empty())
    {
        if (auto* buf = std::get_if<score::cpp::span<const std::uint8_t>>(&request[0]))
        {
            initialData.emplace(*buf);
        }
    }
    return handler.InitVerify(initialData);
}

Expected<std::monostate, DaemonErrorCode> VerifyExecutor::ExecuteUpdate(ScoreVerifyHandler& handler,
                                                                        RequestParameters& request)
{
    // UPDATE requires one input buffer containing data for the active stream.
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    auto* buf = std::get_if<score::cpp::span<const std::uint8_t>>(&request[0]);
    if (buf == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidDataType);
    }

    return handler.UpdateVerify(*buf);
}

Expected<ResponseParameters, DaemonErrorCode> VerifyExecutor::ExecuteFinalize(ScoreVerifyHandler& handler,
                                                                              RequestParameters& request)
{
    // FINALIZE accepts the signature data and optional final streaming data.
    std::optional<score::cpp::span<std::uint8_t>> output;
    if (!request.empty())
    {
        if (auto* buf = std::get_if<score::cpp::span<std::uint8_t>>(&request[0]))
        {
            output.emplace(*buf);
        }
    }

    std::optional<score::cpp::span<const std::uint8_t>> finalData;
    if (request.size() > 1)
    {
        if (auto* buf = std::get_if<score::cpp::span<const std::uint8_t>>(&request[1]))
        {
            finalData.emplace(*buf);
        }
    }

    return handler.FinalizeVerify(output, finalData);
}

Expected<ResponseParameters, DaemonErrorCode> VerifyExecutor::ExecuteSingleShot(ScoreVerifyHandler& handler,
                                                                                RequestParameters& request)
{
    // SINGLE-SHOT forwards the verification data and signature to the handler.
    if (request.size() < 2U)
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    auto* data = std::get_if<score::cpp::span<const std::uint8_t>>(&request[0]);
    if (data == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidDataType);
    }

    return handler.SingleShotVerify(*data, request[1]);
}

Expected<std::monostate, DaemonErrorCode> VerifyExecutor::ExecuteReset(ScoreVerifyHandler& handler,
                                                                       RequestParameters& /*request*/)
{
    // RESET does not consume request parameters; the handler owns the reset logic.
    return handler.Reset();
}

Expected<std::monostate, DaemonErrorCode> VerifyExecutor::ValidateStreamTransition(
    const common::OperationAction action,
    const StreamOperationState currentState,
    StreamOperationState& nextState)
{
    // Map the VERIFY action to the generic stream operation used by the
    // centralized state-transition validator.
    handler::handler_utils::StreamOperation op{};
    if (action == handler::verify_handler_operations::VERIFY_INIT)
    {
        op = handler::handler_utils::StreamOperation::kInit;
    }
    else if (action == handler::verify_handler_operations::VERIFY_UPDATE)
    {
        op = handler::handler_utils::StreamOperation::kUpdate;
    }
    else if (action == handler::verify_handler_operations::VERIFY_FINALIZE)
    {
        op = handler::handler_utils::StreamOperation::kFinalize;
    }
    else
    {
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }
    const auto result = handler::handler_utils::ValidateStreamOperationSequence(currentState, op);
    if (!result.has_value())
    {
        return make_unexpected(result.error());
    }
    nextState = result.value();
    return std::monostate{};
}
}  // namespace score::crypto::daemon::provider::score_provider::operations::verify
