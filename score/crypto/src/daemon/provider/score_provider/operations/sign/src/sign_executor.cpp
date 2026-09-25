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

#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/sign_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::sign
{
namespace handler = ::score::crypto::daemon::provider::handler;
using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;

Expected<ResponseParameters, DaemonErrorCode> SignExecutor::Execute(ScoreSignHandler& handler,
                                                                    const common::OperationIdentifier& operationId,
                                                                    RequestParameters& request)
{
    // Handle operations that do not participate in the streaming state machine.
    if (operationId.operationAction == handler::sign_handler_operations::SIGN_GET_SIGNATURE_SIZE)
    {
        return GetSignatureSize(handler, request);
    }

    if (operationId.operationAction == handler::sign_handler_operations::SIGN_RESET)
    {
        auto result = ExecuteReset(handler, request);
        if (!result.has_value())
        {
            return make_unexpected(result.error());
        }
        return ResponseParameters{};
    }

    // A single-shot signature is only valid while no streaming operation is active.
    if (operationId.operationAction == handler::sign_handler_operations::SIGN_SS)
    {
        StreamOperationState state = handler.GetOperationState();
        if (state != StreamOperationState::IDLE)
        {
            return make_unexpected(DaemonErrorCode::kOperationInProgress);
        }
        if (request.empty())
        {
            return make_unexpected(DaemonErrorCode::kInsufficientParameters);
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

    // Finalization returns a response and updates the state only after success.
    if (operationId.operationAction == handler::sign_handler_operations::SIGN_FINALIZE)
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
    if (operationId.operationAction == handler::sign_handler_operations::SIGN_INIT)
    {
        const auto result = ExecuteInit(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
        }
        else
        {
            return make_unexpected(result.error());
        }
    }

    if (operationId.operationAction == handler::sign_handler_operations::SIGN_UPDATE)
    {
        const auto result = ExecuteUpdate(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
        }
        else
        {
            return make_unexpected(result.error());
        }
    }

    return ResponseParameters{};
}

Expected<std::monostate, DaemonErrorCode> SignExecutor::ExecuteInit(ScoreSignHandler& handler,
                                                                    RequestParameters& request)
{
    // Initialization data is optional; a missing or incompatible first
    // parameter is treated as no initial data and handled by the provider.
    std::optional<score::cpp::span<const std::uint8_t>> initialData;
    if (!request.empty())
    {
        if (auto* buf = std::get_if<score::cpp::span<const std::uint8_t>>(&request[0]))
        {
            initialData.emplace(*buf);
        }
    }
    return handler.InitSign(initialData);
}

Expected<std::monostate, DaemonErrorCode> SignExecutor::ExecuteUpdate(ScoreSignHandler& handler,
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

    return handler.UpdateSign(*buf);
}

Expected<ResponseParameters, DaemonErrorCode> SignExecutor::ExecuteFinalize(ScoreSignHandler& handler,
                                                                            RequestParameters& request)
{
    // FINALIZE accepts an optional output buffer followed by optional final data.
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

    return handler.FinalizeSign(output, finalData);
}

Expected<ResponseParameters, DaemonErrorCode> SignExecutor::ExecuteSingleShot(ScoreSignHandler& handler,
                                                                              RequestParameters& request)
{
    // SINGLE-SHOT requires input data and may optionally receive an output buffer.
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    auto* data = std::get_if<score::cpp::span<const std::uint8_t>>(&request[0]);
    if (data == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidDataType);
    }

    std::optional<score::cpp::span<std::uint8_t>> output;
    if (request.size() > 1)
    {
        if (auto* buf = std::get_if<score::cpp::span<std::uint8_t>>(&request[1]))
        {
            output.emplace(*buf);
        }
    }

    return handler.SingleShotSign(*data, output);
}

Expected<std::monostate, DaemonErrorCode> SignExecutor::ExecuteReset(ScoreSignHandler& handler,
                                                                     RequestParameters& /*request*/)
{
    // RESET does not consume request parameters; the handler owns the reset logic.
    return handler.Reset();
}

Expected<ResponseParameters, DaemonErrorCode> SignExecutor::GetSignatureSize(const ScoreSignHandler& handler,
                                                                             RequestParameters& /*request*/)
{
    // The signature size depends only on the configured algorithm.
    return handler.GetSignatureSize();
}

Expected<std::monostate, DaemonErrorCode> SignExecutor::ValidateStreamTransition(
    const common::OperationAction action,
    const StreamOperationState currentState,
    StreamOperationState& nextState)
{
    // Map the SIGN action to the generic stream operation used by the
    // centralized state-transition validator.
    handler::handler_utils::StreamOperation op{};
    if (action == handler::sign_handler_operations::SIGN_INIT)
    {
        op = handler::handler_utils::StreamOperation::kInit;
    }
    else if (action == handler::sign_handler_operations::SIGN_UPDATE)
    {
        op = handler::handler_utils::StreamOperation::kUpdate;
    }
    else if (action == handler::sign_handler_operations::SIGN_FINALIZE)
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
}  // namespace score::crypto::daemon::provider::score_provider::operations::sign
