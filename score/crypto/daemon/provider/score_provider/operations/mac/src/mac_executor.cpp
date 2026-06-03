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

#include "score/crypto/daemon/provider/score_provider/operations/mac/mac_executor.hpp"
#include "score/crypto/daemon/provider/handler/operations/mac_handler_operations.hpp"
#include "score/crypto/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/daemon/provider/score_provider/operations/mac/score_mac_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::mac
{

namespace handler = ::score::crypto::daemon::provider::handler;
using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

Expected<ResponseParameters, DaemonErrorCode> MacExecutor::Execute(ScoreMacHandler& handler,
                                                                   const common::OperationIdentifier& operationId,
                                                                   RequestParameters& request)
{
    if (operationId.operationAction == handler::mac_handler_operations::MAC_GET_SIZE)
    {
        return GetMacSize(handler, request);
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_RESET)
    {
        auto res = ExecuteReset(handler, request);
        if (!res.has_value())
        {
            return make_unexpected(res.error());
        }
        return ResponseParameters{};
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_SS)
    {
        if (handler.GetOperationState() == StreamOperationState::STREAM_ACTIVE)
        {
            return make_unexpected(DaemonErrorCode::kOperationInProgress);
        }
        auto result = ExecuteSingleShot(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(StreamOperationState::IDLE);
        }
        return result;
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_VERIFY)
    {
        if (handler.GetOperationState() == StreamOperationState::IDLE)
        {
            return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
        }
        auto result = ExecuteVerify(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(StreamOperationState::IDLE);
        }
        return result;
    }

    // Streaming operations: validate state machine transition
    StreamOperationState currentState = handler.GetOperationState();
    StreamOperationState nextState = StreamOperationState::IDLE;
    const auto validation = ValidateStreamTransition(operationId.operationAction, currentState, nextState);
    if (!validation.has_value())
    {
        return make_unexpected(validation.error());
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_INIT)
    {
        auto result = ExecuteInit(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
            return ResponseParameters{};
        }
        return make_unexpected(result.error());
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_FINALIZE)
    {
        auto result = ExecuteFinalize(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
        }
        return result;
    }

    if (operationId.operationAction == handler::mac_handler_operations::MAC_UPDATE)
    {
        auto result = ExecuteUpdate(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
            return ResponseParameters{};
        }
        return make_unexpected(result.error());
    }

    return make_unexpected(DaemonErrorCode::kInvalidOperation);
}

// ---------------------------------------------------------------------------
// Operation implementations
// ---------------------------------------------------------------------------

Expected<std::monostate, DaemonErrorCode> MacExecutor::ExecuteInit(ScoreMacHandler& handler, RequestParameters& request)
{
    std::optional<common::RequestParameter> initialData;
    if (!request.empty())
    {
        initialData.emplace(request[0]);
    }
    return handler.InitMac(initialData);
}

Expected<std::monostate, DaemonErrorCode> MacExecutor::ExecuteUpdate(ScoreMacHandler& handler,
                                                                     RequestParameters& request)
{
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }
    return handler.UpdateMac(request[0]);
}

Expected<ResponseParameters, DaemonErrorCode> MacExecutor::ExecuteFinalize(ScoreMacHandler& handler,
                                                                           RequestParameters& request)
{
    std::optional<common::RequestParameter> output;
    if (!request.empty())
    {
        if (auto* buf = std::get_if<common::VirtualMemoryBuffer>(&request[0]))
        {
            output.emplace(*buf);
        }
    }

    std::optional<common::RequestParameter> finalData;
    if (request.size() > 1U)
    {
        finalData.emplace(request[1]);
    }

    return handler.FinalizeMac(output, finalData);
}

Expected<ResponseParameters, DaemonErrorCode> MacExecutor::ExecuteVerify(ScoreMacHandler& handler,
                                                                         RequestParameters& request)
{
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    auto res = handler.VerifyMac(request[0]);
    if (!res.has_value())
    {
        return make_unexpected(res.error());
    }

    ResponseParameters response;
    response.push_back(res.value());
    return response;
}

Expected<ResponseParameters, DaemonErrorCode> MacExecutor::ExecuteSingleShot(ScoreMacHandler& handler,
                                                                             RequestParameters& request)
{
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    std::optional<common::RequestParameter> output;
    if (request.size() > 1U)
    {
        if (auto* buf = std::get_if<common::VirtualMemoryBuffer>(&request[1]))
        {
            output.emplace(*buf);
        }
    }

    auto init = handler.InitMac(std::nullopt);
    if (!init.has_value())
    {
        return make_unexpected(init.error());
    }

    auto up = handler.UpdateMac(request[0]);
    if (!up.has_value())
    {
        return make_unexpected(up.error());
    }

    return handler.FinalizeMac(output, std::nullopt);
}

Expected<ResponseParameters, DaemonErrorCode> MacExecutor::GetMacSize(const ScoreMacHandler& handler,
                                                                      RequestParameters& /*request*/)
{
    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(handler.GetMacSize()));
    return response;
}

Expected<std::monostate, DaemonErrorCode> MacExecutor::ExecuteReset(ScoreMacHandler& handler,
                                                                    RequestParameters& /*request*/)
{
    return handler.Reset();
}

// ---------------------------------------------------------------------------
// Stream state machine
// ---------------------------------------------------------------------------

// static
Expected<std::monostate, DaemonErrorCode> MacExecutor::ValidateStreamTransition(const common::OperationAction action,
                                                                                const StreamOperationState currentState,
                                                                                StreamOperationState& nextState)
{
    handler::handler_utils::StreamOperation op{};
    if (action == handler::mac_handler_operations::MAC_INIT)
    {
        op = handler::handler_utils::StreamOperation::kInit;
    }
    else if (action == handler::mac_handler_operations::MAC_UPDATE)
    {
        op = handler::handler_utils::StreamOperation::kUpdate;
    }
    else if (action == handler::mac_handler_operations::MAC_FINALIZE)
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

}  // namespace score::crypto::daemon::provider::score_provider::operations::mac
