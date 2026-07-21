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

#include "score/crypto/daemon/provider/score_provider/operations/hash/hash_executor.hpp"
#include "score/crypto/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/daemon/provider/score_provider/operations/hash/score_hash_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::hash
{

namespace handler = ::score::crypto::daemon::provider::handler;
using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;

Expected<ResponseParameters, DaemonErrorCode> HashExecutor::Execute(ScoreHashHandler& handler,
                                                                    const common::OperationIdentifier& operationId,
                                                                    RequestParameters& request)
{
    if (operationId.operationAction == handler::hash_handler_operations::HASH_GET_DIGEST_SIZE)
    {
        return GetDigestSize(handler, request);
    }

    if (operationId.operationAction == handler::hash_handler_operations::HASH_RESET)
    {
        auto result = ExecuteReset(handler, request);
        if (!result.has_value())
        {
            return make_unexpected(result.error());
        }
        return ResponseParameters{};
    }

    if (operationId.operationAction == handler::hash_handler_operations::HASH_SS)
    {
        StreamOperationState state = handler.GetOperationState();
        if (state != StreamOperationState::IDLE)
        {
            return make_unexpected(DaemonErrorCode::kOperationInProgress);
        }
        return ExecuteSingleShot(handler, request);
    }

    // Streaming operations: validate state machine transition
    StreamOperationState currentState = handler.GetOperationState();
    StreamOperationState nextState = StreamOperationState::IDLE;
    const auto sequenceValidation = ValidateStreamTransition(operationId.operationAction, currentState, nextState);
    if (!sequenceValidation.has_value())
    {
        return make_unexpected(sequenceValidation.error());
    }

    if (operationId.operationAction == handler::hash_handler_operations::HASH_FINALIZE)
    {
        auto result = ExecuteFinalize(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
        }
        return result;
    }

    const auto result = [&]() -> Expected<std::monostate, DaemonErrorCode> {
        if (operationId.operationAction == handler::hash_handler_operations::HASH_INIT)
        {
            return ExecuteInit(handler, request);
        }
        if (operationId.operationAction == handler::hash_handler_operations::HASH_UPDATE)
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

Expected<std::monostate, DaemonErrorCode> HashExecutor::ExecuteInit(ScoreHashHandler& handler,
                                                                    RequestParameters& request)
{
    std::optional<common::VirtualMemoryBufferConst> initialDataOrIV;
    if (!request.empty())
    {
        if (auto* buf = std::get_if<common::VirtualMemoryBufferConst>(&request[0]))
        {
            initialDataOrIV.emplace(*buf);
        }
    }
    return handler.InitHash(initialDataOrIV);
}

Expected<std::monostate, DaemonErrorCode> HashExecutor::ExecuteUpdate(ScoreHashHandler& handler,
                                                                      RequestParameters& request)
{
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    auto* buf = std::get_if<common::VirtualMemoryBufferConst>(&request[0]);
    if (buf == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidDataType);
    }

    return handler.UpdateHash(*buf);
}

Expected<ResponseParameters, DaemonErrorCode> HashExecutor::ExecuteFinalize(ScoreHashHandler& handler,
                                                                            RequestParameters& request)
{
    std::optional<common::VirtualMemoryBuffer> output;
    if (!request.empty())
    {
        if (auto* buf = std::get_if<common::VirtualMemoryBuffer>(&request[0]))
        {
            output.emplace(*buf);
        }
    }

    std::optional<common::VirtualMemoryBufferConst> finalData;
    if (request.size() > 1)
    {
        if (auto* buf = std::get_if<common::VirtualMemoryBufferConst>(&request[1]))
        {
            finalData.emplace(*buf);
        }
    }

    return handler.FinalizeHash(output, finalData);
}

Expected<ResponseParameters, DaemonErrorCode> HashExecutor::ExecuteSingleShot(ScoreHashHandler& handler,
                                                                              RequestParameters& request)
{
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    auto* data = std::get_if<common::VirtualMemoryBufferConst>(&request[0]);
    if (data == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidDataType);
    }

    std::optional<common::VirtualMemoryBuffer> output;
    if (request.size() > 1)
    {
        if (auto* buf = std::get_if<common::VirtualMemoryBuffer>(&request[1]))
        {
            output.emplace(*buf);
        }
    }

    std::optional<common::VirtualMemoryBufferConst> iv;
    if (request.size() > 2)
    {
        if (auto* buf = std::get_if<common::VirtualMemoryBufferConst>(&request[2]))
        {
            iv.emplace(*buf);
        }
    }

    return handler.SingleShotHash(*data, output, iv);
}

Expected<std::monostate, DaemonErrorCode> HashExecutor::ExecuteReset(ScoreHashHandler& handler,
                                                                     RequestParameters& /*request*/)
{
    return handler.Reset();
}

Expected<ResponseParameters, DaemonErrorCode> HashExecutor::GetDigestSize(const ScoreHashHandler& handler,
                                                                          RequestParameters& /*request*/)
{
    return handler.GetDigestSize();
}

// static
Expected<std::monostate, DaemonErrorCode> HashExecutor::ValidateStreamTransition(
    const common::OperationAction action,
    const StreamOperationState currentState,
    StreamOperationState& nextState)
{
    handler::handler_utils::StreamOperation op{};
    if (action == handler::hash_handler_operations::HASH_INIT)
    {
        op = handler::handler_utils::StreamOperation::kInit;
    }
    else if (action == handler::hash_handler_operations::HASH_UPDATE)
    {
        op = handler::handler_utils::StreamOperation::kUpdate;
    }
    else if (action == handler::hash_handler_operations::HASH_FINALIZE)
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

}  // namespace score::crypto::daemon::provider::score_provider::operations::hash
