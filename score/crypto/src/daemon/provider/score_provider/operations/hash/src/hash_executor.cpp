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

#include "score/crypto/src/daemon/provider/score_provider/operations/hash/hash_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/hash/score_hash_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::hash
{

namespace handler = ::score::crypto::daemon::provider::handler;
using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;
using ::score::crypto::daemon::provider::handler::handler_utils::CheckAndGetSpan;
using ::score::crypto::daemon::provider::handler::handler_utils::ValidateParameterCount;

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
    const auto countResult = ValidateParameterCount(request, 0U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }
    return handler.InitHash();
}

Expected<std::monostate, DaemonErrorCode> HashExecutor::ExecuteUpdate(ScoreHashHandler& handler,
                                                                      RequestParameters& request)
{
    const auto countResult = ValidateParameterCount(request, 1U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }

    const auto inputSpan = CheckAndGetSpan<const std::uint8_t>(request[0], true);
    if (!inputSpan.has_value())
    {
        return make_unexpected(inputSpan.error());
    }

    return handler.UpdateHash(inputSpan.value());
}

Expected<ResponseParameters, DaemonErrorCode> HashExecutor::ExecuteFinalize(ScoreHashHandler& handler,
                                                                            RequestParameters& request)
{
    const auto countResult = ValidateParameterCount(request, 1U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }

    const auto outputSpan = CheckAndGetSpan<std::uint8_t>(request[0]);
    if (!outputSpan.has_value())
    {
        return make_unexpected(outputSpan.error());
    }

    return handler.FinalizeHash(outputSpan.value());
}

Expected<ResponseParameters, DaemonErrorCode> HashExecutor::ExecuteSingleShot(ScoreHashHandler& handler,
                                                                              RequestParameters& request)
{
    const auto countResult = ValidateParameterCount(request, 2U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }

    const auto inputSpan = CheckAndGetSpan<const std::uint8_t>(request[0], true);
    if (!inputSpan.has_value())
    {
        return make_unexpected(inputSpan.error());
    }

    const auto outputSpan = CheckAndGetSpan<std::uint8_t>(request[1]);
    if (!outputSpan.has_value())
    {
        return make_unexpected(outputSpan.error());
    }

    return handler.SingleShotHash(inputSpan.value(), outputSpan.value());
}

Expected<std::monostate, DaemonErrorCode> HashExecutor::ExecuteReset(ScoreHashHandler& handler,
                                                                     RequestParameters& request)
{
    const auto countResult = ValidateParameterCount(request, 0U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }
    return handler.Reset();
}

Expected<ResponseParameters, DaemonErrorCode> HashExecutor::GetDigestSize(const ScoreHashHandler& handler,
                                                                          RequestParameters& request)
{
    const auto countResult = ValidateParameterCount(request, 0U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }
    return handler.GetDigestSize();
}

// static
Expected<std::monostate, DaemonErrorCode> HashExecutor::ValidateStreamTransition(
    const common::OperationAction action,
    const StreamOperationState currentState,
    StreamOperationState& nextState)
{
    handler::handler_utils::StreamOperation streamOperation{};
    if (action == handler::hash_handler_operations::HASH_INIT)
    {
        streamOperation = handler::handler_utils::StreamOperation::kInit;
    }
    else if (action == handler::hash_handler_operations::HASH_UPDATE)
    {
        streamOperation = handler::handler_utils::StreamOperation::kUpdate;
    }
    else if (action == handler::hash_handler_operations::HASH_FINALIZE)
    {
        streamOperation = handler::handler_utils::StreamOperation::kFinalize;
    }
    else
    {
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }

    const auto result = handler::handler_utils::ValidateStreamOperationSequence(
        currentState, streamOperation, true, DaemonErrorCode::kStreamNotInitialized);
    if (!result.has_value())
    {
        return make_unexpected(result.error());
    }
    nextState = result.value();
    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::score_provider::operations::hash
