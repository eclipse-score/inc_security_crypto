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

#include "score/crypto/src/daemon/provider/score_provider/operations/cipher/cipher_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/cipher_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/cipher/score_cipher_handler.hpp"

#include <cstdint>
#include <optional>
#include <utility>
#include <variant>

namespace score::crypto::daemon::provider::score_provider::operations::cipher
{

namespace handler = ::score::crypto::daemon::provider::handler;
using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;

namespace
{

/// @brief Resolves an output buffer that is allowed to be zero-length.
///
/// CIPHER_FINALIZE may legally receive an empty buffer: a stream mode emits no
/// trailing bytes, and a single-shot whose update exactly filled the buffer
/// leaves no tail. CheckAndGetSpan() treats both as an error, so the length
/// check is left to the handler.
[[nodiscard]] Expected<score::cpp::span<std::uint8_t>, DaemonErrorCode> GetPossiblyEmptyOutput(
    common::RequestParameter& param)
{
    auto* const span = std::get_if<score::cpp::span<std::uint8_t>>(&param);
    if (span == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidDataType);
    }
    return *span;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

Expected<ResponseParameters, DaemonErrorCode> CipherExecutor::Execute(ScoreCipherHandler& handler_ref,
                                                                      const common::OperationIdentifier& operationId,
                                                                      RequestParameters& request)
{
    namespace ops = handler::cipher_handler_operations;

    if (operationId.operationAction == ops::CIPHER_GET_OUTPUT_SIZE)
    {
        ResponseParameters response;
        response.push_back(static_cast<std::uint64_t>(handler_ref.GetBlockSize()));
        return response;
    }

    if (operationId.operationAction == ops::CIPHER_GET_IV_SIZE)
    {
        ResponseParameters response;
        response.push_back(static_cast<std::uint64_t>(handler_ref.GetIvSize()));
        return response;
    }

    if (operationId.operationAction == ops::CIPHER_RESET)
    {
        auto res = ExecuteReset(handler_ref, request);
        if (!res.has_value())
        {
            return make_unexpected(res.error());
        }
        return ResponseParameters{};
    }

    if (operationId.operationAction == ops::CIPHER_SS)
    {
        if (handler_ref.GetOperationState() == StreamOperationState::STREAM_ACTIVE)
        {
            return make_unexpected(DaemonErrorCode::kOperationInProgress);
        }
        auto result = ExecuteSingleShot(handler_ref, request);
        // Single-shot always ends the stream, successfully or not, so the context
        // is left ready for the next call rather than stuck mid-stream.
        handler_ref.SetOperationState(StreamOperationState::IDLE);
        return result;
    }

    // Streaming operations: validate the state machine transition first.
    const StreamOperationState currentState = handler_ref.GetOperationState();
    StreamOperationState nextState = StreamOperationState::IDLE;
    const auto validation = ValidateStreamTransition(operationId.operationAction, currentState, nextState);
    if (!validation.has_value())
    {
        return make_unexpected(validation.error());
    }

    if (operationId.operationAction == ops::CIPHER_INIT)
    {
        auto result = ExecuteInit(handler_ref, request);
        if (!result.has_value())
        {
            return make_unexpected(result.error());
        }
        handler_ref.SetOperationState(nextState);
        return ResponseParameters{};
    }

    if (operationId.operationAction == ops::CIPHER_UPDATE)
    {
        auto result = ExecuteUpdate(handler_ref, request);
        if (result.has_value())
        {
            handler_ref.SetOperationState(nextState);
        }
        return result;
    }

    if (operationId.operationAction == ops::CIPHER_FINALIZE)
    {
        auto result = ExecuteFinalize(handler_ref, request);
        if (result.has_value())
        {
            handler_ref.SetOperationState(nextState);
        }
        return result;
    }

    return make_unexpected(DaemonErrorCode::kInvalidOperation);
}

// ---------------------------------------------------------------------------
// Operation implementations
// ---------------------------------------------------------------------------

Expected<std::monostate, DaemonErrorCode> CipherExecutor::ExecuteInit(ScoreCipherHandler& handler_ref,
                                                                      RequestParameters& request)
{
    std::optional<score::cpp::span<const std::uint8_t>> iv;
    if (!request.empty())
    {
        const auto ivSpan = handler::handler_utils::CheckAndGetSpan<const std::uint8_t>(request[0]);
        if (!ivSpan.has_value())
        {
            return make_unexpected(ivSpan.error());
        }
        iv.emplace(ivSpan.value());
    }
    return handler_ref.InitCipher(iv);
}

Expected<ResponseParameters, DaemonErrorCode> CipherExecutor::ExecuteUpdate(ScoreCipherHandler& handler_ref,
                                                                            RequestParameters& request)
{
    // request[0] = input chunk, request[1] = caller-provided output buffer
    if (request.size() < 2U)
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    const auto inputSpan = handler::handler_utils::CheckAndGetSpan<const std::uint8_t>(request[0]);
    if (!inputSpan.has_value())
    {
        return make_unexpected(inputSpan.error());
    }
    const auto outputSpan = handler::handler_utils::CheckAndGetSpan<std::uint8_t>(request[1]);
    if (!outputSpan.has_value())
    {
        return make_unexpected(outputSpan.error());
    }

    auto written = handler_ref.UpdateCipher(inputSpan.value(), outputSpan.value());
    if (!written.has_value())
    {
        return make_unexpected(written.error());
    }

    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(written.value()));
    return response;
}

Expected<ResponseParameters, DaemonErrorCode> CipherExecutor::ExecuteFinalize(ScoreCipherHandler& handler_ref,
                                                                              RequestParameters& request)
{
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    const auto outputSpan = GetPossiblyEmptyOutput(request[0]);
    if (!outputSpan.has_value())
    {
        return make_unexpected(outputSpan.error());
    }

    auto written = handler_ref.FinalizeCipher(outputSpan.value());
    if (!written.has_value())
    {
        return make_unexpected(written.error());
    }

    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(written.value()));
    return response;
}

Expected<ResponseParameters, DaemonErrorCode> CipherExecutor::ExecuteSingleShot(ScoreCipherHandler& handler_ref,
                                                                                RequestParameters& request)
{
    // request[0] = IV (empty for ECB), request[1] = input data, request[2] = output buffer
    if (request.size() < 3U)
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    std::optional<score::cpp::span<const std::uint8_t>> iv;
    if (handler_ref.GetIvSize() > 0U)
    {
        const auto ivSpan = handler::handler_utils::CheckAndGetSpan<const std::uint8_t>(request[0]);
        if (!ivSpan.has_value())
        {
            return make_unexpected(ivSpan.error());
        }
        iv.emplace(ivSpan.value());
    }

    const auto inputSpan = handler::handler_utils::CheckAndGetSpan<const std::uint8_t>(request[1]);
    if (!inputSpan.has_value())
    {
        return make_unexpected(inputSpan.error());
    }
    const auto outputSpan = handler::handler_utils::CheckAndGetSpan<std::uint8_t>(request[2]);
    if (!outputSpan.has_value())
    {
        return make_unexpected(outputSpan.error());
    }

    // The whole one-shot belongs to the provider; the executor adds no steps.
    auto written = handler_ref.SingleShotCipher(iv, inputSpan.value(), outputSpan.value());
    if (!written.has_value())
    {
        return make_unexpected(written.error());
    }

    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(written.value()));
    return response;
}

Expected<std::monostate, DaemonErrorCode> CipherExecutor::ExecuteReset(ScoreCipherHandler& handler_ref,
                                                                       RequestParameters& /*request*/)
{
    return handler_ref.Reset();
}

// ---------------------------------------------------------------------------
// Stream state machine
// ---------------------------------------------------------------------------

// static
Expected<std::monostate, DaemonErrorCode> CipherExecutor::ValidateStreamTransition(
    const common::OperationAction action,
    const StreamOperationState currentState,
    StreamOperationState& nextState)
{
    const auto op = handler::cipher_handler_operations::ToStreamOperation(action);
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

}  // namespace score::crypto::daemon::provider::score_provider::operations::cipher
