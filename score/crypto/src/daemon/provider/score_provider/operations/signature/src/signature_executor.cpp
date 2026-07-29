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

#include "score/crypto/src/daemon/provider/score_provider/operations/signature/signature_executor.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/signature_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/signature/score_signature_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::signature
{

namespace handler = ::score::crypto::daemon::provider::handler;
namespace actors = ::score::crypto::daemon::common::actors;
namespace sign_ops = ::score::crypto::daemon::provider::handler::sign_handler_operations;
namespace verify_ops = ::score::crypto::daemon::provider::handler::verify_handler_operations;

using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;
using ::score::crypto::daemon::provider::handler::handler_utils::CheckAndGetSpan;

// The sign and verify actors deliberately share one action numbering so that a
// single dispatch table can serve both. Keep the two headers in lock-step.
static_assert(sign_ops::SIGN_INIT == verify_ops::VERIFY_INIT, "sign/verify INIT actions must match");
static_assert(sign_ops::SIGN_UPDATE == verify_ops::VERIFY_UPDATE, "sign/verify UPDATE actions must match");
static_assert(sign_ops::SIGN_FINALIZE == verify_ops::VERIFY_FINALIZE, "sign/verify FINALIZE actions must match");
static_assert(sign_ops::SIGN_SS == verify_ops::VERIFY_SS, "sign/verify single-shot actions must match");
static_assert(sign_ops::SIGN_GET_SIZE == verify_ops::VERIFY_GET_SIZE, "sign/verify GET_SIZE actions must match");
static_assert(sign_ops::SIGN_RESET == verify_ops::VERIFY_RESET, "sign/verify RESET actions must match");

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

Expected<ResponseParameters, DaemonErrorCode> SignatureExecutor::Execute(ScoreSignatureHandler& handler_ref,
                                                                         const common::OperationIdentifier& operationId,
                                                                         RequestParameters& request)
{
    const auto mode_check = ValidateActorMatchesMode(operationId.operationActor, handler_ref);
    if (!mode_check.has_value())
    {
        return make_unexpected(mode_check.error());
    }

    const bool is_verify = (operationId.operationActor == actors::OP_ACTOR_VERIFY_HANDLER);
    const auto action = operationId.operationAction;

    // SIGN_GET_SIZE and VERIFY_GET_SIZE share the same action value.
    if (action == sign_ops::SIGN_GET_SIZE)
    {
        ResponseParameters response;
        response.push_back(static_cast<std::uint64_t>(handler_ref.GetSignatureSize()));
        return response;
    }

    if (action == sign_ops::SIGN_RESET)
    {
        auto res = handler_ref.Reset();
        if (!res.has_value())
        {
            return make_unexpected(res.error());
        }
        return ResponseParameters{};
    }

    if (action == sign_ops::SIGN_SS)
    {
        if (handler_ref.GetOperationState() == StreamOperationState::STREAM_ACTIVE)
        {
            return make_unexpected(DaemonErrorCode::kOperationInProgress);
        }
        auto result =
            is_verify ? ExecuteVerifySingleShot(handler_ref, request) : ExecuteSignSingleShot(handler_ref, request);
        // A single-shot always ends the stream, so the context is left reusable
        // even when the operation failed part-way through.
        handler_ref.SetOperationState(StreamOperationState::IDLE);
        return result;
    }

    // Streaming operations: validate the state machine transition first.
    const StreamOperationState currentState = handler_ref.GetOperationState();
    StreamOperationState nextState = StreamOperationState::IDLE;
    const auto validation = ValidateStreamTransition(action, currentState, nextState);
    if (!validation.has_value())
    {
        return make_unexpected(validation.error());
    }

    if (action == sign_ops::SIGN_INIT)
    {
        auto result = handler_ref.InitSignature();
        if (!result.has_value())
        {
            return make_unexpected(result.error());
        }
        handler_ref.SetOperationState(nextState);
        return ResponseParameters{};
    }

    if (action == sign_ops::SIGN_UPDATE)
    {
        if (request.empty())
        {
            return make_unexpected(DaemonErrorCode::kInsufficientParameters);
        }
        auto result = handler_ref.UpdateSignature(request[0]);
        if (!result.has_value())
        {
            return make_unexpected(result.error());
        }
        handler_ref.SetOperationState(nextState);
        return ResponseParameters{};
    }

    if (action == sign_ops::SIGN_FINALIZE)
    {
        auto result =
            is_verify ? ExecuteVerifyFinalize(handler_ref, request) : ExecuteSignFinalize(handler_ref, request);
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

Expected<ResponseParameters, DaemonErrorCode> SignatureExecutor::ExecuteSignFinalize(ScoreSignatureHandler& handler_ref,
                                                                                     RequestParameters& request)
{
    // request[0] = caller-provided signature output buffer
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    const auto outputSpan = CheckAndGetSpan<std::uint8_t>(request[0]);
    if (!outputSpan.has_value())
    {
        return make_unexpected(outputSpan.error());
    }

    auto written = handler_ref.FinalizeSign(outputSpan.value());
    if (!written.has_value())
    {
        return make_unexpected(written.error());
    }

    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(written.value()));
    return response;
}

Expected<ResponseParameters, DaemonErrorCode> SignatureExecutor::ExecuteSignSingleShot(
    ScoreSignatureHandler& handler_ref,
    RequestParameters& request)
{
    // request[0] = message, request[1] = caller-provided signature output buffer
    if (request.size() < 2U)
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    const auto outputSpan = CheckAndGetSpan<std::uint8_t>(request[1]);
    if (!outputSpan.has_value())
    {
        return make_unexpected(outputSpan.error());
    }

    auto init = handler_ref.InitSignature();
    if (!init.has_value())
    {
        return make_unexpected(init.error());
    }

    auto update = handler_ref.UpdateSignature(request[0]);
    if (!update.has_value())
    {
        return make_unexpected(update.error());
    }

    auto written = handler_ref.FinalizeSign(outputSpan.value());
    if (!written.has_value())
    {
        return make_unexpected(written.error());
    }

    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(written.value()));
    return response;
}

Expected<ResponseParameters, DaemonErrorCode> SignatureExecutor::ExecuteVerifySingleShot(
    ScoreSignatureHandler& handler_ref,
    RequestParameters& request)
{
    // request[0] = message, request[1] = signature
    if (request.size() < 2U)
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    auto init = handler_ref.InitSignature();
    if (!init.has_value())
    {
        return make_unexpected(init.error());
    }

    auto update = handler_ref.UpdateSignature(request[0]);
    if (!update.has_value())
    {
        return make_unexpected(update.error());
    }

    auto verified = handler_ref.FinalizeVerify(request[1]);
    if (!verified.has_value())
    {
        return make_unexpected(verified.error());
    }

    ResponseParameters response;
    response.push_back(verified.value());
    return response;
}

Expected<ResponseParameters, DaemonErrorCode> SignatureExecutor::ExecuteVerifyFinalize(
    ScoreSignatureHandler& handler_ref,
    RequestParameters& request)
{
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    auto verified = handler_ref.FinalizeVerify(request[0]);
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
Expected<std::monostate, DaemonErrorCode> SignatureExecutor::ValidateActorMatchesMode(
    const common::OperationActor actor,
    const ScoreSignatureHandler& handler_ref)
{
    const bool wants_verify = (actor == actors::OP_ACTOR_VERIFY_HANDLER);
    const bool is_verify_ctx = (handler_ref.GetOperationMode() == score::crypto::OperationMode::kVerify);

    if (actor != actors::OP_ACTOR_SIGN_HANDLER && actor != actors::OP_ACTOR_VERIFY_HANDLER)
    {
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }

    // A context bound to the private key must not serve verification requests
    // and vice versa — the key half was chosen at CTX_CREATE time.
    if (wants_verify != is_verify_ctx)
    {
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }

    return std::monostate{};
}

// static
Expected<std::monostate, DaemonErrorCode> SignatureExecutor::ValidateStreamTransition(
    const common::OperationAction action,
    const StreamOperationState currentState,
    StreamOperationState& nextState)
{
    handler::handler_utils::StreamOperation op{};
    if (action == sign_ops::SIGN_INIT)
    {
        op = handler::handler_utils::StreamOperation::kInit;
    }
    else if (action == sign_ops::SIGN_UPDATE)
    {
        op = handler::handler_utils::StreamOperation::kUpdate;
    }
    else if (action == sign_ops::SIGN_FINALIZE)
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

}  // namespace score::crypto::daemon::provider::score_provider::operations::signature
