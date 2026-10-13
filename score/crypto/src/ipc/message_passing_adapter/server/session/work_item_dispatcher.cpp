/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#include "score/crypto/src/ipc/message_passing_adapter/server/session/work_item_dispatcher.h"

#include "score/crypto/src/ipc/message_passing_adapter/ipc_config.h"
#include "score/crypto/src/ipc/message_passing_adapter/protocol/i_control_codec.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/session/session.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/session/session_manager.h"

#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/mw/log/logging.h"

#include <chrono>
#include <new>
#include <optional>
#include <utility>
#include <vector>

namespace score::crypto::ipc::message_passing
{

using DaemonErrorCode = score::crypto::daemon::common::DaemonErrorCode;
namespace protocol = daemon::control_plane::protocol;

namespace
{
DaemonErrorCode MapCodecError(const score::crypto::CryptoErrorCode error) noexcept
{
    switch (error)
    {
        case score::crypto::CryptoErrorCode::kAllocationFailed:
            return DaemonErrorCode::kAllocationFailed;
        case score::crypto::CryptoErrorCode::kInvalidFormat:
            return DaemonErrorCode::kInvalidFormat;
        default:
            return DaemonErrorCode::kInternalError;
    }
}
}  // namespace

WorkItemDispatcher::WorkItemDispatcher(SessionManager& session_manager,
                                       IWorkItemSubmitter& submitter,
                                       const IControlCodec& codec) noexcept
    : session_manager_(session_manager), submitter_(submitter), codec_(codec)
{
}

score::crypto::Expected<std::monostate, DaemonErrorCode> WorkItemDispatcher::OnRequest(
    score::message_passing::IServerConnection& connection,
    score::cpp::span<const std::uint8_t> message) noexcept
{
    const auto received_at = std::chrono::steady_clock::now();
    if (message.size() > ipc::kMaxPayloadBytes)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Rejected oversized request (size=" << message.size()
                                   << ")";
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }
    const auto session = session_manager_.FindSessionForRequest(connection);
    if (session == nullptr)
    {
        score::mw::log::LogWarn() << "[MESSAGE_PASSING_SERVER] Request received without a registered session (size="
                                  << message.size() << ")";
        return score::crypto::make_unexpected(DaemonErrorCode::kConnectionFailed);
    }
    if (!session->IsActive())
    {
        score::mw::log::LogWarn() << "[MESSAGE_PASSING_SERVER] Request received for an inactive session (size="
                                  << message.size() << ")";
        return score::crypto::make_unexpected(DaemonErrorCode::kConnectionFailed);
    }
    auto request_item_result = WorkItem::Create(message, session, codec_, received_at);
    if (!request_item_result.has_value())
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Failed to create request work item (error="
                                   << static_cast<int>(request_item_result.error()) << ", size=" << message.size()
                                   << ")";
        return score::crypto::make_unexpected(request_item_result.error());
    }
    auto item = std::move(request_item_result).value();
    const auto request_id = item->GetRequestId();
    auto result = HandleWorkItem(session, std::move(item));
    if (!result.has_value())
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Failed to handle request request_id=" << request_id
                                   << " (error=" << static_cast<int>(result.error()) << ")";
    }
    return result;
}

score::crypto::Expected<std::monostate, DaemonErrorCode> WorkItemDispatcher::HandleWorkItem(
    const std::shared_ptr<detail::Session>& session,
    std::shared_ptr<WorkItem> item) noexcept
{
    if (item->GetKind() == protocol::ControlRequestKind::kCancel)
    {
        // Nothing we can do if the cancellation request fails
        static_cast<void>(session->RequestCancellationByRequestId(item->GetRequestId()));
        return {};
    }

    const auto admission_result = session->TryAdmitWorkItem(item);
    if (!admission_result.has_value())
    {
        const auto admission_error = admission_result.error();
        auto response = BuildEnvelopeErrorResponse(item->GetRequestId(), admission_error);
        return RespondAndCompleteWorkItem(session, item, std::move(response));
    }

    // If accepted, RunAcceptedWorkItem owns the request's terminal response.
    IWorkItemSubmitter::WorkItemProcessor processor;
    try
    {
        processor = [this](const WorkItemSubmission& submission,
                           daemon::control_plane::IRequestHandler& handler,
                           const score::cpp::stop_token& stop_token) {
            return RunAcceptedWorkItem(submission.session, submission.item, handler, stop_token);
        };
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Failed to allocate work-item processor for request_id="
                                   << item->GetRequestId();
        auto response = BuildEnvelopeErrorResponse(item->GetRequestId(), DaemonErrorCode::kAllocationFailed);
        return RespondAndCompleteWorkItem(session, item, std::move(response));
    }
    catch (...)
    {
        score::mw::log::LogError()
            << "[MESSAGE_PASSING_SERVER] Unexpected failure while creating work-item processor for request_id="
            << item->GetRequestId();
        auto response = BuildEnvelopeErrorResponse(item->GetRequestId(), DaemonErrorCode::kInternalError);
        return RespondAndCompleteWorkItem(session, item, std::move(response));
    }

    const auto submit_result = submitter_.TrySubmitWorkItem(WorkItemSubmission{session, item}, std::move(processor));
    if (submit_result.has_value())
    {
        return score::crypto::Expected<std::monostate, DaemonErrorCode>{};
    }

    auto response = BuildEnvelopeErrorResponse(item->GetRequestId(), submit_result.error());
    return RespondAndCompleteWorkItem(session, item, std::move(response));
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
WorkItemDispatcher::RunAcceptedWorkItem(const std::shared_ptr<detail::Session>& session,
                                        const std::shared_ptr<WorkItem>& item,
                                        daemon::control_plane::IRequestHandler& handler,
                                        const score::cpp::stop_token& stop_token) noexcept
{
    // Handler calls and response construction may throw; finalize the admitted item before reporting failure.
    try
    {
        const auto deserialize_result = item->DeserializeRequest(codec_);
        if (!deserialize_result.has_value())
        {
            const auto error = deserialize_result.error();
            score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Failed to deserialize accepted request request_id="
                                       << item->GetRequestId() << " (error=" << static_cast<int>(error) << ")";
            auto response = BuildEnvelopeErrorResponse(item->GetRequestId(), error);
            return RespondAndCompleteWorkItem(session, item, std::move(response));
        }

        const auto work_item_state = item->PrepareForExecution();
        switch (work_item_state)
        {
            case detail::WorkItemState::kRunning:
            {
                auto response = handler.processRequest(item->GetRequest(), item->GetCancellationToken());
                return RespondAndCompleteWorkItem(session, item, {std::move(response)});
            }
            case detail::WorkItemState::kCancelled:
            {
                auto response = BuildEnvelopeErrorResponse(item->GetRequestId(), DaemonErrorCode::kOperationCancelled);
                return RespondAndCompleteWorkItem(session, item, std::move(response));
            }
            case detail::WorkItemState::kDeadlineExpired:
            {
                auto response = BuildEnvelopeErrorResponse(item->GetRequestId(), DaemonErrorCode::kOperationTimedOut);
                return RespondAndCompleteWorkItem(session, item, std::move(response));
            }
            default:
            {
                score::mw::log::LogError()
                    << "[MESSAGE_PASSING_SERVER] Invalid work-item state for request_id=" << item->GetRequestId();
                auto response = BuildEnvelopeErrorResponse(item->GetRequestId(), DaemonErrorCode::kInternalError);
                return RespondAndCompleteWorkItem(session, item, std::move(response));
            }
        }
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Allocation failed while processing request_id="
                                   << item->GetRequestId();
        auto response = BuildEnvelopeErrorResponse(item->GetRequestId(), DaemonErrorCode::kAllocationFailed);
        return RespondAndCompleteWorkItem(session, item, std::move(response));
    }
    catch (...)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Unexpected failure while processing request_id="
                                   << item->GetRequestId();
        auto response = BuildEnvelopeErrorResponse(item->GetRequestId(), DaemonErrorCode::kInternalError);
        return RespondAndCompleteWorkItem(session, item, std::move(response));
    }
}

score::crypto::Expected<protocol::ControlResponse, score::crypto::daemon::common::DaemonErrorCode>
WorkItemDispatcher::BuildEnvelopeErrorResponse(const protocol::RequestId request_id,
                                               const DaemonErrorCode error) noexcept
{
    // The response builder may allocate; signal failure to callers with an empty optional.
    try
    {
        protocol::OperationResponseBuilder response_builder;
        response_builder.operation(protocol::kEnvelopeErrorOperationIdentifier).return_error(ToCryptoErrorCode(error));
        auto operation_response = response_builder.build();
        if (!operation_response.has_value())
        {
            const auto error = MapCodecError(operation_response.error());
            score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Failed to build error response (error="
                                       << static_cast<int>(error) << ")";
            return score::crypto::make_unexpected(error);
        }
        return protocol::ControlResponse{request_id, std::move(operation_response).value()};
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError()
            << "[MESSAGE_PASSING_SERVER] Allocation failed while building error response for request_id=" << request_id;
        return score::crypto::make_unexpected(DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        score::mw::log::LogError()
            << "[MESSAGE_PASSING_SERVER] Unexpected failure while building error response for request_id="
            << request_id;
        return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    }
}

score::crypto::Expected<std::monostate, DaemonErrorCode> WorkItemDispatcher::RespondAndCompleteWorkItem(
    const std::shared_ptr<detail::Session>& session,
    const std::shared_ptr<WorkItem>& item,
    score::crypto::Expected<protocol::ControlResponse, DaemonErrorCode> response) noexcept
{
    if (!response.has_value())
    {
        item->Complete();
        return score::crypto::make_unexpected(response.error());
    }

    const auto response_bytes = codec_.SerializeResponse(response.value());
    if (!response_bytes.has_value())
    {
        item->Complete();
        return score::crypto::make_unexpected(MapCodecError(response_bytes.error()));
    }
    if (response_bytes->size() > ipc::kMaxPayloadBytes)
    {
        item->Complete();
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }

    const auto respond_result =
        session->Respond(score::cpp::span<const std::uint8_t>{response_bytes->data(), response_bytes->size()});
    item->Complete();
    return respond_result;
}

}  // namespace score::crypto::ipc::message_passing
