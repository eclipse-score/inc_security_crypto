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

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_WORK_ITEM_DISPATCHER_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_WORK_ITEM_DISPATCHER_H

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <score/span.hpp>

#include <cstdint>
#include <memory>

namespace score::crypto::daemon::control_plane
{
class IRequestHandler;
}  // namespace score::crypto::daemon::control_plane

namespace score::crypto::ipc::protocol
{
class IControlCodec;
}  // namespace score::crypto::ipc::protocol

namespace score::message_passing
{
class IServerConnection;
}  // namespace score::message_passing

namespace score::crypto::ipc::message_passing
{

class SessionManager;
class IWorkItemSubmitter;

namespace detail
{
class Session;
struct WorkItem;
}  // namespace detail

/**
 * @brief
 * Routes decoded requests to per-connection sessions and worker execution.
 * Dispatches operation admission and coordinates response delivery. Per-request state is owned by
 * Session rather than by the dispatcher.
 */
class WorkItemDispatcher final
{
  public:
    /// @brief To handle worktime and dispatch request for processing.
    /// @param session_manager Session manager used to find the connection's session.
    /// @param submitter Executor that accepts admitted work.
    /// @param codec Codec used to validate and serialize protocol messages.
    WorkItemDispatcher(SessionManager& session_manager,
                       IWorkItemSubmitter& submitter,
                       const score::crypto::ipc::protocol::IControlCodec& codec) noexcept;

    /// @brief Validates and dispatches a request received on a transport connection and sends the response after
    /// processing.
    /// @param connection Connection that delivered the request.
    /// @param message Serialized control request bytes.
    /// @return Success if handled or deliberately dropped with a response to the client, or a daemon error for
    /// transport reporting.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> OnRequest(
        score::message_passing::IServerConnection& connection,
        score::cpp::span<const std::uint8_t> message) noexcept;

  private:
    using WorkItem = detail::WorkItem;

    /// @brief Admits a work item and submits it to the executor.
    /// @param session Session that owns the request.
    /// @param item Validated work item to admit.
    /// @return Success when submitted, or an admission/submission error.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> HandleWorkItem(
        const std::shared_ptr<detail::Session>& session,
        std::shared_ptr<WorkItem> item) noexcept;

    /// @brief Sends a response and marks the work item complete.
    /// @param session Session used to send the response.
    /// @param item Work item whose response is being completed.
    /// @param response Response value or error to encode.
    /// @return Success if response handling completed, or an error if encoding/sending failed.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> RespondAndCompleteWorkItem(
        const std::shared_ptr<detail::Session>& session,
        const std::shared_ptr<WorkItem>& item,
        score::crypto::Expected<daemon::control_plane::protocol::ControlResponse,
                                score::crypto::daemon::common::DaemonErrorCode> response) noexcept;

    /// @brief Decodes and executes an admitted work item on a worker.
    /// @param session Session used for response delivery and completion tracking.
    /// @param item Admitted request to process.
    /// @param handler Worker-owned request handler.
    /// @return Success when processing completes, or an error for processing/response failure.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> RunAcceptedWorkItem(
        const std::shared_ptr<detail::Session>& session,
        const std::shared_ptr<WorkItem>& item,
        daemon::control_plane::IRequestHandler& handler) noexcept;

    /// @brief Builds a protocol response based on a daemon error. Used to generate error responses for the client. If
    /// proper processing is not possible.
    /// @param request_id Request ID to correlate with the client call.
    /// @param error Error to encode in the operation result.
    /// @return The encoded error response, or an error if response construction fails.
    static score::crypto::Expected<daemon::control_plane::protocol::ControlResponse,
                                   score::crypto::daemon::common::DaemonErrorCode>
    BuildEnvelopeErrorResponse(const daemon::control_plane::protocol::RequestId request_id,
                               const score::crypto::daemon::common::DaemonErrorCode error) noexcept;

    /// @brief Sends a error response to the client, if proper processing is not possible.
    /// @param session Session used for response delivery.
    /// @param item Work item carrying the request ID.
    /// @param error Daemon error to send.
    /// @return Success if the error response was handled, or an error if construction/sending failed.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> RespondWithEnvelopeError(
        const std::shared_ptr<detail::Session>& session,
        const std::shared_ptr<WorkItem>& item,
        const score::crypto::daemon::common::DaemonErrorCode error) noexcept;

    SessionManager& m_session_manager;
    IWorkItemSubmitter& m_submitter;
    const score::crypto::ipc::protocol::IControlCodec& m_codec;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_WORK_ITEM_DISPATCHER_H
