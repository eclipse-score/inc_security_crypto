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

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/ipc/message_passing_adapter/protocol/i_control_codec.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/work_item_execution/i_work_item_submitter.h"

#include "score/message_passing/i_server_connection.h"

#include <score/span.hpp>
#include <score/stop_token.hpp>

#include <cstdint>
#include <memory>
#include <optional>

namespace score::crypto::ipc::message_passing
{

class SessionManager;

/**
 * @brief
 * Routes decoded requests to per-connection sessions and worker execution.
 * Dispatches operation admission and cancellation, then coordinates response delivery. Per-request
 * state is owned by Session rather than by the dispatcher.
 * @endrst
 */
class WorkItemDispatcher final
{
  public:
    WorkItemDispatcher(SessionManager& session_manager,
                       IWorkItemSubmitter& submitter,
                       const IControlCodec& codec) noexcept;

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> OnRequest(
        score::message_passing::IServerConnection& connection,
        score::cpp::span<const std::uint8_t> message) noexcept;

  private:
    using WorkItem = detail::WorkItem;

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> HandleCancellationRequest(
        const std::shared_ptr<detail::Session>& session,
        daemon::control_plane::protocol::RequestId request_id) noexcept;
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> HandleWorkItem(
        const std::shared_ptr<detail::Session>& session,
        std::shared_ptr<WorkItem> item) noexcept;
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> RespondAndCompleteWorkItem(
        const std::shared_ptr<detail::Session>& session,
        const std::shared_ptr<WorkItem>& item,
        score::crypto::Expected<daemon::control_plane::protocol::ControlResponse,
                                score::crypto::daemon::common::DaemonErrorCode> response) noexcept;
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> RunAcceptedWorkItem(
        const std::shared_ptr<detail::Session>& session,
        const std::shared_ptr<WorkItem>& item,
        daemon::control_plane::IRequestHandler& handler,
        const score::cpp::stop_token& stop_token) noexcept;
    static score::crypto::Expected<daemon::control_plane::protocol::ControlResponse,
                                   score::crypto::daemon::common::DaemonErrorCode>
    BuildEnvelopeErrorResponse(const daemon::control_plane::protocol::RequestId request_id,
                               const score::crypto::daemon::common::DaemonErrorCode error) noexcept;

    SessionManager& session_manager_;
    IWorkItemSubmitter& submitter_;
    const IControlCodec& codec_;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_WORK_ITEM_DISPATCHER_H
