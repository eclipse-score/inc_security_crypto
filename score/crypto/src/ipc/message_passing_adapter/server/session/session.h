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

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_H

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/server_callbacks.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/session/work_item.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/work_item_execution/i_work_item_submitter.h"

#include "score/message_passing/i_server_connection.h"

#include <score/span.hpp>
#include <score/unordered_map.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>

namespace score::crypto::ipc::message_passing::detail
{

enum class SessionState : std::uint8_t
{
    kActive,
    kDrainingWork,
    kReadyForCleanup,
    kCleanupRunning,
    kCleanupFinished,
    kCleanupFailed,
};

/**
 * @brief
 * Owns the request and disconnect-cleanup state for one server connection.
 * Tracks admitted work items by request ID, coordinates cancellation, and delivers responses on
 * the associated server connection.
 * @endrst
 */
class Session final : public std::enable_shared_from_this<Session>
{
  public:
    using CleanupFinishedCallback = std::function<void(daemon::control_plane::protocol::ClientId, bool)>;

    Session(score::message_passing::IServerConnection& connection,
            daemon::control_plane::protocol::ClientId client_id,
            IWorkItemSubmitter& cleanup_submitter,
            DisconnectCleanupCallback cleanup_callback,
            CleanupFinishedCallback cleanup_finished_callback) noexcept;

    /// @brief Attempts to admit the given work item into this session.
    /// @param item The work item to admit into the session.
    /// @return An expected containing the admitted work item on success, or an error on failure.
    score::crypto::Expected<std::shared_ptr<WorkItem>, score::crypto::daemon::common::DaemonErrorCode> TryAdmitWorkItem(
        std::shared_ptr<WorkItem> item) noexcept;

    /// @brief Requests cancellation of the work item identified by the given request ID.
    /// @param cancel_request_id The unique request ID of the work item to cancel.
    /// @return An expected indicating success or failure of the cancellation request.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    RequestCancellationByRequestId(daemon::control_plane::protocol::RequestId cancel_request_id) noexcept;

    /// @brief Requests cancellation of all pending work items in this session.
    void CancelAllPendingWorkItems() noexcept;

    /// @brief Initiates the disconnection process for this session, triggering cleanup if necessary.
    void Disconnect() noexcept;

    /// @brief Checks if the session is currently active.
    /// @return True if the session is active, false otherwise.
    bool IsActive() noexcept;

    /// @brief Sends a response message for this session.
    /// @param bytes The response message bytes to send.
    /// @return An expected indicating success or failure of the response operation.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Respond(
        score::cpp::span<const std::uint8_t> bytes) noexcept;

    /// @brief Retrieves the client ID associated with this session.
    /// @return The client ID of this session.
    daemon::control_plane::protocol::ClientId client_id() const noexcept
    {
        return client_id_;
    }

  private:
    friend struct WorkItem;

    /// @brief Called by WorkItem when it has completed. May trigger cleanup if necessary.
    /// @param item The work item that has completed.
    void OnWorkItemCompleted(const WorkItem& item) noexcept;

    /// @brief Attempts to claim cleanup responsibility if the session is ready for cleanup.
    /// @param lock A lock guard for the session's mutex.
    /// @return True if cleanup was successfully claimed, false otherwise.
    bool ClaimCleanupIfReady(std::lock_guard<std::mutex>& lock) noexcept;

    /// @brief Schedules a cleanup job for this session.
    void ScheduleCleanupJob() noexcept;

    /// @brief Submitted function at cleanup.
    /// @return The result of the cleanup job.
    IWorkItemSubmitter::JobResult RunCleanup() noexcept;

    /// @brief Begins the cleanup process for this session.
    /// @return True if cleanup was successfully started, false otherwise.
    bool BeginCleanup() noexcept;
    /// @brief Completes the cleanup process for this session.
    /// @param cleanup_succeeded Indicates whether the cleanup was successful.
    void FinishCleanup(bool cleanup_succeeded) noexcept;

    std::mutex mutex_;
    SessionState state_{SessionState::kActive};
    const daemon::control_plane::protocol::ClientId client_id_;
    score::message_passing::IServerConnection& connection_;
    // Workitem of this session, keyed by their unique request IDs.
    std::unordered_map<daemon::control_plane::protocol::RequestId, std::shared_ptr<WorkItem>> work_items_{};

    // Function to schedule when connection is closed / lost
    DisconnectCleanupCallback cleanup_callback_;
    IWorkItemSubmitter& cleanup_submitter_;

    // Hint:
    // This shall only be called without the mutex being held, to avoid lock ordering issues.
    // The call is going up to the Registry, which may hold its lock internally.
    CleanupFinishedCallback cleanup_finished_callback_;
};

}  // namespace score::crypto::ipc::message_passing::detail

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_H
