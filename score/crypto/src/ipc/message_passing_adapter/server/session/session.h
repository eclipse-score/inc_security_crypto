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

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/server_callbacks.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/work_item_execution/i_work_item_submitter.h"

#include <score/span.hpp>
#include <score/unordered_map.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <variant>

namespace score::message_passing
{
class IServerConnection;
}  // namespace score::message_passing

namespace score::crypto::ipc::message_passing::detail
{

struct WorkItem;

enum class SessionState : std::uint8_t
{
    kActive,           ///< Accepts new work and may send responses.
    kDrainingWork,     ///< Rejects new work while admitted work completes.
    kReadyForCleanup,  ///< All admitted work is complete and cleanup may start.
    kCleanupRunning,   ///< The disconnect cleanup callback is executing.
    kCleanupFinished,  ///< Disconnect cleanup completed successfully.
    kCleanupFailed,    ///< Disconnect cleanup failed; the reservation is retained.
};

/**
 * @brief
 * Owns the request and disconnect-cleanup state for one server connection.
 * Tracks admitted work items by request ID and delivers responses on the associated server connection.
 */
class Session final : public std::enable_shared_from_this<Session>
{
  public:
    using CleanupFinishedCallback = std::function<void(daemon::common::ClientId, bool)>;

    /// @brief Creates a session bound to one transport connection and client ID.
    /// @param connection Transport connection owned by the message-passing server.
    /// @param client_id Server-assigned identity for this connection.
    /// @param cleanup_submitter Executor used to schedule disconnect cleanup.
    /// @param cleanup_callback Optional callback that releases client-owned resources.
    /// @param cleanup_finished_callback Notifies the registry when cleanup completes.
    Session(score::message_passing::IServerConnection& connection,
            daemon::common::ClientId client_id,
            IWorkItemSubmitter& cleanup_submitter,
            DisconnectCleanupCallback cleanup_callback,
            CleanupFinishedCallback cleanup_finished_callback) noexcept;

    /// @brief Attempts to admit the given work item into this session.
    /// @param item The work item to admit into the session.
    /// @return An expected containing the admitted work item on success, or an error on failure.
    score::crypto::Expected<std::shared_ptr<WorkItem>, score::crypto::daemon::common::DaemonErrorCode> TryAdmitWorkItem(
        std::shared_ptr<WorkItem> item) noexcept;

    /// @brief Stops admission and response sending without scheduling cleanup.
    /// @note Used by the registry before removing the connection mapping.
    void BeginDisconnect() noexcept;

    /// @brief Continues disconnection and schedules cleanup when the work queue is drained.
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
    daemon::common::ClientId client_id() const noexcept
    {
        return m_client_id;
    }

  private:
    friend struct WorkItem;

    /// @brief Called by WorkItem when it has completed. May trigger cleanup if necessary.
    /// @param item The work item that has completed.
    void OnWorkItemCompleted(const WorkItem& item) noexcept;

    /// @brief Marks the session ready for cleanup when draining has completed.
    /// @param lock A lock guard for the session's mutex.
    /// @return True if the state transitioned to ready-for-cleanup, false otherwise.
    bool MarkReadyForCleanupIfDrained(std::lock_guard<std::mutex>& lock) noexcept;

    /// @brief Starts the cleanup stage for this session.
    void StartCleanupJob() noexcept;

    /// @brief Submitted function at cleanup.
    /// @return The result of the cleanup job.
    IWorkItemSubmitter::JobResult RunCleanup() noexcept;

    /// @brief Begins the cleanup process for this session.
    /// @return True if cleanup was successfully started, false otherwise.
    bool BeginCleanup() noexcept;
    /// @brief Completes the cleanup process for this session.
    /// @param cleanup_succeeded Indicates whether the cleanup was successful.
    void FinishCleanup(bool cleanup_succeeded) noexcept;

    std::mutex m_mutex;
    SessionState m_state{SessionState::kActive};
    const daemon::common::ClientId m_client_id;
    score::message_passing::IServerConnection& m_connection;
    /// Admitted work items indexed by their unique request IDs.
    std::unordered_map<daemon::common::RequestId, std::shared_ptr<WorkItem>> m_work_items{};

    /// Cleanup operation run after disconnect work has drained.
    DisconnectCleanupCallback m_cleanup_callback;
    IWorkItemSubmitter& m_cleanup_submitter;

    // Hint:
    // This shall only be called without the mutex being held, to avoid lock ordering issues.
    // The call is going up to the Registry, which may hold its lock internally.
    /// Reports cleanup completion to the owning registry.
    CleanupFinishedCallback m_cleanup_finished_callback;
};

}  // namespace score::crypto::ipc::message_passing::detail

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_H
