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

#include "score/crypto/src/ipc/message_passing_adapter/server/session/session.h"

#include "score/crypto/src/ipc/message_passing_adapter/ipc_config.h"

#include "score/mw/log/logging.h"
#include "score/os/errno.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <new>
#include <utility>

namespace score::crypto::ipc::message_passing::detail
{
namespace
{

score::crypto::daemon::common::DaemonErrorCode MapTransportError(const score::os::Error& error) noexcept
{
    const auto os_error = error.GetOsDependentErrorCode();
    if ((os_error == EAGAIN) || (os_error == EWOULDBLOCK) || (os_error == ENOBUFS) || (os_error == EBUSY))
    {
        return score::crypto::daemon::common::DaemonErrorCode::kProviderBusy;
    }
    if (os_error == ENOMEM)
    {
        return score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed;
    }
    if ((os_error == EACCES) || (os_error == EPERM))
    {
        return score::crypto::daemon::common::DaemonErrorCode::kAccessDenied;
    }
    if ((os_error == EINVAL) || (os_error == EMSGSIZE))
    {
        return score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat;
    }
    if ((os_error == ENOENT) || (os_error == ESHUTDOWN) || (os_error == EPIPE))
    {
        return score::crypto::daemon::common::DaemonErrorCode::kConnectionFailed;
    }
    return score::crypto::daemon::common::DaemonErrorCode::kInternalError;
}

}  // namespace

Session::Session(score::message_passing::IServerConnection& connection,
                 const daemon::control_plane::protocol::ClientId client_id,
                 IWorkItemSubmitter& cleanup_submitter,
                 DisconnectCleanupCallback cleanup_callback,
                 CleanupFinishedCallback cleanup_finished_callback) noexcept
    : m_client_id(client_id),
      m_connection(connection),
      m_cleanup_callback(std::move(cleanup_callback)),
      m_cleanup_submitter(cleanup_submitter),
      m_cleanup_finished_callback(std::move(cleanup_finished_callback))
{
}

score::crypto::Expected<std::shared_ptr<WorkItem>, score::crypto::daemon::common::DaemonErrorCode>
Session::TryAdmitWorkItem(std::shared_ptr<WorkItem> item) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != SessionState::kActive)
    {
        score::mw::log::LogWarn() << "Session::TryAdmitWorkItem: Connection is no longer active for client_id="
                                  << m_client_id;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kConnectionFailed);
    }
    if (m_work_items.size() >= ipc::kMaxOutstandingOperationsPerConnection)
    {
        score::mw::log::LogWarn() << "Session::TryAdmitWorkItem: Capacity reached for client_id=" << m_client_id
                                  << ", request_id=" << item->GetRequestId();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
    }
    bool inserted{false};
    // Work-item admission can allocate a map node; translate allocation and unexpected failures to crypto errors.
    try
    {
        inserted = m_work_items.try_emplace(item->request_id, item).second;
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError() << "Session::TryAdmitWorkItem: Allocation failed for client_id=" << m_client_id
                                   << ", request_id=" << item->GetRequestId();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        score::mw::log::LogError() << "Session::TryAdmitWorkItem: Unexpected insertion failure for client_id="
                                   << m_client_id << ", request_id=" << item->GetRequestId();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    if (!inserted)
    {
        score::mw::log::LogWarn() << "Session::TryAdmitWorkItem: Duplicate request_id=" << item->GetRequestId()
                                  << " for client_id=" << m_client_id;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
    }
    return item;
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
Session::RequestCancellationByRequestId(const daemon::control_plane::protocol::RequestId cancel_request_id) noexcept
{
    std::shared_ptr<WorkItem> item;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto iterator = m_work_items.find(cancel_request_id);
        if (iterator != m_work_items.end())
        {
            item = iterator->second;
        }
    }
    if (item == nullptr)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidState);
    }

    item->TryRequestCancellation();
    return {};
}

void Session::CancelAllPendingWorkItems() noexcept
{
    std::array<std::shared_ptr<WorkItem>, ipc::kMaxOutstandingOperationsPerConnection> to_cancel{};
    std::size_t cancellation_count{0U};
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& entry : m_work_items)
        {
            to_cancel[cancellation_count] = entry.second;
            ++cancellation_count;
        }
    }

    for (std::size_t index = 0U; index < cancellation_count; ++index)
    {
        static_cast<void>(to_cancel[index]->TryRequestCancellation());
    }
}

void Session::OnWorkItemCompleted(const WorkItem& item) noexcept
{
    bool cleanup_ready{false};
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto iterator = m_work_items.find(item.request_id);
        if ((iterator == m_work_items.end()) || (iterator->second.get() != &item))
        {
            return;
        }
        m_work_items.erase(iterator);
        cleanup_ready = ClaimCleanupIfReady(lock);
    }
    if (cleanup_ready)
    {
        ScheduleCleanupJob();
    }
}

bool Session::ClaimCleanupIfReady(std::lock_guard<std::mutex>& lock) noexcept
{
    static_cast<void>(lock);
    if ((m_state != SessionState::kDrainingWork) || !m_work_items.empty())
    {
        return false;
    }
    m_state = SessionState::kReadyForCleanup;
    return true;
}

void Session::ScheduleCleanupJob() noexcept
{
    if (!m_cleanup_callback)
    {
        FinishCleanup(true);
        return;
    }

    const auto session = shared_from_this();
    auto submit_result =
        score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>{std::monostate{}};
    try
    {
        submit_result = m_cleanup_submitter.TrySubmitCleanup([session]() noexcept {
            return session->RunCleanup();
        });
    }
    catch (...)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Cleanup submission threw for client_id=" << m_client_id;
        FinishCleanup(false);
        return;
    }
    if (!submit_result.has_value())
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Failed to schedule disconnect cleanup for client_id="
                                   << m_client_id << " (error=" << static_cast<int>(submit_result.error()) << ")";
        FinishCleanup(false);
    }
}

void Session::Disconnect() noexcept
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state == SessionState::kCleanupFinished || m_state == SessionState::kCleanupFailed)
        {
            return;
        }
        if (m_state == SessionState::kActive)
        {
            m_state = SessionState::kDrainingWork;
        }
    }

    CancelAllPendingWorkItems();

    bool cleanup_ready{false};
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        cleanup_ready = ClaimCleanupIfReady(lock);
    }

    // If cleanup is ready, schedule the cleanup job.
    // Otherwise, cleanup will be scheduled later when the last work item completes.
    if (cleanup_ready)
    {
        ScheduleCleanupJob();
    }
}

IWorkItemSubmitter::JobResult Session::RunCleanup() noexcept
{
    if (!BeginCleanup())
    {
        FinishCleanup(false);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidState);
    }

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> cleanup_result;
    try
    {
        cleanup_result = m_cleanup_callback(m_client_id);
    }
    catch (...)
    {
        cleanup_result = score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    const bool cleanup_succeeded = cleanup_result.has_value();
    if (!cleanup_succeeded)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Disconnect cleanup failed for client_id=" << m_client_id
                                   << " (error=" << static_cast<int>(cleanup_result.error()) << ")";
    }
    FinishCleanup(cleanup_succeeded);
    if (!cleanup_result.has_value())
    {
        return score::crypto::make_unexpected(cleanup_result.error());
    }
    return {};
}

bool Session::BeginCleanup() noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != SessionState::kReadyForCleanup)
    {
        score::mw::log::LogWarn() << "[MESSAGE_PASSING_SERVER] Cleanup requested in unexpected state for client_id="
                                  << m_client_id << " (state=" << static_cast<int>(m_state) << ")";
        return false;
    }
    m_state = SessionState::kCleanupRunning;
    return true;
}

void Session::FinishCleanup(const bool cleanup_succeeded) noexcept
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if ((m_state == SessionState::kReadyForCleanup) || (m_state == SessionState::kCleanupRunning))
        {
            m_state = cleanup_succeeded ? SessionState::kCleanupFinished : SessionState::kCleanupFailed;
        }
        else
        {
            score::mw::log::LogWarn() << "[MESSAGE_PASSING_SERVER] Cleanup completed in unexpected state for client_id="
                                      << m_client_id << " (state=" << static_cast<int>(m_state) << ")";
        }
    }
    if (m_cleanup_finished_callback)
    {
        try
        {
            m_cleanup_finished_callback(m_client_id, cleanup_succeeded);
        }
        catch (...)
        {
            score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Cleanup completion callback threw for client_id="
                                       << m_client_id;
        }
    }
}

bool Session::IsActive() noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_state == SessionState::kActive;
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Session::Respond(
    const score::cpp::span<const std::uint8_t> bytes) noexcept
{
    // QNX queues Notify() messages in preallocated per-connection storage, so the transport call is
    // non-blocking apart from this mutex and can fail with ENOBUFS when the queue is full. Linux uses the
    // Unix-domain transport's SendProtocolMessage() directly; a slow peer or transport backpressure may
    // therefore hold this mutex and delay disconnect/lifecycle progress. Neither backend's own locking
    // (verified against both self-owning ServerConnection implementations) protects a Notify() call
    // against concurrent connection teardown -- this mutex, held for the whole call and shared with
    // Disconnect(), is what prevents a worker thread from touching a connection object the transport's
    // dispatch thread is concurrently destroying.
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != SessionState::kActive)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kConnectionFailed);
    }
    const auto notify_result = m_connection.Notify(bytes);
    if (!notify_result.has_value())
    {
        return score::crypto::make_unexpected(MapTransportError(notify_result.error()));
    }
    return {};
}

}  // namespace score::crypto::ipc::message_passing::detail
