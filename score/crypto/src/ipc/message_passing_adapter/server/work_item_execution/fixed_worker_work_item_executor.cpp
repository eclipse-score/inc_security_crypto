/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#include "score/crypto/src/ipc/message_passing_adapter/server/work_item_execution/fixed_worker_work_item_executor.h"

#include "score/crypto/src/ipc/message_passing_adapter/server/session/work_item.h"
#include "score/mw/log/logging.h"

#include <new>
#include <utility>

namespace score::crypto::ipc::message_passing
{

FixedWorkerWorkItemExecutor::FixedWorkerWorkItemExecutor(const std::size_t worker_count,
                                                         const std::size_t cleanup_queue_capacity) noexcept
    : m_worker_count(worker_count), m_cleanup_queue_capacity(cleanup_queue_capacity)
{
}

FixedWorkerWorkItemExecutor::~FixedWorkerWorkItemExecutor() noexcept
{
    Shutdown();
    Join();
}

bool FixedWorkerWorkItemExecutor::Start(HandlerFactory handler_factory) noexcept
{
    // StartImpl allocates worker state; clean up any partially initialized executor on failure.
    try
    {
        return StartImpl(std::move(handler_factory));
        // Thread creation can fail after earlier workers have started, so stop and join those workers.
    }
    catch (...)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Failed to start fixed worker executor";
        Shutdown();
        Join();
        return false;
    }
}

bool FixedWorkerWorkItemExecutor::StartImpl(HandlerFactory handler_factory)
{
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_started)
    {
        return false;
    }
    if (m_worker_count == 0U)
    {
        return false;
    }
    m_handler_factory = std::move(handler_factory);
    m_stopping = false;
    m_startup_failed = false;
    m_initialized_worker_count = 0U;
    m_exited_worker_count = 0U;
    m_started = true;
    m_stop_sources.resize(m_worker_count);
    m_worker_conditions.resize(m_worker_count);
    m_assigned_work_items.resize(m_worker_count);
    m_assigned_cleanup_jobs.resize(m_worker_count);
    m_worker_busy.assign(m_worker_count, false);
    m_workers.reserve(m_worker_count);
    // Thread creation may fail after earlier workers start, so stop and join those workers.
    try
    {
        for (std::size_t index = 0U; index < m_worker_count; ++index)
        {
            m_workers.emplace_back([this, index] {
                RunWorker(index);
            });
        }
    }
    catch (...)
    {
        m_stopping = true;
        for (auto& stop_source : m_stop_sources)
        {
            stop_source.request_stop();
        }
        lock.unlock();
        for (auto& worker_condition : m_worker_conditions)
        {
            worker_condition.notify_all();
        }
        Join();
        return false;
    }

    m_startup_condition.wait(lock, [this] {
        return m_startup_failed || (m_initialized_worker_count == m_worker_count);
    });
    if (m_startup_failed)
    {
        m_stopping = true;
        for (auto& stop_source : m_stop_sources)
        {
            stop_source.request_stop();
        }
        lock.unlock();
        for (auto& worker_condition : m_worker_conditions)
        {
            worker_condition.notify_all();
        }
        Join();
        return false;
    }
    return true;
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
FixedWorkerWorkItemExecutor::TrySubmitWorkItem(WorkItemSubmission submission, WorkItemJob job) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_stopping || !m_started)
    {
        score::mw::log::LogWarn()
            << "FixedWorkerWorkItemExecutor::TrySubmitWorkItem: Executor unavailable for request_id="
            << submission.item->GetRequestId();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidState);
    }
    for (std::size_t index = 0U; index < m_worker_count; ++index)
    {
        if (!m_worker_busy.at(index))
        {
            // Moving a user-supplied job into its worker slot may throw.
            try
            {
                m_assigned_work_items.at(index).submission = std::move(submission);
                m_assigned_work_items.at(index).job = std::move(job);
            }
            catch (const std::bad_alloc&)
            {
                score::mw::log::LogError() << "FixedWorkerWorkItemExecutor::TrySubmitWorkItem: Allocation failed";
                return score::crypto::make_unexpected(
                    score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
            }
            catch (...)
            {
                score::mw::log::LogError()
                    << "FixedWorkerWorkItemExecutor::TrySubmitWorkItem: Unexpected assignment failure";
                return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
            }
            m_worker_busy.at(index) = true;
            m_worker_conditions.at(index).notify_one();
            return {};
        }
    }
    score::mw::log::LogWarn() << "FixedWorkerWorkItemExecutor::TrySubmitWorkItem: No idle worker for request_id="
                              << submission.item->GetRequestId();
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
FixedWorkerWorkItemExecutor::TrySubmitCleanup(CleanupJob job) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_stopping || !m_started)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidState);
    }
    for (std::size_t index = 0U; index < m_worker_count; ++index)
    {
        if (!m_worker_busy.at(index))
        {
            // Moving the cleanup callable into its worker slot may throw.
            try
            {
                m_assigned_cleanup_jobs.at(index) = std::move(job);
            }
            catch (const std::bad_alloc&)
            {
                return score::crypto::make_unexpected(
                    score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
            }
            catch (...)
            {
                return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
            }
            m_worker_busy.at(index) = true;
            m_worker_conditions.at(index).notify_one();
            return {};
        }
    }
    if (m_cleanup_jobs.size() >= m_cleanup_queue_capacity)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kResourceBusy);
    }
    // Growing the cleanup deque can allocate; report exhaustion through the submit result.
    try
    {
        m_cleanup_jobs.push_back(std::move(job));
    }
    catch (const std::bad_alloc&)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    return {};
}

void FixedWorkerWorkItemExecutor::Shutdown() noexcept
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_started || m_stopping)
        {
            return;
        }
        m_stopping = true;
        for (auto& stop_source : m_stop_sources)
        {
            stop_source.request_stop();
        }
    }
    for (auto& worker_condition : m_worker_conditions)
    {
        worker_condition.notify_all();
    }
}

void FixedWorkerWorkItemExecutor::Join() noexcept
{
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_worker_exit_condition.wait(lock, [this] {
            return m_exited_worker_count == m_workers.size();
        });
    }
    for (auto& worker : m_workers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }
    m_workers.clear();
    m_stop_sources.clear();
    m_worker_conditions.clear();
    std::lock_guard<std::mutex> lock(m_mutex);
    m_cleanup_jobs.clear();
    m_assigned_work_items.clear();
    m_assigned_cleanup_jobs.clear();
    m_worker_busy.clear();
    m_exited_worker_count = 0U;
    m_started = false;
    m_handler_factory = {};
}

void FixedWorkerWorkItemExecutor::MarkWorkerExited() noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    ++m_exited_worker_count;
    m_worker_exit_condition.notify_all();
}

void FixedWorkerWorkItemExecutor::RunWorker(const std::size_t worker_index) noexcept
{
    std::unique_ptr<daemon::control_plane::IRequestHandler> handler;
    // The configured handler factory is external code and may throw during worker startup.
    try
    {
        handler = m_handler_factory();
    }
    catch (...)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Request-handler factory threw for worker="
                                   << worker_index;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_startup_failed = true;
            ++m_initialized_worker_count;
            for (auto& stop_source : m_stop_sources)
            {
                stop_source.request_stop();
            }
            m_startup_condition.notify_all();
        }
        MarkWorkerExited();
        return;
    }
    if (handler == nullptr)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Request-handler factory returned null for worker="
                                   << worker_index;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_startup_failed = true;
            ++m_initialized_worker_count;
            for (auto& stop_source : m_stop_sources)
            {
                stop_source.request_stop();
            }
            m_startup_condition.notify_all();
        }
        MarkWorkerExited();
        return;
    }
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_initialized_worker_count;
        m_startup_condition.notify_all();
    }
    // Keep unexpected loop failures from escaping the worker thread and signal its exit to Join().
    try
    {
        RunWorkerLoop(worker_index, *handler, m_stop_sources.at(worker_index).get_token());
    }
    catch (...)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Worker loop failed for worker=" << worker_index;
        MarkWorkerExited();
    }
}

void FixedWorkerWorkItemExecutor::RunWorkerLoop(const std::size_t worker_index,
                                                daemon::control_plane::IRequestHandler& handler,
                                                const score::cpp::stop_token& stop_token)
{
    while (true)
    {
        AssignedWorkItem work_item;
        CleanupJob cleanup_job;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_worker_conditions.at(worker_index).wait(lock, [this, worker_index] {
                return m_stopping || m_assigned_work_items.at(worker_index).job ||
                       m_assigned_cleanup_jobs.at(worker_index);
            });
            if (m_assigned_cleanup_jobs.at(worker_index))
            {
                cleanup_job = std::move(m_assigned_cleanup_jobs.at(worker_index));
            }
            else if (m_assigned_work_items.at(worker_index).job)
            {
                work_item = std::move(m_assigned_work_items.at(worker_index));
            }
            else if (m_stopping)
            {
                lock.unlock();
                MarkWorkerExited();
                return;
            }
            else
            {
                continue;
            }
        }
        ExecuteJob(std::move(work_item), std::move(cleanup_job), handler, stop_token);
        CompleteWork(worker_index);
    }
}

void FixedWorkerWorkItemExecutor::ExecuteJob(AssignedWorkItem work_item,
                                             CleanupJob cleanup_job,
                                             daemon::control_plane::IRequestHandler& handler,
                                             const score::cpp::stop_token& stop_token) noexcept
{
    if (cleanup_job)
    {
        // The cleanup-job type permits throwing callables; contain failures to keep this worker alive.
        try
        {
            static_cast<void>(cleanup_job());
        }
        catch (...)
        {
            score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Cleanup job threw an exception";
        }
    }
    else if (work_item.job)
    {
        // The job type permits throwing callables; contain failures to keep this worker alive.
        try
        {
            const auto result = work_item.job(work_item.submission, handler, stop_token);
            if (!result.has_value())
            {
                score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Work-item job failed for client_id="
                                           << work_item.submission.item->GetClientId()
                                           << ", request_id=" << work_item.submission.item->GetRequestId()
                                           << " (error=" << static_cast<int>(result.error()) << ")";
            }
        }
        catch (...)
        {
            score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Work-item job threw for client_id="
                                       << work_item.submission.item->GetClientId()
                                       << ", request_id=" << work_item.submission.item->GetRequestId();
        }
    }
}

void FixedWorkerWorkItemExecutor::CompleteWork(const std::size_t worker_index) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_worker_busy.at(worker_index) = false;
    if (!m_cleanup_jobs.empty())
    {
        m_assigned_cleanup_jobs.at(worker_index) = std::move(m_cleanup_jobs.front());
        m_cleanup_jobs.pop_front();
        m_worker_busy.at(worker_index) = true;
        m_worker_conditions.at(worker_index).notify_one();
    }
}

}  // namespace score::crypto::ipc::message_passing
