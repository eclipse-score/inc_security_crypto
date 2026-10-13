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
    : worker_count_(worker_count), cleanup_queue_capacity_(cleanup_queue_capacity)
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
    std::unique_lock<std::mutex> lock(mutex_);
    if (started_)
    {
        return false;
    }
    if (worker_count_ == 0U)
    {
        return false;
    }
    handler_factory_ = std::move(handler_factory);
    stopping_ = false;
    startup_failed_ = false;
    initialized_worker_count_ = 0U;
    exited_worker_count_ = 0U;
    started_ = true;
    stop_sources_.resize(worker_count_);
    worker_conditions_.resize(worker_count_);
    assigned_work_items_.resize(worker_count_);
    assigned_cleanup_jobs_.resize(worker_count_);
    worker_busy_.assign(worker_count_, false);
    workers_.reserve(worker_count_);
    // Thread creation may fail after earlier workers start, so stop and join those workers.
    try
    {
        for (std::size_t index = 0U; index < worker_count_; ++index)
        {
            workers_.emplace_back([this, index] {
                RunWorker(index);
            });
        }
    }
    catch (...)
    {
        stopping_ = true;
        for (auto& stop_source : stop_sources_)
        {
            stop_source.request_stop();
        }
        lock.unlock();
        for (auto& worker_condition : worker_conditions_)
        {
            worker_condition.notify_all();
        }
        Join();
        return false;
    }

    startup_condition_.wait(lock, [this] {
        return startup_failed_ || (initialized_worker_count_ == worker_count_);
    });
    if (startup_failed_)
    {
        stopping_ = true;
        for (auto& stop_source : stop_sources_)
        {
            stop_source.request_stop();
        }
        lock.unlock();
        for (auto& worker_condition : worker_conditions_)
        {
            worker_condition.notify_all();
        }
        Join();
        return false;
    }
    return true;
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
FixedWorkerWorkItemExecutor::TrySubmitWorkItem(WorkItemSubmission submission, WorkItemProcessor processor) noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (stopping_ || !started_)
    {
        score::mw::log::LogWarn()
            << "FixedWorkerWorkItemExecutor::TrySubmitWorkItem: Executor unavailable for request_id="
            << submission.item->GetRequestId();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidState);
    }
    for (std::size_t index = 0U; index < worker_count_; ++index)
    {
        if (!worker_busy_.at(index))
        {
            // Moving a user-supplied processor into its worker slot may throw.
            try
            {
                assigned_work_items_.at(index).submission = std::move(submission);
                assigned_work_items_.at(index).processor = std::move(processor);
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
            worker_busy_.at(index) = true;
            worker_conditions_.at(index).notify_one();
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
    std::lock_guard<std::mutex> lock(mutex_);
    if (stopping_ || !started_)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidState);
    }
    for (std::size_t index = 0U; index < worker_count_; ++index)
    {
        if (!worker_busy_.at(index))
        {
            // Moving the cleanup callable into its worker slot may throw.
            try
            {
                assigned_cleanup_jobs_.at(index) = std::move(job);
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
            worker_busy_.at(index) = true;
            worker_conditions_.at(index).notify_one();
            return {};
        }
    }
    if (cleanup_jobs_.size() >= cleanup_queue_capacity_)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kResourceBusy);
    }
    // Growing the cleanup deque can allocate; report exhaustion through the submit result.
    try
    {
        cleanup_jobs_.push_back(std::move(job));
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
        std::lock_guard<std::mutex> lock(mutex_);
        if (!started_ || stopping_)
        {
            return;
        }
        stopping_ = true;
        for (auto& stop_source : stop_sources_)
        {
            stop_source.request_stop();
        }
    }
    for (auto& worker_condition : worker_conditions_)
    {
        worker_condition.notify_all();
    }
}

void FixedWorkerWorkItemExecutor::Join() noexcept
{
    {
        std::unique_lock<std::mutex> lock(mutex_);
        worker_exit_condition_.wait(lock, [this] {
            return exited_worker_count_ == workers_.size();
        });
    }
    for (auto& worker : workers_)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }
    workers_.clear();
    stop_sources_.clear();
    worker_conditions_.clear();
    std::lock_guard<std::mutex> lock(mutex_);
    cleanup_jobs_.clear();
    assigned_work_items_.clear();
    assigned_cleanup_jobs_.clear();
    worker_busy_.clear();
    exited_worker_count_ = 0U;
    started_ = false;
    handler_factory_ = {};
}

void FixedWorkerWorkItemExecutor::MarkWorkerExited() noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);
    ++exited_worker_count_;
    worker_exit_condition_.notify_all();
}

void FixedWorkerWorkItemExecutor::RunWorker(const std::size_t worker_index) noexcept
{
    std::unique_ptr<daemon::control_plane::IRequestHandler> handler;
    // The configured handler factory is external code and may throw during worker startup.
    try
    {
        handler = handler_factory_();
    }
    catch (...)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Request-handler factory threw for worker="
                                   << worker_index;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            startup_failed_ = true;
            ++initialized_worker_count_;
            for (auto& stop_source : stop_sources_)
            {
                stop_source.request_stop();
            }
            startup_condition_.notify_all();
        }
        MarkWorkerExited();
        return;
    }
    if (handler == nullptr)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Request-handler factory returned null for worker="
                                   << worker_index;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            startup_failed_ = true;
            ++initialized_worker_count_;
            for (auto& stop_source : stop_sources_)
            {
                stop_source.request_stop();
            }
            startup_condition_.notify_all();
        }
        MarkWorkerExited();
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++initialized_worker_count_;
        startup_condition_.notify_all();
    }
    // Keep unexpected loop failures from escaping the worker thread and signal its exit to Join().
    try
    {
        RunWorkerLoop(worker_index, *handler, stop_sources_.at(worker_index).get_token());
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
            std::unique_lock<std::mutex> lock(mutex_);
            worker_conditions_.at(worker_index).wait(lock, [this, worker_index] {
                return stopping_ || assigned_work_items_.at(worker_index).processor ||
                       assigned_cleanup_jobs_.at(worker_index);
            });
            if (assigned_cleanup_jobs_.at(worker_index))
            {
                cleanup_job = std::move(assigned_cleanup_jobs_.at(worker_index));
            }
            else if (assigned_work_items_.at(worker_index).processor)
            {
                work_item = std::move(assigned_work_items_.at(worker_index));
            }
            else if (stopping_)
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
    else if (work_item.processor)
    {
        // The processor type permits throwing callables; contain failures to keep this worker alive.
        try
        {
            const auto result = work_item.processor(work_item.submission, handler, stop_token);
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
    std::lock_guard<std::mutex> lock(mutex_);
    worker_busy_.at(worker_index) = false;
    if (!cleanup_jobs_.empty())
    {
        assigned_cleanup_jobs_.at(worker_index) = std::move(cleanup_jobs_.front());
        cleanup_jobs_.pop_front();
        worker_busy_.at(worker_index) = true;
        worker_conditions_.at(worker_index).notify_one();
    }
}

}  // namespace score::crypto::ipc::message_passing
