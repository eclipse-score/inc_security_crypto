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

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_ADAPTER_FIXED_WORKER_WORK_ITEM_EXECUTOR_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_ADAPTER_FIXED_WORKER_WORK_ITEM_EXECUTOR_H

#include "score/crypto/src/ipc/message_passing_adapter/server/work_item_execution/i_work_item_submitter.h"

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace score::crypto::ipc::message_passing
{

/**
 * @brief
 * Executes submitted operations on a fixed worker set and schedules cleanup jobs.
 * Each worker obtains a request handler from the configured factory; work and cleanup submission
 * are bounded by the executor's available worker and queue capacity.
 * @endrst
 */
class FixedWorkerWorkItemExecutor final : public IWorkItemSubmitter
{
  public:
    using HandlerFactory = std::function<std::unique_ptr<daemon::control_plane::IRequestHandler>()>;

    /// @brief Creates an executor with fixed workers and bounded cleanup capacity.
    /// @param worker_count Number of worker threads to create.
    /// @param cleanup_queue_capacity Maximum cleanup jobs queued while all workers are busy.
    explicit FixedWorkerWorkItemExecutor(std::size_t worker_count, std::size_t cleanup_queue_capacity) noexcept;

    /// @brief Stops and joins all worker threads.
    ~FixedWorkerWorkItemExecutor() noexcept override;

    /// @brief Starts workers and constructs one handler per worker before returning.
    /// @param handler_factory Factory invoked once by each worker during startup.
    /// @return True if all workers initialize, false if startup fails.
    bool Start(HandlerFactory handler_factory) noexcept;

    /// @brief Assigns a request to an idle worker; request jobs are never queued.
    /// @param submission Session and item retained for execution.
    /// @param job Operation to execute.
    /// @return Success if assigned, or an error if stopped, saturated, or assignment fails.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> TrySubmitWorkItem(
        WorkItemSubmission submission,
        WorkItemJob job) noexcept override;

    /// @brief Assigns cleanup to an idle worker or queues it within cleanup capacity.
    /// @param job Cleanup operation to execute.
    /// @return Success if assigned or queued, or an error if stopped or capacity is exhausted.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> TrySubmitCleanup(
        CleanupJob job) noexcept override;

    /// @brief Rejects further submissions and wakes worker threads to exit.
    void Shutdown() noexcept;

    /// @brief Waits for workers to exit and resets the executor to its stopped state.
    void Join() noexcept;

  private:
    /// @brief Allocates worker state and creates worker threads.
    /// @param handler_factory Factory used by each worker during initialization.
    /// @return True if all workers start successfully.
    bool StartImpl(HandlerFactory handler_factory);

    /// @brief Creates the handler and runs the indexed worker loop.
    /// @param worker_index Index of this worker's assigned-job slots.
    void RunWorker(std::size_t worker_index) noexcept;

    /// @brief Loops and Waits for work for one worker and executes assigned request or cleanup jobs.
    /// @param worker_index Index of this worker's assigned-job slots.
    /// @param handler Request handler owned by this worker.
    void RunWorkerLoop(std::size_t worker_index, daemon::control_plane::IRequestHandler& handler);

    /// Holds the session, item, and callable assigned to one worker.
    struct AssignedWorkItem final
    {
        /// Session and request state retained through execution.
        WorkItemSubmission submission{};
        /// Operation callable assigned to the worker.
        WorkItemJob job{};
    };

    /// @brief Runs one assigned request or cleanup callable and contains exceptions.
    /// @param work_item Assigned operation; empty for a cleanup job.
    /// @param cleanup_job Assigned cleanup callable; empty for an operation.
    /// @param handler Handler owned by the executing worker.
    static void ExecuteJob(AssignedWorkItem work_item,
                           CleanupJob cleanup_job,
                           daemon::control_plane::IRequestHandler& handler) noexcept;

    /// @brief Marks completion of work by a worker and dispatches the next queued cleanup job if any.
    /// @param worker_index Index of the worker that completed its job.
    void CompleteWork(std::size_t worker_index) noexcept;

    /// @brief Records worker exit and wakes Join waiters.
    void MarkWorkerExited() noexcept;

    std::size_t m_worker_count{0U};
    std::size_t m_cleanup_queue_capacity{0U};
    std::mutex m_mutex{};
    std::deque<std::condition_variable> m_worker_conditions{};
    std::condition_variable m_startup_condition{};
    std::condition_variable m_worker_exit_condition{};
    std::deque<CleanupJob> m_cleanup_jobs{};
    std::vector<AssignedWorkItem> m_assigned_work_items{};
    std::vector<CleanupJob> m_assigned_cleanup_jobs{};
    std::vector<bool> m_worker_busy{};
    std::vector<std::thread> m_workers{};
    HandlerFactory m_handler_factory{};
    std::size_t m_initialized_worker_count{0U};
    std::size_t m_exited_worker_count{0U};
    bool m_startup_failed{false};
    bool m_stopping{false};
    bool m_started{false};
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_ADAPTER_FIXED_WORKER_WORK_ITEM_EXECUTOR_H
