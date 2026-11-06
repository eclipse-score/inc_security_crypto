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

    explicit FixedWorkerWorkItemExecutor(std::size_t worker_count, std::size_t cleanup_queue_capacity) noexcept;
    ~FixedWorkerWorkItemExecutor() noexcept override;

    bool Start(HandlerFactory handler_factory) noexcept;
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> TrySubmitWorkItem(
        WorkItemSubmission submission,
        WorkItemJob job) noexcept override;
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> TrySubmitCleanup(
        CleanupJob job) noexcept override;
    void Shutdown() noexcept;
    void Join() noexcept;

  private:
    bool StartImpl(HandlerFactory handler_factory);
    void RunWorker(std::size_t worker_index) noexcept;
    void RunWorkerLoop(std::size_t worker_index, daemon::control_plane::IRequestHandler& handler);
    struct AssignedWorkItem final
    {
        WorkItemSubmission submission{};
        WorkItemJob job{};
    };
    static void ExecuteJob(AssignedWorkItem work_item,
                           CleanupJob cleanup_job,
                           daemon::control_plane::IRequestHandler& handler) noexcept;
    void CompleteWork(std::size_t worker_index) noexcept;
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
