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

#include <score/stop_token.hpp>

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
        WorkItemProcessor processor) noexcept override;
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> TrySubmitCleanup(
        CleanupJob job) noexcept override;
    void Shutdown() noexcept;
    void Join() noexcept;

  private:
    bool StartImpl(HandlerFactory handler_factory);
    void RunWorker(std::size_t worker_index) noexcept;
    void RunWorkerLoop(std::size_t worker_index,
                       daemon::control_plane::IRequestHandler& handler,
                       const score::cpp::stop_token& stop_token);
    struct AssignedWorkItem final
    {
        WorkItemSubmission submission{};
        WorkItemProcessor processor{};
    };
    static void ExecuteJob(AssignedWorkItem work_item,
                           CleanupJob cleanup_job,
                           daemon::control_plane::IRequestHandler& handler,
                           const score::cpp::stop_token& stop_token) noexcept;
    void CompleteWork(std::size_t worker_index) noexcept;
    void MarkWorkerExited() noexcept;

    std::size_t worker_count_{0U};
    std::size_t cleanup_queue_capacity_{0U};
    std::mutex mutex_{};
    std::deque<std::condition_variable> worker_conditions_{};
    std::condition_variable startup_condition_{};
    std::condition_variable worker_exit_condition_{};
    std::deque<CleanupJob> cleanup_jobs_{};
    std::vector<AssignedWorkItem> assigned_work_items_{};
    std::vector<CleanupJob> assigned_cleanup_jobs_{};
    std::vector<bool> worker_busy_{};
    std::vector<std::thread> workers_{};
    std::vector<score::cpp::stop_source> stop_sources_{};
    HandlerFactory handler_factory_{};
    std::size_t initialized_worker_count_{0U};
    std::size_t exited_worker_count_{0U};
    bool startup_failed_{false};
    bool stopping_{false};
    bool started_{false};
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_ADAPTER_FIXED_WORKER_WORK_ITEM_EXECUTOR_H
