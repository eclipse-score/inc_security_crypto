/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_ADAPTER_I_WORK_ITEM_SUBMITTER_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_ADAPTER_I_WORK_ITEM_SUBMITTER_H

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <functional>
#include <memory>
#include <variant>

namespace score::crypto::daemon::control_plane
{
class IRequestHandler;
}  // namespace score::crypto::daemon::control_plane

namespace score::crypto::ipc::message_passing
{

namespace detail
{
class Session;
struct WorkItem;
}  // namespace detail

struct WorkItemSubmission final
{
    std::shared_ptr<detail::Session> session{};
    std::shared_ptr<detail::WorkItem> item{};
};

/**
 * @brief
 * Submission boundary for operation work and disconnect-cleanup jobs.
 * Implementations accept work for asynchronous execution and retain submitted session and item
 * objects until the operation job completes.
 * @endrst
 */
class IWorkItemSubmitter
{
  public:
    using JobResult = score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>;
    using WorkItemJob = std::function<JobResult(const WorkItemSubmission&, daemon::control_plane::IRequestHandler&)>;
    using CleanupJob = std::function<JobResult()>;

    virtual ~IWorkItemSubmitter() noexcept = default;

    IWorkItemSubmitter(const IWorkItemSubmitter&) = delete;
    IWorkItemSubmitter& operator=(const IWorkItemSubmitter&) = delete;
    IWorkItemSubmitter(IWorkItemSubmitter&&) = delete;
    IWorkItemSubmitter& operator=(IWorkItemSubmitter&&) = delete;

    // An accepted submission keeps both the session and item alive through worker completion.
    virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> TrySubmitWorkItem(
        WorkItemSubmission submission,
        WorkItemJob job) noexcept = 0;
    virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> TrySubmitCleanup(
        CleanupJob job) noexcept = 0;

  protected:
    IWorkItemSubmitter() noexcept = default;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_ADAPTER_I_WORK_ITEM_SUBMITTER_H
