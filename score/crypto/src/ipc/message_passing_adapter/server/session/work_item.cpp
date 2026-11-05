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

#include "score/crypto/src/ipc/message_passing_adapter/server/session/work_item.h"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/ipc/message_passing_adapter/ipc_config.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/session/session.h"
#include "score/crypto/src/ipc/protocol/i_control_codec.h"

#include <score/span.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <new>
#include <utility>
#include <variant>

namespace score::crypto::ipc::message_passing::detail
{
namespace
{

score::crypto::daemon::common::DaemonErrorCode MapCodecError(const score::crypto::CryptoErrorCode error) noexcept
{
    switch (error)
    {
        case score::crypto::CryptoErrorCode::kAllocationFailed:
            return score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed;
        case score::crypto::CryptoErrorCode::kInvalidFormat:
            return score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat;
        default:
            return score::crypto::daemon::common::DaemonErrorCode::kInternalError;
    }
}

}  // namespace

bool WorkItem::TryRequestCancellation() noexcept
{
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (lifecycle_ == WorkItemState::kCancellationRequested || lifecycle_ == WorkItemState::kCancelled)
        {
            return true;
        }
        if (lifecycle_ == WorkItemState::kQueued)
        {
            return TryTransitionTo(lock, WorkItemState::kCancellationRequested);
        }
        if (lifecycle_ != WorkItemState::kRunning)
        {
            return false;
        }
        if (!TryTransitionTo(lock, WorkItemState::kCancellationRequested))
        {
            return false;
        }
    }

    cancellation.RequestCancellation();
    return true;
}

bool WorkItem::IsCancellationRequested() const noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);
    return (lifecycle_ == WorkItemState::kCancellationRequested) || (lifecycle_ == WorkItemState::kCancelled);
}

void WorkItem::Complete() noexcept
{
    std::shared_ptr<Session> session;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (lifecycle_ == WorkItemState::kCompleted)
        {
            return;
        }
        if (!TryTransitionTo(lock, WorkItemState::kCompleted))
        {
            return;
        }
        session = session_.lock();
    }
    if (session != nullptr)
    {
        session->OnWorkItemCompleted(*this);
    }
}

WorkItemState WorkItem::PrepareForExecution() noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);

    if ((lifecycle_ == WorkItemState::kCompleted) || (lifecycle_ == WorkItemState::kCancelled) ||
        (lifecycle_ == WorkItemState::kDeadlineExpired) || (lifecycle_ == WorkItemState::kRunning))
    {
        return lifecycle_;
    }
    if (lifecycle_ == WorkItemState::kCancellationRequested)
    {
        static_cast<void>(TryTransitionTo(lock, WorkItemState::kCancelled));
        return lifecycle_;
    }
    if (std::chrono::steady_clock::now() >= request.deadline)
    {
        static_cast<void>(TryTransitionTo(lock, WorkItemState::kDeadlineExpired));
        return lifecycle_;
    }
    static_cast<void>(TryTransitionTo(lock, WorkItemState::kRunning));
    return lifecycle_;
}

bool WorkItem::TryTransitionTo(std::lock_guard<std::mutex>& lock, const WorkItemState next_state) noexcept
{
    static_cast<void>(lock);
    if (lifecycle_ == next_state)
    {
        return true;
    }
    bool allowed{false};
    switch (lifecycle_)
    {
        case WorkItemState::kQueued:
            allowed = (next_state == WorkItemState::kRunning) ||
                      (next_state == WorkItemState::kCancellationRequested) ||
                      (next_state == WorkItemState::kDeadlineExpired) || (next_state == WorkItemState::kCompleted);
            break;
        case WorkItemState::kRunning:
            allowed =
                (next_state == WorkItemState::kCancellationRequested) || (next_state == WorkItemState::kCompleted);
            break;
        case WorkItemState::kCancellationRequested:
            allowed = (next_state == WorkItemState::kCancelled) || (next_state == WorkItemState::kCompleted);
            break;
        case WorkItemState::kCancelled:
        case WorkItemState::kDeadlineExpired:
            allowed = next_state == WorkItemState::kCompleted;
            break;
        case WorkItemState::kCompleted:
            break;
    }
    if (!allowed)
    {
        return false;
    }
    lifecycle_ = next_state;
    return true;
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> WorkItem::DeserializeRequest(
    const score::crypto::ipc::protocol::IControlCodec& codec) noexcept
{
    const auto owned_request =
        score::cpp::span<const std::uint8_t>{serialized_request.data(), serialized_request.size()};
    auto decoded_request = protocol::ControlRequest{};
    const auto deserialize_result = codec.DeserializeRequest(owned_request, decoded_request);
    if (!deserialize_result.has_value())
    {
        return score::crypto::make_unexpected(MapCodecError(deserialize_result.error()));
    }
    if (decoded_request.request_id != request_id)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }
    // Overwrite the client_id and deadline in the decoded request with the values stored in the work item.
    decoded_request.client_id = client_id;
    decoded_request.deadline = deadline;
    request = std::move(decoded_request);
    return {};
}

score::crypto::Expected<std::shared_ptr<WorkItem>, score::crypto::daemon::common::DaemonErrorCode> WorkItem::Create(
    const score::cpp::span<const std::uint8_t> serialized_request,
    const std::shared_ptr<Session>& session,
    const score::crypto::ipc::protocol::IControlCodec& codec,
    const std::chrono::steady_clock::time_point received_at) noexcept
{
    if (serialized_request.size() > ipc::kMaxPayloadBytes)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }
    if (session == nullptr)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kConnectionFailed);
    }
    const auto metadata_result = codec.PeekRequestMetadata(serialized_request);
    if (!metadata_result.has_value())
    {
        return score::crypto::make_unexpected(MapCodecError(metadata_result.error()));
    }
    const auto metadata = metadata_result.value();

    // Work-item creation allocates shared state and copies the serialized request into owned storage.
    try
    {
        auto item = std::make_shared<WorkItem>();
        auto deadline =
            received_at + std::min(std::chrono::milliseconds{metadata.timeout_ms}, ipc::kMaximumRequestTimeout);
        item->deadline = deadline;
        item->session_ = session;
        item->client_id = session->client_id();
        item->kind = metadata.kind;
        item->request_id = metadata.request_id;
        item->execution_policy = metadata.execution_policy;
        item->serialized_request.assign(serialized_request.begin(), serialized_request.end());
        return item;
    }
    catch (const std::bad_alloc&)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
}

}  // namespace score::crypto::ipc::message_passing::detail
