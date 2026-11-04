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

#include "score/crypto/src/ipc/message_passing_adapter/client/client_session/pending_call.h"

#include <utility>

namespace score::crypto::ipc::message_passing
{

bool PendingCall::Complete(daemon::control_plane::protocol::ControlResponse&& completed_response) noexcept
{
    {
        std::lock_guard<std::mutex> call_lock(mutex);
        if (state != State::kPending)
        {
            return false;
        }
        state = State::kCompleted;
        result = std::move(completed_response);
    }
    condition.notify_one();
    return true;
}

bool PendingCall::Fail(const score::crypto::CryptoErrorCode failure) noexcept
{
    {
        std::lock_guard<std::mutex> call_lock(mutex);
        if (state != State::kPending)
        {
            return false;
        }
        state = State::kFailed;
        result = score::crypto::make_unexpected(failure);
    }
    condition.notify_one();
    return true;
}

score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
PendingCall::WaitForResponse(const std::chrono::steady_clock::time_point deadline) noexcept
{
    std::unique_lock<std::mutex> call_lock(mutex);
    const auto call_finalized = condition.wait_until(call_lock, deadline, [this] {
        return (state != State::kPending);
    });

    if (call_finalized)
    {
        return std::move(result);
    }

    // TODO: Log RequstId
    // score::mw::log::LogError() << "PendingCall::WaitForResponse timed out for requestId: " << request_id;
    return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kOperationResponseTimedOut);
}

}  // namespace score::crypto::ipc::message_passing
