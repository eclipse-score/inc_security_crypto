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

#include "score/crypto/src/ipc/message_passing_adapter/server/server_lifecycle.h"

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <utility>

namespace score::crypto::ipc::message_passing
{

score::crypto::Expected<ServerLifecycle::StartGuard, score::crypto::daemon::common::DaemonErrorCode>
ServerLifecycle::TryBeginStart() noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);
    if ((state_ != State::kNotStarted) && (state_ != State::kStopped))
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidState);
    }
    return {std::move(lock)};
}

void ServerLifecycle::MarkStarted(StartGuard& lock) noexcept
{
    if (!lock.owns_lock() || (lock.mutex() != &mutex_))
    {
        return;
    }
    state_ = State::kRunning;
    lock.unlock();
}

bool ServerLifecycle::BeginStopping() noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != State::kRunning)
    {
        return false;
    }
    state_ = State::kStopping;
    return true;
}

void ServerLifecycle::MarkStopped() noexcept
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = State::kStopped;
    }
}

}  // namespace score::crypto::ipc::message_passing
