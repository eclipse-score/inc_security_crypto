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

#include "score/crypto/src/ipc/message_passing_adapter/server/server_state_machine.h"

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <utility>

namespace score::crypto::ipc::message_passing
{

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
ServerStateMachine::TryBeginStart() noexcept
{
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_state != State::kStopped)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidState);
    }
    m_state = State::kStarting;
    return {};
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
ServerStateMachine::MarkStarted() noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != State::kStarting)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidState);
    }
    m_state = State::kStarted;
    return {};
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
ServerStateMachine::BeginStopping() noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != State::kStarted)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidState);
    }
    m_state = State::kStopping;
    return {};
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
ServerStateMachine::MarkStopped() noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != State::kStopping && m_state != State::kStarting)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidState);
    }
    m_state = State::kStopped;
    return {};
}

}  // namespace score::crypto::ipc::message_passing
