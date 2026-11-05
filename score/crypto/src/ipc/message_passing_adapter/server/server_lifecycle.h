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

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_SERVER_LIFECYCLE_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_SERVER_LIFECYCLE_H

#include <cstdint>
#include <mutex>

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

namespace score::crypto::ipc::message_passing
{

/**
 * @brief
 * Serializes server start, stop, and terminal lifecycle transitions.
 * @endrst
 */
class ServerLifecycle final
{
  public:
    enum class State : std::uint8_t
    {
        kNotStarted,
        kRunning,
        kStopping,
        kStopped,
    };

    using StartGuard = std::unique_lock<std::mutex>;

    score::crypto::Expected<ServerLifecycle::StartGuard, score::crypto::daemon::common::DaemonErrorCode>
    TryBeginStart() noexcept;

    void MarkStarted(StartGuard& lock) noexcept;
    bool BeginStopping() noexcept;
    void MarkStopped() noexcept;

  private:
    std::mutex m_mutex;
    State m_state{State::kNotStarted};
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_SERVER_LIFECYCLE_H
