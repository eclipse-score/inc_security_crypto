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

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_SERVER_STATE_MACHINE_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_SERVER_STATE_MACHINE_H

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
class ServerStateMachine final
{
  public:
    enum class State : std::uint8_t
    {
        kStarting,  ///< Startup is in progress.
        kStarted,   ///< The server is listening.
        kStopping,  ///< Shutdown has begun.
        kStopped,   ///< The server has completed shutdown.
    };

    /// @brief Atomically starts a transition from stopped to starting.
    /// @return Success if startup may proceed, or an invalid-state error.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> TryBeginStart() noexcept;

    /// @brief Commits a successful startup transition to started.
    /// @return Success if the current state is starting, or an invalid-state error.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> MarkStarted() noexcept;

    /// @brief Begins shutdown from the started state.
    /// @return Success if shutdown may proceed, or an invalid-state error.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> BeginStopping() noexcept;

    /// @brief Marks shutdown complete and returns the server to stopped.
    /// @return Success if the current state permits stopping, or an invalid-state error.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> MarkStopped() noexcept;

  private:
    std::mutex m_mutex;
    State m_state{State::kStopped};
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_SERVER_STATE_MACHINE_H
