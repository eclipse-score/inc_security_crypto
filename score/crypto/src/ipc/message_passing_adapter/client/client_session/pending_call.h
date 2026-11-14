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

#ifndef SCORE_CRYPTO_IPC_PENDING_CALL_H
#define SCORE_CRYPTO_IPC_PENDING_CALL_H

#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>

namespace score::crypto::ipc::message_passing
{

class PendingCallRegistry;

/**
 * @brief
 * Holds the completion state and result for one client request.
 * Provides synchronized response waiting and a single terminal transition to completed or failed.
 */
class PendingCall final
{
  private:
    enum class State : std::uint8_t
    {
        kPending,    ///< No terminal result has been stored.
        kFailed,     ///< The call completed with a transport or operation error.
        kCompleted,  ///< The call completed with a response.
    };

  private:
    friend class PendingCallRegistry;

    /// @brief Stores a response if the call is still pending.
    /// @param response Response received for this call.
    /// @return True if the response completed the call; false if it was already terminal.
    bool Complete(daemon::control_plane::protocol::ControlResponse&& response) noexcept;

    /// @brief Stores an error if the call is still pending.
    /// @param error Terminal error to deliver to the waiter.
    /// @return True if the error failed the call; false if it was already terminal.
    bool Fail(score::crypto::CryptoErrorCode error) noexcept;

    /// @brief Waits for a terminal result until the deadline.
    /// @param deadline Latest time to wait.
    /// @return The stored response or error, or a timeout error if still pending.
    score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
    WaitForResponse(std::chrono::steady_clock::time_point deadline) noexcept;

    std::condition_variable condition;
    std::mutex mutex;
    State state{State::kPending};
    score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> result;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_PENDING_CALL_H
