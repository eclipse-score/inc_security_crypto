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

#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>

namespace score::crypto::ipc::message_passing
{

class PendingCallRegistry;

/**
 * @brief
 * Holds the completion state and result for one client request.
 * Provides synchronized response waiting and a single terminal transition to completed or failed.
 * @endrst
 */
class PendingCall final
{
  private:
    enum class State : std::uint8_t
    {
        kPending,
        kFailed,
        kCompleted,
    };

  private:
    friend class PendingCallRegistry;

    bool Complete(daemon::control_plane::protocol::ControlResponse&& response) noexcept;
    bool Fail(score::crypto::CryptoErrorCode error) noexcept;
    score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
    WaitForResponse(std::chrono::steady_clock::time_point deadline) noexcept;

    std::condition_variable condition;
    std::mutex mutex;
    State state{State::kPending};
    score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> result;
};

using PendingCallHandle = std::shared_ptr<PendingCall>;

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_PENDING_CALL_H
