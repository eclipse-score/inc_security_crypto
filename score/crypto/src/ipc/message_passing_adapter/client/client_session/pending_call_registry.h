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

#ifndef SCORE_CRYPTO_IPC_PENDING_CALL_REGISTRY_H
#define SCORE_CRYPTO_IPC_PENDING_CALL_REGISTRY_H

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <score/unordered_map.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>

namespace score::crypto::ipc::message_passing
{

class PendingCall;
/// Shared handle that keeps a pending call alive while a caller waits for it.
using PendingCallHandle = std::shared_ptr<PendingCall>;

/**
 * @brief
 * Registers client calls and correlates terminal responses by request ID.
 * Owns the pending-call map for a client session and propagates transport failures to all calls.
 * @endrst
 */
class PendingCallRegistry final
{
  public:
    /// @brief Creates an empty registry for outstanding client calls.
    PendingCallRegistry();

    using RegisteredPendingCall = std::pair<daemon::control_plane::protocol::RequestId, PendingCallHandle>;

    /// @brief Creates and registers a pending call with a unique request ID.
    /// @return The request ID and call handle, or an error if registration fails or capacity is full.
    score::crypto::Expected<RegisteredPendingCall, score::crypto::CryptoErrorCode> BeginCall() noexcept;

    /// @brief Completes the pending call identified by the response request ID.
    /// @param request_id ID of the call to complete.
    /// @param response Terminal response to deliver to the waiting caller.
    void CompleteCall(daemon::control_plane::protocol::RequestId request_id,
                      daemon::control_plane::protocol::ControlResponse response) noexcept;

    /// @brief Fails a pending call if the ID still refers to the expected handle.
    /// @param request_id ID of the call to fail.
    /// @param expected_call Handle expected to be registered for that ID.
    /// @param error Error to deliver to the waiting caller.
    void FailCall(daemon::control_plane::protocol::RequestId request_id,
                  const PendingCallHandle& expected_call,
                  score::crypto::CryptoErrorCode error) noexcept;
    /// @brief Waits for a call's terminal result until the specified deadline.
    /// @param request_id ID of the pending call.
    /// @param call Handle of the pending call.
    /// @param deadline Latest time to wait for a response.
    /// @return The response, or the call's failure or timeout error.
    score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
    WaitForCallResponse(daemon::control_plane::protocol::RequestId request_id,
                        const PendingCallHandle& call,
                        std::chrono::steady_clock::time_point deadline) noexcept;
    /// @brief Fails and removes every currently registered call.
    /// @param error Error delivered to each waiting caller.
    void FailAllPendingCalls(score::crypto::CryptoErrorCode error) noexcept;

  private:
    /// @brief Generates an unused non-zero request ID while the registry lock is held.
    /// @param lock Lock protecting the pending-call map and counter.
    /// @return An unused request ID, or an error if one cannot be generated.
    score::crypto::Expected<daemon::control_plane::protocol::RequestId, score::crypto::CryptoErrorCode>
    GenerateRequestId(const std::lock_guard<std::mutex>& lock);

    std::mutex m_pending_calls_mutex{};
    std::unordered_map<daemon::control_plane::protocol::RequestId, PendingCallHandle> m_pending_calls{};
    std::uint32_t m_next_request_counter{1U};
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_PENDING_CALL_REGISTRY_H
