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
    PendingCallRegistry();

    using RegisteredPendingCall = std::pair<daemon::control_plane::protocol::RequestId, PendingCallHandle>;

    score::crypto::Expected<RegisteredPendingCall, score::crypto::CryptoErrorCode> BeginCall() noexcept;
    void CompleteCall(daemon::control_plane::protocol::RequestId request_id,
                      daemon::control_plane::protocol::ControlResponse response) noexcept;
    void FailCall(daemon::control_plane::protocol::RequestId request_id,
                  const PendingCallHandle& expected_call,
                  score::crypto::CryptoErrorCode error) noexcept;
    score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
    WaitForCallResponse(daemon::control_plane::protocol::RequestId request_id,
                        const PendingCallHandle& call,
                        std::chrono::steady_clock::time_point deadline) noexcept;
    void FailAllPendingCalls(score::crypto::CryptoErrorCode error) noexcept;

  private:
    score::crypto::Expected<daemon::control_plane::protocol::RequestId, score::crypto::CryptoErrorCode>
    GenerateRequestId(const std::lock_guard<std::mutex>& lock);

    std::mutex m_pending_calls_mutex{};
    std::unordered_map<daemon::control_plane::protocol::RequestId, PendingCallHandle> m_pending_calls{};
    std::uint32_t m_next_request_counter{1U};
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_PENDING_CALL_REGISTRY_H
