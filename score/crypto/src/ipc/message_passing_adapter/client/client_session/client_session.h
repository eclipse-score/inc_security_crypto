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

#ifndef SCORE_CRYPTO_IPC_CLIENT_SESSION_H
#define SCORE_CRYPTO_IPC_CLIENT_SESSION_H

#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/client/client_session/pending_call_registry.h"
#include "score/crypto/src/ipc/message_passing_adapter/protocol/i_control_codec.h"

#include "score/message_passing/i_client_connection.h"

#include <score/expected.hpp>
#include <score/memory.hpp>
#include <score/span.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>

namespace score::crypto::ipc::message_passing
{

/**
 * @brief
 * Coordinates request/response calls and transport lifecycle for one client connection.
 * Encoded responses are matched to pending calls by request ID. Shutdown terminates outstanding
 * calls and waits for the transport to stop.
 * @endrst
 */
class ClientSession final : public std::enable_shared_from_this<ClientSession>
{
  public:
    explicit ClientSession(const IControlCodec& codec,
                           score::cpp::pmr::unique_ptr<score::message_passing::IClientConnection> connection);
    ~ClientSession() noexcept;

    score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
    SendRequest(daemon::control_plane::protocol::ControlRequest& request,
                std::chrono::milliseconds timeout,
                const daemon::control_plane::CancellationToken& cancellation) noexcept;
    score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
    SendRequest(daemon::control_plane::protocol::ControlRequest& request) noexcept;

    score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> StartCallbacks() noexcept;
    void Shutdown() noexcept;

  private:
    enum class LifecycleState : std::uint8_t
    {
        kStarting,
        kReady,
        kStopping,
        kStopped,
    };

    void FailAllPendingCalls(score::crypto::CryptoErrorCode error) noexcept;
    void OnTransportStateChanged(score::message_passing::IClientConnection::State state) noexcept;
    void OnResponseBytes(score::cpp::span<const std::uint8_t> message) noexcept;
    score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> WaitForConnectionReady(
        std::chrono::steady_clock::time_point deadline) noexcept;
    void WaitForStopped() noexcept;
    bool CreateAndSendCancelRequest(daemon::control_plane::protocol::RequestId request_id) noexcept;
    void HandleTransportState(LifecycleState state) noexcept;
    score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> TransferRequestBytes(
        score::cpp::span<const std::uint8_t> bytes) noexcept;

    mutable std::mutex mutex_{};
    std::condition_variable state_condition_{};
    LifecycleState state_{LifecycleState::kStarting};

    const IControlCodec& codec_;

    PendingCallRegistry pending_call_registry_{};
    score::cpp::pmr::unique_ptr<score::message_passing::IClientConnection> connection_;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_CLIENT_SESSION_H
