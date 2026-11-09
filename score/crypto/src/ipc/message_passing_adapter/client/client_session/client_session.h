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
#include "score/crypto/src/ipc/message_passing_adapter/client/client_session/pending_call_registry.h"

#include <score/memory.hpp>
#include <score/span.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>

namespace score::crypto::ipc::protocol
{
class IControlCodec;
}  // namespace score::crypto::ipc::protocol

namespace score::message_passing
{
class IClientConnection;
}  // namespace score::message_passing

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
    explicit ClientSession(const score::crypto::ipc::protocol::IControlCodec& codec,
                           score::cpp::pmr::unique_ptr<score::message_passing::IClientConnection> connection);
    ~ClientSession() noexcept;

    score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
    SendRequest(daemon::control_plane::protocol::ControlRequest& request, std::chrono::milliseconds timeout) noexcept;
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
    void OnTransportStateChanged(LifecycleState state) noexcept;
    void OnResponseBytes(score::cpp::span<const std::uint8_t> message) noexcept;
    score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> WaitForConnectionReady(
        std::chrono::steady_clock::time_point deadline) noexcept;
    void WaitForStopped() noexcept;
    bool CreateAndSendCancelRequest(daemon::control_plane::protocol::RequestId request_id) noexcept;
    void HandleTransportState(LifecycleState state) noexcept;
    score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> TransferRequestBytes(
        score::cpp::span<const std::uint8_t> bytes) noexcept;

    mutable std::mutex m_mutex{};
    std::condition_variable m_state_condition{};
    LifecycleState m_state{LifecycleState::kStarting};

    const score::crypto::ipc::protocol::IControlCodec& m_codec;

    PendingCallRegistry m_pending_call_registry{};
    score::cpp::pmr::unique_ptr<score::message_passing::IClientConnection> m_connection;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_CLIENT_SESSION_H
