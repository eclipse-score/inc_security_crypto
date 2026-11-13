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
 */
class ClientSession final : public std::enable_shared_from_this<ClientSession>
{
  public:
    /// @brief Creates a session around the codec and transport connection.
    /// @param codec Codec used to serialize requests and decode responses.
    /// @param connection message-passing connection.
    explicit ClientSession(const score::crypto::ipc::protocol::IControlCodec& codec,
                           score::cpp::pmr::unique_ptr<score::message_passing::IClientConnection> connection);
    /// @brief Stops the transport and fails outstanding calls.
    ~ClientSession() noexcept;

    /// @brief Sends a request and waits up to the supplied timeout.
    /// @param request Request whose ID and deadline are assigned by the session.
    /// @param timeout Maximum duration to await the response, subject to the configured cap.
    /// @return The response or the corresponding serialization, transport, or timeout error.
    score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
    SendRequest(daemon::control_plane::protocol::ControlRequest& request, std::chrono::milliseconds timeout) noexcept;

    /// @brief Sends a request using the maximum configured request timeout.
    /// @param request Request whose ID and deadline are assigned by the session.
    /// @return The response or the corresponding serialization, transport, or timeout error.
    score::crypto::Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
    SendRequest(daemon::control_plane::protocol::ControlRequest& request) noexcept;

    /// @brief Starts transport callbacks and begins tracking connection readiness.
    /// @return Success if callbacks start, or an error if setup fails.
    score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> StartCallbacks() noexcept;

    /// @brief Fails outstanding calls, stops the transport, and waits for it to stop.
    void Shutdown() noexcept;

  private:
    enum class LifecycleState : std::uint8_t
    {
        kStarting,  ///< The transport is attempting to connect.
        kReady,     ///< The transport can send requests.
        kStopping,  ///< The transport is shutting down.
        kStopped,   ///< The transport has stopped and can be destroyed.
    };

    /// @brief Fails all calls currently registered with the pending-call registry.
    /// @param error Error to deliver to each waiter.
    void FailAllPendingCalls(score::crypto::CryptoErrorCode error) noexcept;

    /// @brief Processes a transport lifecycle callback and fails calls on shutdown.
    /// @param state New client-session lifecycle state.
    void OnTransportStateChanged(LifecycleState state) noexcept;

    /// @brief Decodes a notification and completes its matching pending call.
    /// @param message Serialized response bytes received from the transport.
    void OnResponseBytes(score::cpp::span<const std::uint8_t> message) noexcept;

    /// @brief Waits for the transport to become ready or stop before a deadline.
    /// @param deadline Latest time to wait for readiness.
    /// @return Success when ready, or a connection error if it stops or times out.
    score::crypto::Expected<std::monostate, score::crypto::CryptoErrorCode> WaitForConnectionReady(
        std::chrono::steady_clock::time_point deadline) noexcept;

    /// @brief Waits until the transport reports its stopped state.
    void WaitForStopped() noexcept;

    /// @brief Updates the lifecycle state and wakes readiness waiters.
    /// @param state New lifecycle state.
    void HandleTransportState(LifecycleState state) noexcept;

    /// @brief Sends already-serialized request bytes when the connection is ready.
    /// @param bytes Serialized request data.
    /// @return Success if submitted, or a connection error if sending fails.
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
