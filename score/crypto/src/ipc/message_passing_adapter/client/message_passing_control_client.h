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
#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_CONTROL_CLIENT_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_CONTROL_CLIENT_H

#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/ipc/message_passing_adapter/client/client_session/client_session.h"
#include "score/crypto/src/ipc/protocol/flatbuffer_codec.h"

#include "score/memory.hpp"
#include "score/message_passing/client_factory.h"

#include <chrono>
#include <memory>
#include <string_view>

namespace score::message_passing
{
class IClientConnection;
}  // namespace score::message_passing

namespace score::crypto::ipc::message_passing
{

/**
 * @brief
 * Client-facing synchronous facade for the message-passing control protocol.
 * Owns the transport factory and codec; ClientSession owns the connection and its request and
 * transport lifecycle state.
 */
class MessagePassingControlClient final
{
  public:
    /// @brief Creates a client connection to a message-passing service.
    /// @param service_identifier Endpoint identifier of the daemon service.
    /// @return A client facade, or an error if creation or callback startup fails.
    static Expected<std::shared_ptr<MessagePassingControlClient>, score::crypto::CryptoErrorCode> Create(
        std::string_view service_identifier) noexcept;

    /// @brief Stops the client session and releases its transport resources.
    ~MessagePassingControlClient() noexcept;

    MessagePassingControlClient(const MessagePassingControlClient&) = delete;
    MessagePassingControlClient& operator=(const MessagePassingControlClient&) = delete;
    MessagePassingControlClient(MessagePassingControlClient&&) = delete;
    MessagePassingControlClient& operator=(MessagePassingControlClient&&) = delete;

    /// @brief Sends a control request using the default maximum timeout.
    /// @param request Request to send; request ID and deadline are assigned before serialization.
    /// @return The correlated response, or an error if sending or completion fails.
    Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> SendRequest(
        daemon::control_plane::protocol::ControlRequest& request) noexcept;

    /// @brief Sends a control request and waits up to the supplied timeout.
    /// @param request Request to send; request ID and deadline are assigned before serialization.
    /// @param timeout Maximum time to wait for the terminal response.
    /// @return The correlated response, or an error if sending or completion fails.
    Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> SendRequest(
        daemon::control_plane::protocol::ControlRequest& request,
        std::chrono::milliseconds timeout) noexcept;

  private:
    /// @brief Constructs the MessagePassingControlClient from an owned factory and created connection.
    /// used by static Create method.
    /// @param factory Transport factory retained for the connection lifetime.
    /// @param connection Client transport connection transferred to the session.
    MessagePassingControlClient(std::unique_ptr<score::message_passing::ClientFactory> factory,
                                score::cpp::pmr::unique_ptr<score::message_passing::IClientConnection> connection);

    // The score::message_passing client-factory contract requires it to outlive every connection it creates.
    std::unique_ptr<score::message_passing::ClientFactory> m_factory;
    score::crypto::ipc::protocol::FlatBufferCodec m_codec;
    ClientSession m_session;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_CONTROL_CLIENT_H
