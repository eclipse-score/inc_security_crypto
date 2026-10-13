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
#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/client/client_session/client_session.h"
#include "score/crypto/src/ipc/message_passing_adapter/protocol/flatbuffer_codec.h"

#include "score/memory.hpp"
#include "score/message_passing/client_factory.h"
#include "score/message_passing/i_client_connection.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>

namespace score::crypto::ipc::message_passing
{

using CancellationToken = daemon::control_plane::CancellationToken;
using CancellationSource = daemon::control_plane::CancellationSource;

/**
 * @brief
 * Client-facing synchronous facade for the message-passing control protocol.
 * Owns the transport factory and codec; ClientSession owns the connection and its request and
 * transport lifecycle state.
 * @endrst
 */
class MessagePassingControlClient final
{
  public:
    static Expected<std::shared_ptr<MessagePassingControlClient>, score::crypto::CryptoErrorCode> Create(
        std::string_view service_identifier) noexcept;
    ~MessagePassingControlClient() noexcept;

    MessagePassingControlClient(const MessagePassingControlClient&) = delete;
    MessagePassingControlClient& operator=(const MessagePassingControlClient&) = delete;
    MessagePassingControlClient(MessagePassingControlClient&&) = delete;
    MessagePassingControlClient& operator=(MessagePassingControlClient&&) = delete;

    // Assigns the transport request ID and deadline to request before serialization.
    Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> SendRequest(
        daemon::control_plane::protocol::ControlRequest& request) noexcept;

    Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> SendRequest(
        daemon::control_plane::protocol::ControlRequest& request,
        std::chrono::milliseconds timeout,
        const CancellationToken& cancellation = {}) noexcept;

  private:
    MessagePassingControlClient(std::unique_ptr<score::message_passing::ClientFactory> factory,
                                score::cpp::pmr::unique_ptr<score::message_passing::IClientConnection> connection);

    std::unique_ptr<score::message_passing::ClientFactory> factory_;
    FlatBufferCodec codec_;
    ClientSession session_;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_CONTROL_CLIENT_H
