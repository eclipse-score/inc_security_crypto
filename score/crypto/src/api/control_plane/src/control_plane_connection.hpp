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
#ifndef SCORE_CRYPTO_SRC_API_CONTROL_PLANE_CONTROL_PLANE_CONNECTION_HPP
#define SCORE_CRYPTO_SRC_API_CONTROL_PLANE_CONTROL_PLANE_CONNECTION_HPP

#include "score/crypto/src/api/control_plane/i_connection.hpp"

#include <chrono>
#include <cstdint>
#include <memory>

namespace score::crypto::ipc::message_passing
{
class MessagePassingControlClient;
}

namespace score::crypto::api::control_plane
{

/// @brief Adapts the message-passing client to the API control-plane connection interface.
/// @details Opens one daemon-side connection and retains its node ID for subsequent requests.
class ControlPlaneConnection final : public IConnection
{
  public:
    /// @brief Creates a connection wrapper around a shared message-passing client.
    /// @param transport Client transport used to send control requests.
    explicit ControlPlaneConnection(
        std::shared_ptr<score::crypto::ipc::message_passing::MessagePassingControlClient> transport) noexcept;
    /// @brief Closes the daemon-side connection when this wrapper is released.
    ~ControlPlaneConnection() override;

    ControlPlaneConnection(const ControlPlaneConnection&) = delete;
    ControlPlaneConnection& operator=(const ControlPlaneConnection&) = delete;
    ControlPlaneConnection(ControlPlaneConnection&&) = default;
    ControlPlaneConnection& operator=(ControlPlaneConnection&&) = default;

    /// @copydoc IConnection::SendRequest(daemon::control_plane::protocol::ControlRequest&)
    Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> SendRequest(
        daemon::control_plane::protocol::ControlRequest& request) override;
    /// @copydoc IConnection::SendRequest(daemon::control_plane::protocol::ControlRequest&, std::chrono::milliseconds)
    Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> SendRequest(
        daemon::control_plane::protocol::ControlRequest& request,
        std::chrono::milliseconds timeout) override;
    /// @copydoc IConnection::GetConnectionNodeId
    daemon::control_plane::protocol::DataNodeId GetConnectionNodeId() const override;

    /// @brief Opens the daemon-side control connection and records its node ID.
    /// @return Success when open, or the error returned by the transport or daemon.
    Expected<std::monostate, score::crypto::CryptoErrorCode> Establish() noexcept;

  private:
    /// @brief Sends CONNECTION_OPEN and returns the node ID assigned by the daemon.
    /// @return The assigned node ID, or an error if the open request fails.
    Expected<daemon::control_plane::protocol::DataNodeId, score::crypto::CryptoErrorCode> OpenConnection() noexcept;
    /// @brief Sends CONNECTION_CLOSE for the recorded node ID.
    /// @return Success when closed, or the error returned by the transport or daemon.
    Expected<std::monostate, score::crypto::CryptoErrorCode> CloseConnection() noexcept;

    std::shared_ptr<score::crypto::ipc::message_passing::MessagePassingControlClient> m_transport;
    /// Node ID assigned by the daemon; zero until the connection is established.
    daemon::control_plane::protocol::DataNodeId m_connection_node_id{0U};
};

}  // namespace score::crypto::api::control_plane

#endif  // SCORE_CRYPTO_SRC_API_CONTROL_PLANE_CONTROL_PLANE_CONNECTION_HPP
