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

class ControlPlaneConnection final : public IConnection
{
  public:
    explicit ControlPlaneConnection(
        std::shared_ptr<score::crypto::ipc::message_passing::MessagePassingControlClient> transport) noexcept;
    ~ControlPlaneConnection() override;

    ControlPlaneConnection(const ControlPlaneConnection&) = delete;
    ControlPlaneConnection& operator=(const ControlPlaneConnection&) = delete;
    ControlPlaneConnection(ControlPlaneConnection&&) = default;
    ControlPlaneConnection& operator=(ControlPlaneConnection&&) = default;

    Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> SendRequest(
        daemon::control_plane::protocol::ControlRequest& request) override;
    Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> SendRequest(
        daemon::control_plane::protocol::ControlRequest& request,
        std::chrono::milliseconds timeout) override;
    daemon::control_plane::protocol::DataNodeId GetConnectionNodeId() const override;

    Expected<std::monostate, score::crypto::CryptoErrorCode> Establish() noexcept;

  private:
    Expected<daemon::control_plane::protocol::DataNodeId, score::crypto::CryptoErrorCode> OpenConnection() noexcept;
    Expected<std::monostate, score::crypto::CryptoErrorCode> CloseConnection() noexcept;

    std::shared_ptr<score::crypto::ipc::message_passing::MessagePassingControlClient> transport_;
    daemon::control_plane::protocol::DataNodeId connection_node_id_{0U};
};

}  // namespace score::crypto::api::control_plane

#endif  // SCORE_CRYPTO_SRC_API_CONTROL_PLANE_CONTROL_PLANE_CONNECTION_HPP
