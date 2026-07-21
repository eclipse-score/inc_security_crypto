/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_CRYPTO_API_CONTROL_PLANE_CONNECTION_IMPL_H
#define SCORE_CRYPTO_API_CONTROL_PLANE_CONNECTION_IMPL_H

#include <memory>
#include <string_view>

#include "score/crypto/api/control_plane/i_connection.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/ipc/grpc_adapter/grpc_control_client.h"

namespace score::crypto::api::control_plane
{

/// Control plane client implementation - communicates with daemon's control server
class ConnectionImpl : public IConnection
{
  public:
    Expected<daemon::control_plane::protocol::ControlResponse, score::mw::crypto::CryptoErrorCode> SendRequest(
        const daemon::control_plane::protocol::ControlRequest& request) override;

    daemon::control_plane::protocol::DataNodeId GetConnectionNodeId() const override;

    explicit ConnectionImpl(std::string_view endpoint);

    ~ConnectionImpl() override;

    /// Set the connection node ID after successful CONNECTION_OPEN
    void SetConnectionNodeId(daemon::control_plane::protocol::DataNodeId id) override;

    /// Disable copy, allow move
    ConnectionImpl(const ConnectionImpl&) = delete;
    ConnectionImpl& operator=(const ConnectionImpl&) = delete;
    ConnectionImpl(ConnectionImpl&&) = default;
    ConnectionImpl& operator=(ConnectionImpl&&) = default;

  private:
    std::shared_ptr<ipc::GrpcControlClient> mClient;
    daemon::control_plane::protocol::DataNodeId m_connection_id = 0;
};

}  // namespace score::crypto::api::control_plane

#endif  // SCORE_CRYPTO_API_CONTROL_PLANE_CONNECTION_IMPL_H
