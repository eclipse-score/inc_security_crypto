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

#ifndef SCORE_CRYPTO_API_CONTROL_PLANE_I_CONNECTION_HPP
#define SCORE_CRYPTO_API_CONTROL_PLANE_I_CONNECTION_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/mw/crypto/api/common/error_domain.hpp"

namespace score::crypto::api::control_plane
{

class IConnection
{
  protected:
    IConnection() = default;

    IConnection& operator=(const IConnection&) = delete;
    IConnection(const IConnection&) = delete;
    IConnection(IConnection&&) = default;
    IConnection& operator=(IConnection&&) = default;

  public:
    virtual ~IConnection() = default;

    virtual Expected<daemon::control_plane::protocol::ControlResponse, score::mw::crypto::CryptoErrorCode> SendRequest(
        const daemon::control_plane::protocol::ControlRequest& request) = 0;

    /// @brief Returns the connection node ID assigned by the daemon during CONNECTION_OPEN.
    /// @return DataNodeId that identifies this connection on the daemon side, or 0 if not yet established.
    virtual daemon::control_plane::protocol::DataNodeId GetConnectionNodeId() const = 0;

    /// @brief Sets the connection node ID (called after successful CONNECTION_OPEN).
    /// @param id The DataNodeId assigned by the daemon
    virtual void SetConnectionNodeId(daemon::control_plane::protocol::DataNodeId id)
    {
        // Default no-op implementation for implementations that don't store the ID
    }
};

}  // namespace score::crypto::api::control_plane

#endif  // SCORE_CRYPTO_API_CONTROL_PLANE_I_CONNECTION_HPP
