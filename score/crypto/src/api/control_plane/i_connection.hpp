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

#ifndef SCORE_CRYPTO_SRC_API_CONTROL_PLANE_I_CONNECTION_HPP
#define SCORE_CRYPTO_SRC_API_CONTROL_PLANE_I_CONNECTION_HPP

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <chrono>

namespace score::crypto::api::control_plane
{

/// The connection may process requests for independent contexts concurrently.
/// Callers must serialize requests that use the same stateful context. Access to
/// the connection lifecycle, including GetConnectionNodeId()
/// and destruction, must also be externally serialized.
class IConnection
{
  protected:
    IConnection() = default;

    IConnection& operator=(const IConnection&) = delete;
    IConnection(const IConnection&) = delete;
    IConnection(IConnection&&) = default;
    IConnection& operator=(IConnection&&) = default;

  public:
    /// Destruction releases this wrapper. Implementations may share the
    /// daemon-side connection, so wrapper destruction does not imply that the
    /// daemon-side connection is closed.
    virtual ~IConnection() = default;

    virtual Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> SendRequest(
        daemon::control_plane::protocol::ControlRequest& request) = 0;

    virtual Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode> SendRequest(
        daemon::control_plane::protocol::ControlRequest& request,
        std::chrono::milliseconds timeout) = 0;

    /// @brief Returns the connection node ID assigned by the daemon during CONNECTION_OPEN.
    /// @return DataNodeId that identifies the shared connection on the daemon side, or 0 if not yet established.
    virtual daemon::control_plane::protocol::DataNodeId GetConnectionNodeId() const = 0;
};

}  // namespace score::crypto::api::control_plane

#endif  // SCORE_CRYPTO_SRC_API_CONTROL_PLANE_I_CONNECTION_HPP
