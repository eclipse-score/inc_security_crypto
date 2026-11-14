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

#ifndef SCORE_CRYPTO_SRC_API_CONTROL_PLANE_CONNECTION_FACTORY_HPP
#define SCORE_CRYPTO_SRC_API_CONTROL_PLANE_CONNECTION_FACTORY_HPP

#include <memory>
#include <string_view>

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"

namespace score::crypto::api::control_plane
{

/// Factory for creating control client nodes.
/// Connections for the same endpoint share one opened daemon-side connection
/// and one underlying message-passing transport while a strong connection owner exists.
class ConnectionFactory
{
  public:
    /// @brief Creates a factory for shared control-plane connections.
    ConnectionFactory() = default;
    /// @brief Releases this factory without closing connections still held by callers.
    ~ConnectionFactory() = default;

    // Disable copy, allow move
    ConnectionFactory(const ConnectionFactory&) = delete;
    ConnectionFactory& operator=(const ConnectionFactory&) = delete;
    ConnectionFactory(ConnectionFactory&&) = default;
    ConnectionFactory& operator=(ConnectionFactory&&) = default;

    /// @brief Establishes or reuses the shared connection for an endpoint.
    /// @param endpoint Service endpoint identifying the daemon.
    /// @return The shared connection, or the error that prevented establishment.
    Expected<std::shared_ptr<IConnection>, score::crypto::CryptoErrorCode> EstablishConnection(
        std::string_view endpoint);
};

}  // namespace score::crypto::api::control_plane

#endif  // SCORE_CRYPTO_SRC_API_CONTROL_PLANE_CONNECTION_FACTORY_HPP
