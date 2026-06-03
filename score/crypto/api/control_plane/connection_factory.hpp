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

#ifndef SCORE_CRYPTO_API_CONTROLLPLANE_CONNECTION_FACTORY_HPP
#define SCORE_CRYPTO_API_CONTROLLPLANE_CONNECTION_FACTORY_HPP

#include <memory>
#include <string_view>

#include "score/crypto/common/types.hpp"
#include "score/mw/crypto/api/common/error_domain.hpp"

#include "score/crypto/api/control_plane/i_connection.hpp"

namespace score::crypto::api::control_plane
{

/// Factory for creating control client nodes
/// Handles the creation and initialization of node connections to the daemon
class ConnectionFactory
{
  public:
    ConnectionFactory() = default;
    ~ConnectionFactory() = default;

    // Disable copy, allow move
    ConnectionFactory(const ConnectionFactory&) = delete;
    ConnectionFactory& operator=(const ConnectionFactory&) = delete;
    ConnectionFactory(ConnectionFactory&&) = default;
    ConnectionFactory& operator=(ConnectionFactory&&) = default;

    Expected<std::unique_ptr<IConnection>, score::mw::crypto::CryptoErrorCode> CreateConnection(
        std::string_view endpoint);
};

}  // namespace score::crypto::api::control_plane

#endif  // SCORE_CRYPTO_API_CONTROLLPLANE_CONNECTION_FACTORY_HPP
