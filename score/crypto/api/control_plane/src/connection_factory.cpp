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

#include "score/mw/log/logging.h"

#include <memory>
#include <string_view>

#include "score/crypto/common/types.hpp"

#include "score/crypto/api/control_plane/connection_factory.hpp"
#include "score/crypto/api/control_plane/i_connection.hpp"
#include "score/crypto/api/control_plane/src/connection_impl.hpp"
#include "score/mw/crypto/api/common/error_domain.hpp"

namespace score::crypto::api::control_plane
{

Expected<std::unique_ptr<IConnection>, score::mw::crypto::CryptoErrorCode> ConnectionFactory::CreateConnection(
    std::string_view endpoint)
{
    const std::string_view unixProtocolPrefix = "unix://";
    if (endpoint.rfind(unixProtocolPrefix, 0) != 0)
    {
        score::mw::log::LogError()
            << "[CONTROL_CLIENT_NODE_FACTORY] ERROR - Unsupported endpoint protocol. Only unix domain sockets "
               "are supported.";
        return make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
    }

    const std::string_view socketPath = endpoint.substr(unixProtocolPrefix.size());

    auto connection = std::make_unique<ConnectionImpl>(socketPath);
    if (!connection)
    {
        score::mw::log::LogError() << "[CONTROL_CLIENT_NODE_FACTORY] ERROR - Failed to create connection to socket: "
                                   << socketPath;
        return make_unexpected(score::mw::crypto::CryptoErrorCode::kInternalError);
    }

    return connection;
}

}  // namespace score::crypto::api::control_plane
