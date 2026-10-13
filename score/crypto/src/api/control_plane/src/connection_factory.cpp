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

#include "score/crypto/src/common/types.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/control_plane/connection_factory.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/control_plane/src/control_plane_connection_registry.hpp"

#include <string>
#include <utility>

namespace score::crypto::api::control_plane
{

Expected<std::shared_ptr<IConnection>, score::crypto::CryptoErrorCode> ConnectionFactory::EstablishConnection(
    std::string_view endpoint)
{
    const std::string_view messagePassingProtocolPrefix = "score://";
    if (endpoint.rfind(messagePassingProtocolPrefix, 0) != 0)
    {
        score::mw::log::LogError()
            << "[CONNECTION_FACTORY] ERROR - Unsupported endpoint protocol. Only score:// protocol "
               "is supported.";
        return make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
    }

    const std::string_view endpointIdentifier = endpoint.substr(messagePassingProtocolPrefix.size());

    try
    {
        auto connection_result = ControlPlaneConnectionRegistry::Instance().EstablishConnection(endpointIdentifier);
        if (!connection_result.has_value())
        {
            score::mw::log::LogError() << "[CONNECTION_FACTORY] ERROR - Failed to open endpoint: "
                                       << endpointIdentifier;
            return score::crypto::make_unexpected(connection_result.error());
        }
        return std::shared_ptr<IConnection>{std::move(connection_result).value()};
    }
    catch (...)
    {
        score::mw::log::LogError() << "[CONNECTION_FACTORY] ERROR - Failed to open endpoint: " << endpointIdentifier;
        return score::crypto::make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
    }
}

}  // namespace score::crypto::api::control_plane
