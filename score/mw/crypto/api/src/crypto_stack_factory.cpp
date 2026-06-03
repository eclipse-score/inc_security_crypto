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

#include "score/mw/crypto/api/crypto_stack_factory.hpp"

#include "score/mw/crypto/api/common/error_domain.hpp"
#include "score/mw/crypto/api/i_crypto_stack.hpp"
#include "score/mw/crypto/api/src/crypto_stack_impl.hpp"

#include "score/crypto/api/control_plane/connection_factory.hpp"
#include "score/crypto/api/control_plane/i_connection.hpp"
#include "score/crypto/daemon/control_plane/control_operations.h"
#include "score/crypto/daemon/control_plane/control_protocol.h"

#include "score/result/result.h"

#include <cstdint>
#include <memory>
#include <utility>

namespace score
{
namespace mw
{
namespace crypto
{

score::Result<ICryptoStack::Uptr> CreateCryptoStack(const CryptoStackConfig& config)
{
    if (config.connection_endpoint.empty())
    {
        return score::Result<ICryptoStack::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "Connection endpoint must not be empty")};
    }

    // Create socket connection to daemon
    score::crypto::api::control_plane::ConnectionFactory factory;
    auto connection_result = factory.CreateConnection(config.connection_endpoint);
    if (!connection_result.has_value())
    {
        return score::Result<ICryptoStack::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kConnectionFailed, "Failed to create socket connection")};
    }

    auto connection =
        std::shared_ptr<score::crypto::api::control_plane::IConnection>(std::move(connection_result.value()));

    // Send CONNECTION_OPEN to daemon to establish control plane connection
    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    namespace ctrl = ::score::crypto::daemon::control_plane;

    auto request_res = proto::ControlRequestBuilder()
                           .forDataNodeId(0)  // No connection ID yet during initial open
                           .operation(ctrl::operations::OpenConnection())
                           .build();

    if (!request_res.has_value())
    {
        return score::Result<ICryptoStack::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kConnectionFailed, "Failed to build CONNECTION_OPEN request")};
    }

    auto response_res = connection->SendRequest(request_res.value());

    // Validate response and extract DataNodeId
    auto validator = proto::ControlResponseValidator::FromResult(response_res);
    validator.expectOperation(ctrl::operations::OpenConnection()).expectSuccess();

    if (!validator.isValid())
    {
        return score::Result<ICryptoStack::Uptr>{
            score::unexpect,
            MakeError(CryptoErrorCode::kConnectionFailed,
                      "Failed to validate CONNECTION_OPEN response: " + validator.getError())};
    }

    // Extract connection DataNodeId from response parameter at index 0
    auto connection_node_id_result = validator.getParameterAt<uint64_t>(0, 0);
    if (!connection_node_id_result.has_value())
    {
        return score::Result<ICryptoStack::Uptr>{
            score::unexpect,
            MakeError(CryptoErrorCode::kConnectionFailed,
                      "Failed to extract connection DataNodeId from CONNECTION_OPEN response")};
    }

    const uint64_t connection_node_id = connection_node_id_result.value();

    // Set the connection node ID on the connection itself for lifecycle management
    connection->SetConnectionNodeId(connection_node_id);

    return std::make_unique<CryptoStackImpl>(config, connection);
}

}  // namespace crypto
}  // namespace mw
}  // namespace score
