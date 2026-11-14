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

#include "score/crypto/src/api/control_plane/src/control_plane_connection.hpp"

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_operations.h"
#include "score/crypto/src/ipc/message_passing_adapter/client/message_passing_control_client.h"

#include <algorithm>
#include <cstdint>
#include <memory>

namespace score::crypto::api::control_plane
{

Expected<daemon::control_plane::protocol::DataNodeId, score::crypto::CryptoErrorCode>
ControlPlaneConnection::OpenConnection() noexcept
{
    try
    {
        auto request_result = daemon::control_plane::protocol::ControlRequestBuilder()
                                  .forDataNodeId(0U)
                                  .operation(daemon::control_plane::operations::OpenConnection())
                                  .build();
        if (!request_result.has_value())
        {
            return make_unexpected(score::crypto::CryptoErrorCode::kConnectionFailed);
        }

        const auto response_result = SendRequest(request_result.value());
        auto validator = daemon::control_plane::protocol::ControlResponseValidator::FromResult(response_result);
        validator.expectOperation(daemon::control_plane::operations::OpenConnection()).expectSuccess();
        if (!validator.isValid())
        {
            return make_unexpected(validator.getOperationError().value_or(CryptoErrorCode::kInternalError));
        }

        const auto connection_id_result = validator.template getParameterAt<std::uint64_t>(0U, 0U);
        if (!connection_id_result.has_value())
        {
            return make_unexpected(validator.getOperationError().value_or(CryptoErrorCode::kInternalError));
        }
        if (connection_id_result.value() == 0U)
        {
            return make_unexpected(score::crypto::CryptoErrorCode::kConnectionFailed);
        }
        return connection_id_result.value();
    }
    catch (...)
    {
        return make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
    }
}

Expected<std::monostate, score::crypto::CryptoErrorCode> ControlPlaneConnection::CloseConnection() noexcept
{
    try
    {
        auto request_result = daemon::control_plane::protocol::ControlRequestBuilder()
                                  .forDataNodeId(m_connection_node_id)
                                  .operation(daemon::control_plane::operations::CloseConnection())
                                  .build();
        if (!request_result.has_value())
        {
            return make_unexpected(score::crypto::CryptoErrorCode::kConnectionFailed);
        }

        const auto response_result = SendRequest(request_result.value());
        auto validator = daemon::control_plane::protocol::ControlResponseValidator::FromResult(response_result);
        validator.expectOperation(daemon::control_plane::operations::CloseConnection()).expectSuccess();
        if (!validator.isValid())
        {
            return make_unexpected(validator.getOperationError().value_or(CryptoErrorCode::kInternalError));
        }
        return {};
    }
    catch (...)
    {
        return make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
    }
}

ControlPlaneConnection::ControlPlaneConnection(
    std::shared_ptr<score::crypto::ipc::message_passing::MessagePassingControlClient> transport) noexcept
    : m_transport(std::move(transport))
{
}

ControlPlaneConnection::~ControlPlaneConnection()
{
    if ((m_transport != nullptr) && (m_connection_node_id != 0U))
    {
        static_cast<void>(CloseConnection());
    }
}

Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
ControlPlaneConnection::SendRequest(daemon::control_plane::protocol::ControlRequest& request)
{
    return m_transport->SendRequest(request);
}

Expected<daemon::control_plane::protocol::ControlResponse, score::crypto::CryptoErrorCode>
ControlPlaneConnection::SendRequest(daemon::control_plane::protocol::ControlRequest& request,
                                    const std::chrono::milliseconds timeout)
{
    return m_transport->SendRequest(request, timeout);
}

daemon::control_plane::protocol::DataNodeId ControlPlaneConnection::GetConnectionNodeId() const
{
    return m_connection_node_id;
}

Expected<std::monostate, score::crypto::CryptoErrorCode> ControlPlaneConnection::Establish() noexcept
{
    if (m_connection_node_id != 0U)
    {
        return {};
    }
    const auto result = OpenConnection();
    if (!result.has_value())
    {
        return make_unexpected(result.error());
    }
    m_connection_node_id = result.value();
    return {};
}

}  // namespace score::crypto::api::control_plane
