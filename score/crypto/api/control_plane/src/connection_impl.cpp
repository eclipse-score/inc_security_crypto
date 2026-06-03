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

#include "score/crypto/api/control_plane/src/connection_impl.hpp"
#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/control_plane/control_operations.h"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/ipc/grpc_adapter/grpc_control_client.h"
#include "score/mw/crypto/api/common/error_domain.hpp"

namespace score::crypto::api::control_plane
{

ConnectionImpl::ConnectionImpl(std::string_view endpoint) : mClient(std::make_unique<ipc::GrpcControlClient>(endpoint))
{
}

ConnectionImpl::~ConnectionImpl()
{
    // Send CONNECTION_CLOSE when the last reference to this connection is destroyed
    if (m_connection_id == 0)
    {
        return;  // Connection not fully opened
    }

    namespace proto = ::score::crypto::daemon::control_plane::protocol;
    namespace ctrl_ops = ::score::crypto::daemon::control_plane::operations;

    auto requestRes =
        proto::ControlRequestBuilder().forDataNodeId(m_connection_id).operation(ctrl_ops::CloseConnection()).build();

    if (!requestRes.has_value())
    {
        score::mw::log::LogError() << "[IPC][ConnectionImpl] ERROR: Failed to build CONNECTION_CLOSE request";
        return;
    }

    auto responseRes = mClient->SendRequest(requestRes.value());

    auto validator = proto::ControlResponseValidator::FromResult(responseRes);
    validator.expectOperation(ctrl_ops::CloseConnection()).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[IPC][ConnectionImpl] ERROR: CONNECTION_CLOSE response validation failed: "
                                   << validator.getError();
        return;
    }
}

Expected<daemon::control_plane::protocol::ControlResponse, score::mw::crypto::CryptoErrorCode>
ConnectionImpl::SendRequest(const daemon::control_plane::protocol::ControlRequest& request)
{
    // HINT: We expect, that the IPC
    // - Ensures Blocking behaviour (RPC style)
    // - Ensures Responses are matching the Request
    // - Enhances the request with UserId and RequestId
    return mClient->SendRequest(request);
}

daemon::control_plane::protocol::DataNodeId ConnectionImpl::GetConnectionNodeId() const
{
    return m_connection_id;
}

void ConnectionImpl::SetConnectionNodeId(daemon::control_plane::protocol::DataNodeId id)
{
    m_connection_id = id;
}

}  // namespace score::crypto::api::control_plane
