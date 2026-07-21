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

#include "score/crypto/daemon/control_plane/src/connection_handler.hpp"
#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/control_plane/control_operations.h"
#include "score/crypto/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"

#include "score/mw/log/logging.h"

#include <memory>
#include <sstream>
#include <thread>

namespace score::crypto::daemon::control_plane
{

ConnectionHandler::ConnectionHandler(std::unique_ptr<IRequestHandler> next_request_handler,
                                     std::shared_ptr<data_manager::IDataManager> data_manager,
                                     const config::Config& config)
    : m_next_request_handler(std::move(next_request_handler)), m_data_manager(data_manager)
{
    (void)config;  // For future use
}

ControlResponse ConnectionHandler::processRequest(const ControlRequest& request)
{
    score::mw::log::LogDebug() << "[CONTROL_HANDLER] Received request - Request ID:" << request.request_id
                               << ", Client Id ID:" << request.client_id << ", UID:" << request.uid
                               << ", PID:" << request.pid << ", Data Node Id:" << request.data_node_id
                               << ", Data Node Value:" << request.node_id_value
                               << ", Data Node Tag:" << request.node_tag_value;
    std::ostringstream tid;
    tid << std::this_thread::get_id();
    score::mw::log::LogDebug() << "[CONTROL_HANDLER] Thread ID:" << tid.str();
    // Validate empty request
    if (request.operation.operations.empty())
    {
        score::mw::log::LogDebug() << "[CONTROL_HANDLER] Empty operation, returning error";
        protocol::OperationResponseBuilder builder;
        auto opResponse = builder.build().value();
        return ControlResponse{request.request_id, opResponse};
    }

    // TODO: This probably also needs to be refactored.
    // Currently, we are only processing the first operation in the request.
    // We should iterate through all operations and process them accordingly.
    // But that also means we need the response builder here and forward it
    // Otherwise, we need to limit what types of request can be combined in one batch

    // This means IRequestHandler::processRequest needs to be refactored

    protocol::OperationResponseBuilder responseBuilder;

    // Iterate through operations in request - process those for the control plane
    for (size_t idx = 0; idx < request.operation.operations.size(); ++idx)
    {
        // Extract operation name
        const auto& opId = request.operation.operations[idx].operationId;
        score::mw::log::LogDebug() << "[CONTROL_HANDLER] Operation actor:" << opId.operationActor
                                   << " action:" << opId.operationAction;
        if (opId.operationActor != common::actors::OP_ACTOR_CONTROL)
        {
            // Forward to next handler
            return m_next_request_handler->processRequest(request);
        }
        else
        {
            if (!ProcessSingleRequest(request, request.operation.operations[idx].operationId, responseBuilder))
            {
                score::mw::log::LogError()
                    << "[CONTROL_HANDLER] Failed to process control operation: actor=" << opId.operationActor
                    << " action=" << opId.operationAction;
                score::mw::log::LogError()
                    << "[CONTROL_HANDLER] Stopping further processing of operations in this request";
                break;
            }
        }
    }

    return ControlResponse{request.request_id,
                           responseBuilder.build().value_or(control_plane::protocol::OperationResponse())};
}

bool ConnectionHandler::ProcessSingleRequest(const ControlRequest& request,
                                             const common::OperationIdentifier& opId,
                                             control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    score::mw::log::LogDebug() << "[CONTROL_HANDLER] Processing control operation: actor=" << opId.operationActor
                               << " action=" << opId.operationAction;

    if (opId.operationAction == operations::CONNECTION_OPEN)
    {
        return ProcessConnectionCreation(request, opId, responseBuilder);
    }
    if (opId.operationAction == operations::CONNECTION_CLOSE)
    {
        return ProcessConnectionClosure(request, opId, responseBuilder);
    }

    return ProcessUnknownRequest(request, opId, responseBuilder);
}

bool ConnectionHandler::ProcessConnectionCreation(const ControlRequest& request,
                                                  const common::OperationIdentifier& opId,
                                                  control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    // Create root node via DataManager - returns assigned DataNodeId
    auto node = std::make_shared<data_manager::DataNode>();
    auto dataNodeIdRes = m_data_manager->addNode(request.client_id, node);
    if (!dataNodeIdRes.has_value())
    {
        score::mw::log::LogError() << "[CONTROL_HANDLER] Failed to create connection";
        responseBuilder.operation(opId).return_error(dataNodeIdRes.error());
        return false;
    }

    auto connection_id = dataNodeIdRes.value();

    score::mw::log::LogDebug() << "[CONTROL_HANDLER] Created connection with connection_id:" << connection_id;

    // Build success response with connection_id
    responseBuilder.operation(opId).return_success().return_value_uint64(connection_id);

    return true;
}

bool ConnectionHandler::ProcessConnectionClosure(const ControlRequest& request,
                                                 const common::OperationIdentifier& opId,
                                                 control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    auto connection_id = request.data_node_id;
    auto client_id = request.client_id;

    score::mw::log::LogDebug() << "[CONTROL_HANDLER] Closing client_id:" << client_id
                               << " connection_id:" << connection_id;

    // Clear all contexts associated with this connection by removing the connection node
    // This will cascade delete all child context nodes
    auto result = m_data_manager->deleteNode(client_id, connection_id);
    if (!result.has_value())
    {
        score::mw::log::LogDebug() << "[CONTROL_HANDLER] Warning Connection_id:" << connection_id << " not found";
    }

    responseBuilder.operation(opId).return_success();
    return true;
}

bool ConnectionHandler::ProcessUnknownRequest(const ControlRequest& request,
                                              const common::OperationIdentifier& opId,
                                              control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    score::mw::log::LogDebug() << "[CONTROL_HANDLER] Received unknown operationAction=" << opId.operationAction;
    responseBuilder.operation(opId).return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
    return true;
}

}  // namespace score::crypto::daemon::control_plane
