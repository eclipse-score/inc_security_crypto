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

#include "score/crypto/src/daemon/data_plane/src/shm_request_handler.hpp"

#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/data_manager/data_node_accessor.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/src/daemon/data_plane/i_shm_data_node.hpp"

#include "score/span.hpp"

#include <cstdint>
#include <memory>
#include <utility>
#include <variant>

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::data_plane
{

ShmRequestHandler::ShmRequestHandler(std::unique_ptr<control_plane::IRequestHandler> next_handler,
                                     data_manager::IDataManager::Sptr data_manager)
    : m_next_handler(std::move(next_handler)), m_data_manager(std::move(data_manager))
{
}

control_plane::ControlResponse ShmRequestHandler::processRequest(control_plane::ControlRequest& request)
{
    return ForwardWithResolvedShm(request);
}

control_plane::ControlResponse ShmRequestHandler::ForwardWithResolvedShm(control_plane::ControlRequest& request)
{
    for (auto& operation : request.operation.operations)
    {
        for (auto& param : operation.parameters)
        {
            if (!std::holds_alternative<common::DataShm>(param))
            {
                continue;
            }

            const auto& data_shm = std::get<common::DataShm>(param);

            auto accessor_res = m_data_manager->getNodeAccessor(request.client_id, data_shm.node_id);
            if (!accessor_res.has_value())
            {
                score::mw::log::LogError() << LOG_PREFIX << "getNodeAccessor failed for node_id=" << data_shm.node_id;
                control_plane::protocol::OperationResponseBuilder builder;
                builder.operation(operation.operationId).return_error(common::DaemonErrorCode::kInvalidMemoryRegion);
                return control_plane::ControlResponse{request.request_id, builder.build().value()};
            }
            auto node_res = std::move(accessor_res).value().downCast<IShmDataNode>();
            if (!node_res.has_value())
            {
                score::mw::log::LogError()
                    << LOG_PREFIX << "downCast<IShmDataNode> failed for node_id=" << data_shm.node_id;
                control_plane::protocol::OperationResponseBuilder builder;
                builder.operation(operation.operationId).return_error(common::DaemonErrorCode::kInvalidMemoryRegion);
                return control_plane::ControlResponse{request.request_id, builder.build().value()};
            }
            auto& node = node_res.value();
            if (data_shm.direction != common::ShmDirection::In && data_shm.direction != common::ShmDirection::InOut)
            {
                score::mw::log::LogError()
                    << LOG_PREFIX << "Invalid shared memory direction for node_id=" << data_shm.node_id;
                control_plane::protocol::OperationResponseBuilder builder;
                builder.operation(operation.operationId).return_error(common::DaemonErrorCode::kInvalidMemoryRegion);
                return control_plane::ControlResponse{request.request_id, builder.build().value()};
            }

            const auto node_size = node->GetSize();
            if (data_shm.offset > node_size || data_shm.size > node_size - data_shm.offset)
            {
                score::mw::log::LogError()
                    << LOG_PREFIX << "Requested shared memory location out of bounds for node_id=" << data_shm.node_id
                    << ": offset=" << data_shm.offset << ", size=" << data_shm.size << ", node_size=" << node_size;
                control_plane::protocol::OperationResponseBuilder builder;
                builder.operation(operation.operationId).return_error(common::DaemonErrorCode::kInvalidMemoryRegion);
                return control_plane::ControlResponse{request.request_id, builder.build().value()};
            }

            auto* handle = node->GetHandle();
            if (handle == nullptr)
            {
                score::mw::log::LogError()
                    << LOG_PREFIX << "Shared memory handle is null for node_id=" << data_shm.node_id;
                control_plane::protocol::OperationResponseBuilder builder;
                builder.operation(operation.operationId).return_error(common::DaemonErrorCode::kInvalidMemoryRegion);
                return control_plane::ControlResponse{request.request_id, builder.build().value()};
            }

            auto* base_address = handle->getUsableBaseAddress();
            if (base_address == nullptr)
            {
                score::mw::log::LogError()
                    << LOG_PREFIX << "Shared memory usable base address is null for node_id=" << data_shm.node_id;
                control_plane::protocol::OperationResponseBuilder builder;
                builder.operation(operation.operationId).return_error(common::DaemonErrorCode::kInvalidMemoryRegion);
                return control_plane::ControlResponse{request.request_id, builder.build().value()};
            }

            auto* addr = static_cast<std::uint8_t*>(base_address) + data_shm.offset;

            if (data_shm.direction == common::ShmDirection::In)
            {
                param = score::cpp::span<const uint8_t>{addr, data_shm.size};
            }
            else
            {
                param = score::cpp::span<uint8_t>{addr, data_shm.size};
            }
        }
    }

    return m_next_handler->processRequest(request);
}

}  // namespace score::crypto::daemon::data_plane
