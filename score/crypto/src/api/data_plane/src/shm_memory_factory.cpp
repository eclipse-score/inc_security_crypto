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

#include "score/crypto/src/api/data_plane/shm_memory_factory.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"
#include "score/crypto/src/api/data_plane/src/shm_rw_memory.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/memory/shared/shared_memory_factory.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace protocol = score::crypto::daemon::control_plane::protocol;
namespace actors = score::crypto::daemon::common::actors;
namespace med_ops = score::crypto::daemon::mediator::operations;

namespace score
{

namespace crypto
{

ShmMemoryFactory::ShmMemoryFactory(std::shared_ptr<IShmRegionRegistry> registry,
                                   std::shared_ptr<score::crypto::api::control_plane::IConnection> connection)
    : m_registry{std::move(registry)}, m_connection{std::move(connection)}
{
}

score::crypto::Expected<ShmCreateResult, CryptoErrorCode> ShmMemoryFactory::Create(const ShmRegionParams& region_params)
{
    const std::uint64_t node_id = region_params.node_id;
    const std::size_t usable_size = static_cast<std::size_t>(region_params.size);
    const auto transport_type =
        static_cast<score::crypto::daemon::mediator::operations::ShmTransportType>(region_params.transport_type);

    if (transport_type != score::crypto::daemon::mediator::operations::ShmTransportType::kPosixNamed)
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kUnsupportedOperation);
    }

    auto resource = score::memory::shared::SharedMemoryFactory::Open(region_params.token, /*is_read_write=*/true);
    if (resource == nullptr)
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kAllocationFailed);
    }

    void* addr = resource->getUsableBaseAddress();
    if (addr == nullptr)
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kAllocationFailed);
    }

    std::shared_ptr<void> handle(resource.get(), [res = std::move(resource)](void*) mutable {
        res.reset();
    });

    if (m_registry == nullptr)
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kUninitializedStack);
    }

    // Create a stateless destroy callback for sending SHM_DESTROY_OBJECT. The connection it operates on is
    // owned by the ShmReadWriteMemory and passed in when the callback is invoked, so the callback does not
    // capture any factory state and stays valid even if this factory has been destroyed.
    DestroyRequestCallback destroy_callback =
        [](std::uint64_t node_id, const std::shared_ptr<score::crypto::api::control_plane::IConnection>& connection) {
            if (connection != nullptr)
            {
                auto destroy_req = protocol::OperationRequestBuilder()
                                       .operation({actors::OP_ACTOR_MEDIATOR, med_ops::SHM_DESTROY_OBJECT})
                                       .with_in_val_uint64(node_id)
                                       .build();
                if (destroy_req.has_value())
                {
                    protocol::ControlRequest ctrl_req{};
                    ctrl_req.operation = destroy_req.value();
                    ctrl_req.data_node_id = connection->GetConnectionNodeId();
                    connection->SendRequest(ctrl_req);
                }
                else
                {
                    score::mw::log::LogError()
                        << "[ShmMemoryFactory] ERROR: Failed to build SHM_DESTROY_OBJECT request";
                }
            }
        };

    auto memory_result = ShmReadWriteMemory::Create(node_id,
                                                    std::move(handle),
                                                    score::cpp::span<uint8_t>{static_cast<uint8_t*>(addr), usable_size},
                                                    m_registry,
                                                    m_connection,
                                                    std::move(destroy_callback));

    if (!memory_result.has_value())
    {
        return score::crypto::make_unexpected(static_cast<CryptoErrorCode>(*memory_result.error()));
    }

    return ShmCreateResult{node_id, std::move(memory_result.value())};
}

}  // namespace crypto

}  // namespace score
