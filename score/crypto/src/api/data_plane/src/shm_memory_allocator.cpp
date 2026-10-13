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

#include "score/crypto/src/api/data_plane/src/shm_memory_allocator.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include "score/mw/log/logging.h"
#include <cstddef>
#include <cstdint>
#include <memory>

namespace protocol = score::crypto::daemon::control_plane::protocol;
namespace actors = score::crypto::daemon::common::actors;
namespace med_ops = score::crypto::daemon::mediator::operations;

namespace score
{

namespace crypto
{

score::Result<std::unique_ptr<ShmMemoryAllocator>> ShmMemoryAllocator::Create(
    std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
    IReadWriteMemoryFactory::Sptr factory,
    std::shared_ptr<IShmRegionRegistry> registry)
{
    if (!connection)
    {
        return score::Result<std::unique_ptr<ShmMemoryAllocator>>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "Connection is null")};
    }

    if (!factory)
    {
        return score::Result<std::unique_ptr<ShmMemoryAllocator>>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "Factory is null")};
    }

    if (!registry)
    {
        return score::Result<std::unique_ptr<ShmMemoryAllocator>>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "Registry is null")};
    }

    return std::make_unique<ShmMemoryAllocator>(
        ConstructorTag{}, std::move(connection), std::move(factory), std::move(registry));
}

ShmMemoryAllocator::ShmMemoryAllocator(ConstructorTag /* tag */,
                                       std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                       IReadWriteMemoryFactory::Sptr factory,
                                       std::shared_ptr<IShmRegionRegistry> registry)
    : m_connection_ptr(std::move(connection)), m_factory_ptr(std::move(factory)), m_registry_ptr(std::move(registry))
{
    // All pointers validated by Create()
}

score::Result<IReadWriteMemory::Uptr> ShmMemoryAllocator::Allocate(std::size_t size,
                                                                   std::optional<ProviderType> provider_type)
{
    auto result = AllocateInternal(size, provider_type, std::nullopt);
    if (!result.has_value())
    {
        return score::MakeUnexpected(result.error());
    }
    return std::move(result).value();
}

score::Result<IReadWriteMemory::Uptr> ShmMemoryAllocator::Allocate(std::size_t size, const CryptoResourceId& provider)
{
    const std::optional<std::uint16_t> provider_id =
        (provider.primary_provider != med_ops::SHM_WIRE_PROVIDER_ID_UNBOUND)
            ? std::optional<std::uint16_t>{provider.primary_provider}
            : std::nullopt;
    auto result = AllocateInternal(size, std::nullopt, provider_id);
    if (!result.has_value())
    {
        return score::MakeUnexpected(result.error());
    }
    return std::move(result).value();
}

std::size_t ShmMemoryAllocator::GetQuota() const noexcept
{
    return m_registry_ptr->GetQuota();
}

std::size_t ShmMemoryAllocator::GetCurrentUsage() const noexcept
{
    return m_registry_ptr->GetTotalRegisteredSize();
}

score::crypto::Expected<IReadWriteMemory::Uptr, CryptoErrorCode> ShmMemoryAllocator::AllocateInternal(
    std::size_t size,
    std::optional<ProviderType> provider_type,
    std::optional<std::uint16_t> provider_id)
{
    // Encode provider hints as trailing wire params.
    // Sentinel values signal "absent" to the daemon:
    //   param(1): SHM_WIRE_PROVIDER_TYPE_ABSENT = no ProviderType hint (DEFAULT)
    //   param(2): SHM_WIRE_PROVIDER_ID_UNBOUND  = no primary_provider hint (unbound)
    const std::uint64_t wire_provider_type = provider_type.has_value()
                                                 ? static_cast<std::uint64_t>(provider_type.value())
                                                 : med_ops::SHM_WIRE_PROVIDER_TYPE_ABSENT;
    const std::uint64_t wire_provider_id = provider_id.has_value() ? static_cast<std::uint64_t>(provider_id.value())
                                                                   : med_ops::SHM_WIRE_PROVIDER_ID_UNBOUND;

    // Build request: OP_ACTOR_MEDIATOR / SHM_SETUP (is_pool=0 — bulk object)
    auto request = protocol::OperationRequestBuilder()
                       .operation({actors::OP_ACTOR_MEDIATOR, med_ops::SHM_SETUP})
                       .with_in_val_uint64(size)
                       .with_in_val_uint64(wire_provider_type)
                       .with_in_val_uint64(wire_provider_id)
                       .with_in_val_uint64(0U)  // is_pool=false
                       .build();

    if (!request.has_value())
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kInternalError);
    }

    protocol::ControlRequest ctrl_req{};
    ctrl_req.operation = request.value();
    ctrl_req.data_node_id = m_connection_ptr->GetConnectionNodeId();
    auto send_res = m_connection_ptr->SendRequest(ctrl_req);
    if (!send_res.has_value())
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kAllocationFailed);
    }
    auto response = send_res.value().operation;
    if (response.operations.empty())
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kAllocationFailed);
    }

    const auto& op_resp = response.operations[0];

    // Check daemon result
    if (op_resp.result != protocol::OPERATION_RESULT_SUCCESS)
    {
        // Map daemon error to client error
        if (op_resp.result == static_cast<protocol::OperationResult>(CryptoErrorCode::kQuotaExceeded))
        {
            return score::crypto::make_unexpected(CryptoErrorCode::kQuotaExceeded);
        }
        return score::crypto::make_unexpected(CryptoErrorCode::kAllocationFailed);
    }

    // Extract parameters and build ShmSetupResponse for the data plane factory.
    auto node_id_param = op_resp.getParameter<std::uint64_t>(0);
    auto size_param = op_resp.getParameter<std::uint64_t>(1);
    auto token_param = op_resp.getParameter<protocol::DataBufferReturn>(2);
    auto transport_param = op_resp.getParameter<std::uint64_t>(3);

    if (!node_id_param.has_value() || !size_param.has_value() || !token_param.has_value())
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kAllocationFailed);
    }

    const auto& token_buf = token_param.value();
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto* token_str = reinterpret_cast<const char*>(token_buf.data());
    ShmRegionParams region_params{.node_id = node_id_param.value(),
                                  .size = size_param.value(),
                                  .token = std::string{token_str, token_buf.size()},
                                  .transport_type = transport_param.value_or(static_cast<std::uint64_t>(
                                      score::crypto::daemon::mediator::operations::ShmTransportType::kPosixNamed))};

    auto result = m_factory_ptr->Create(region_params);
    if (!result.has_value())
    {
        return score::crypto::make_unexpected(result.error());
    }
    return std::move(result).value().memory;
}

}  // namespace crypto

}  // namespace score
