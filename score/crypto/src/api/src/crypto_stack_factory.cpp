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

#include "score/crypto/src/api/crypto_stack_factory.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/data_plane/i_read_write_memory_factory.hpp"
#include "score/crypto/src/api/data_plane/shm_memory_factory.hpp"
#include "score/crypto/src/api/data_plane/src/pool_allocator.hpp"
#include "score/crypto/src/api/data_plane/src/shm_region_registry.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/src/crypto_stack_impl.hpp"

#include "score/crypto/src/api/control_plane/connection_factory.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_operations.h"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

#include "score/result/result.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>

namespace proto = score::crypto::daemon::control_plane::protocol;
namespace actors = score::crypto::daemon::common::actors;
namespace med_ops = score::crypto::daemon::mediator::operations;

namespace score
{

namespace crypto

{

namespace
{

/// @brief Setup data plane handshake and return validated SHM_SETUP parameters.
///
/// Sends SHM_SETUP(is_pool=1), receives response, validates pool geometry, and returns
/// the extracted parameters as a ShmSetupResponse for use by CreateCryptoStack.
score::crypto::Expected<ShmSetupResponse, score::result::Error> SetupDataPlane(
    std::shared_ptr<score::crypto::api::control_plane::IConnection> connection)
{
    auto req = proto::OperationRequestBuilder()
                   .operation({actors::OP_ACTOR_MEDIATOR, med_ops::SHM_SETUP})
                   .with_in_val_uint64(0U)  // size=0; daemon uses config pool_size
                   .with_in_val_uint64(med_ops::SHM_WIRE_PROVIDER_TYPE_ABSENT)
                   .with_in_val_uint64(med_ops::SHM_WIRE_PROVIDER_ID_UNBOUND)
                   .with_in_val_uint64(1U)  // is_pool=1
                   .build();
    if (!req.has_value())
    {
        return score::Result<ShmSetupResponse>{
            score::unexpect, MakeError(CryptoErrorCode::kAllocationFailed, "Failed to build SHM_SETUP request")};
    }

    proto::ControlRequest ctrl_req{};
    ctrl_req.operation = req.value();
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    ctrl_req.data_node_id = connection->GetConnectionNodeId();
    auto res = connection->SendRequest(ctrl_req);

    auto validator = proto::ControlResponseValidator::FromResult(res);
    validator.expectOperation(med_ops::CreateShmObject()).expectSuccess();
    if (!validator.isValid())
    {
        return score::Result<ShmSetupResponse>{
            score::unexpect, MakeError(CryptoErrorCode::kAllocationFailed, "SHM_SETUP daemon response invalid")};
    }

    // Extract and validate all required parameters.
    auto node_id_param = validator.getParameterAt<std::uint64_t>(0, med_ops::SHM_PARAM_NODE_ID);
    auto size_param = validator.getParameterAt<std::uint64_t>(0, med_ops::SHM_PARAM_SIZE);
    auto token_param = validator.getParameterAt<proto::DataBufferReturn>(0, med_ops::SHM_PARAM_TOKEN);
    auto transport_param = validator.getParameterAt<std::uint64_t>(0, med_ops::SHM_PARAM_TRANSPORT);
    auto slot_size_param = validator.getParameterAt<std::uint64_t>(0, med_ops::SHM_PARAM_SLOT_SIZE);
    auto total_quota_param = validator.getParameterAt<std::uint64_t>(0, med_ops::SHM_PARAM_TOTAL_QUOTA);

    if (!node_id_param.has_value() || !size_param.has_value() || !token_param.has_value() ||
        !slot_size_param.has_value() || !total_quota_param.has_value())
    {
        return score::Result<ShmSetupResponse>{
            score::unexpect,
            MakeError(CryptoErrorCode::kAllocationFailed, "SHM_SETUP response missing required parameters")};
    }

    // Extract pool geometry parameter values for validation.
    const auto pool_size = static_cast<std::size_t>(size_param.value());
    const PoolGeometry pool_geom{.slot_size = slot_size_param.value(), .total_quota = total_quota_param.value()};

    // Validate pool geometry parameter values.
    if (pool_geom.total_quota == 0)
    {
        return score::Result<ShmSetupResponse>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "Total quota configured as 0")};
    }

    if (pool_geom.slot_size == 0)
    {
        return score::Result<ShmSetupResponse>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "Pool slot size configured as 0")};
    }

    if (pool_size == 0)
    {
        return score::Result<ShmSetupResponse>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "Pool size configured as 0")};
    }

    if (pool_size < pool_geom.slot_size)
    {
        return score::Result<ShmSetupResponse>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInvalidArgument,
                      "Pool size (" + std::to_string(pool_size) + ") is smaller than slot size (" +
                          std::to_string(pool_geom.slot_size) + ")")};
    }

    // Build and return ShmSetupResponse.
    const auto& token_buf = token_param.value();
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto* token_str = reinterpret_cast<const char*>(token_buf.data());

    ShmRegionParams region{.node_id = node_id_param.value(),
                           .size = size_param.value(),
                           .token = std::string{token_str, token_buf.size()},
                           .transport_type = transport_param.value_or(static_cast<std::uint64_t>(
                               score::crypto::daemon::mediator::operations::ShmTransportType::kPosixNamed))};

    return ShmSetupResponse{.region = region, .pool = pool_geom};
}

/// @brief Send CONNECTION_OPEN, validate response, extract and set connection DataNodeId.
///
/// @param connection  Active IConnection instance.
/// @return OK on success; error if request build, send, validation, or parameter extraction fails.
score::crypto::Expected<void, CryptoErrorCode> OpenConnection(
    score::crypto::api::control_plane::IConnection& connection)
{
    namespace ctrl = ::score::crypto::daemon::control_plane;

    auto request_res = proto::ControlRequestBuilder()
                           .forDataNodeId(0)  // No connection ID yet during initial open
                           .operation(ctrl::operations::OpenConnection())
                           .build();

    if (!request_res.has_value())
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kConnectionFailed);
    }

    auto response_res = connection.SendRequest(request_res.value());

    // Validate response and extract DataNodeId
    auto validator = proto::ControlResponseValidator::FromResult(response_res);
    validator.expectOperation(ctrl::operations::OpenConnection()).expectSuccess();

    if (!validator.isValid())
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kConnectionFailed);
    }

    // Extract connection DataNodeId from response parameter at index 0
    auto connection_node_id_result = validator.getParameterAt<uint64_t>(0, 0);
    if (!connection_node_id_result.has_value())
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kConnectionFailed);
    }

    connection.SetConnectionNodeId(connection_node_id_result.value());
    return {};
}

}  // namespace

score::Result<ICryptoStack::Uptr> CreateCryptoStack(const CryptoStackConfig& config)
{
    if (config.connection_endpoint.empty())
    {
        return score::Result<ICryptoStack::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "Connection endpoint must not be empty")};
    }

    score::crypto::api::control_plane::ConnectionFactory factory;
    auto connection_result = factory.CreateConnection(config.connection_endpoint);
    if (!connection_result.has_value())
    {
        return score::Result<ICryptoStack::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kConnectionFailed, "Failed to create socket connection")};
    }

    auto connection =
        std::shared_ptr<score::crypto::api::control_plane::IConnection>(std::move(connection_result.value()));

    // Open connection and extract DataNodeId
    auto open_res = OpenConnection(*connection);
    if (!open_res.has_value())
    {
        return score::Result<ICryptoStack::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kConnectionFailed, "Failed to open connection")};
    }

    // Setup data plane and extract pool geometry.
    auto setup_result = SetupDataPlane(connection);
    if (!setup_result.has_value())
    {
        return score::Result<ICryptoStack::Uptr>{score::unexpect, setup_result.error()};
    }

    const auto& shm_setup = setup_result.value();

    // Extract pool geometry from the validated SHM setup.
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access) - SetupDataPlane always sets pool for is_pool=1
    const auto& pool_geom = shm_setup.pool.value();

    // Create data plane components.
    auto registry = std::make_shared<ShmRegionRegistry>(pool_geom.total_quota);
    auto shm_factory = std::make_shared<ShmMemoryFactory>(registry, connection);

    // Create and map the pool SHM region (pass only region params, not pool geometry).
    auto pool_create = shm_factory->Create(shm_setup.region, /*is_pool=*/true);
    if (!pool_create.has_value())
    {
        return score::Result<ICryptoStack::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kAllocationFailed, "Failed to create pool SHM region")};
    }

    auto pool_allocator_result = PoolAllocator::Create(std::move(pool_create).value(), pool_geom.slot_size);
    if (!pool_allocator_result.has_value())
    {
        return score::Result<ICryptoStack::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "Failed to create PoolAllocator")};
    }

    // Create and return complete CryptoStack.
    auto stack = std::make_unique<CryptoStackImpl>(
        config, connection, std::move(shm_factory), std::move(pool_allocator_result).value(), std::move(registry));
    return score::Result<ICryptoStack::Uptr>{std::move(stack)};
}

}  // namespace crypto

}  // namespace score
