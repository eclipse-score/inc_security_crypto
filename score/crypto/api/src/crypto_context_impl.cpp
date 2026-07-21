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

#include "score/mw/crypto/api/src/crypto_context_impl.hpp"

#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/mw/crypto/api/common/error_domain.hpp"
#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/config/hash_context_config.hpp"
#include "score/mw/crypto/api/config/key_management_context_config.hpp"
#include "score/mw/crypto/api/config/mac_context_config.hpp"
#include "score/mw/crypto/api/contexts/src/hash_context_impl.hpp"
#include "score/mw/crypto/api/contexts/src/key_management_context_impl.hpp"
#include "score/mw/crypto/api/contexts/src/mac_context_impl.hpp"
#include "score/mw/crypto/api/src/provider_type_converter.hpp"

#include "score/crypto/api/control_plane/i_connection.hpp"
#include "score/result/result.h"

#include "score/mw/log/logging.h"
#include <cstdint>

#include <memory>
#include <utility>

// Full definitions needed for Result<unique_ptr<T>> return types
#include "score/mw/crypto/api/contexts/i_hash_context.hpp"
#include "score/mw/crypto/api/contexts/i_key_management_context.hpp"
#include "score/mw/crypto/api/contexts/i_mac_context.hpp"
#include "score/mw/crypto/api/objects/i_key_object.hpp"
#include "score/mw/crypto/api/objects/i_key_slot_object.hpp"

#include "score/crypto/daemon/mediator/mediator_operations.hpp"

namespace score
{
namespace mw
{
namespace crypto
{

CryptoContextImpl::CryptoContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection)
    : m_connection(std::move(connection))
{
}

CryptoContextImpl::~CryptoContextImpl() {}

// ---------------------------------------------------------------------------
// Context Factory — Hash
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<IHashContext>> CryptoContextImpl::CreateHashContext(const HashContextConfig& config)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    // Send CTX_CREATE to the daemon to create a server-side hash context.
    // The daemon will validate the algorithm and return the context_id and digest_size.
    auto request_builder = proto::ControlRequestBuilder()
                               .forDataNodeId(m_connection->GetConnectionNodeId())
                               .operation(score::crypto::daemon::mediator::operations::CreateContext())
                               .with_in_string("HASH")
                               .with_in_string(config.algorithm);

    if (config.provider_type.has_value())
    {
        request_builder =
            request_builder.with_in_val_uint8(ProviderTypeConverter::ToWireValue(config.provider_type.value()));
    }
    else
    {
        request_builder = request_builder.with_no_param();
    }

    auto control_req_result = request_builder.build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: Failed to build CTX_CREATE request";
        return score::Result<std::unique_ptr<IHashContext>>{
            score::unexpect, MakeError(CryptoErrorCode::kContextCreationFailed, "Failed to build CTX_CREATE request")};
    }

    // Send CTX_CREATE request to daemon
    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    // Validate CTX_CREATE response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CreateContext()).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR:" << validator.getError();
        return score::Result<std::unique_ptr<IHashContext>>{
            score::unexpect, MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE daemon response invalid")};
    }

    auto ctx_id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctx_id_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: CTX_CREATE response has invalid context_id type";
        return score::Result<std::unique_ptr<IHashContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE response has invalid context_id type")};
    }

    const uint64_t context_id = ctx_id_result.value();
    auto hash_ctx = std::make_unique<HashContextImpl>(m_connection, context_id, config.algorithm);

    return hash_ctx;
}

// ---------------------------------------------------------------------------
// Resource Resolution
// ---------------------------------------------------------------------------

score::Result<CryptoResourceId> CryptoContextImpl::ResolveResource(const ResourceId& resource_id, ResourceType type)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    auto control_req_result = proto::ControlRequestBuilder()
                                  .forDataNodeId(m_connection->GetConnectionNodeId())
                                  .operation(score::crypto::daemon::mediator::operations::ResolveResource())
                                  .with_in_string(resource_id)
                                  .with_in_val_uint8(static_cast<std::uint8_t>(type))
                                  .build();

    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: Failed to build RESOURCE_RESOLVE request";
        return score::Result<CryptoResourceId>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "Failed to build RESOURCE_RESOLVE request")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::ResolveResource()).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR:" << validator.getError();
        return score::Result<CryptoResourceId>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "RESOURCE_RESOLVE daemon response invalid")};
    }

    auto id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!id_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: RESOURCE_RESOLVE response missing resource_id";
        return score::Result<CryptoResourceId>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInternalError, "RESOURCE_RESOLVE response missing resource_id")};
    }

    auto type_result = validator.getParameterAt<std::uint8_t>(0, 1);
    if (!type_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: RESOURCE_RESOLVE response missing type";
        return score::Result<CryptoResourceId>{
            score::unexpect, MakeError(CryptoErrorCode::kInternalError, "RESOURCE_RESOLVE response missing type")};
    }

    auto persistence_result = validator.getParameterAt<bool>(0, 2);
    if (!persistence_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: RESOURCE_RESOLVE response missing persistence";
        return score::Result<CryptoResourceId>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInternalError, "RESOURCE_RESOLVE response missing persistence")};
    }

    auto primary_provider = validator.getParameterAt<std::uint16_t>(0, 3);
    if (!primary_provider.has_value())
    {
        score::mw::log::LogError()
            << "[API][CryptoContextImpl] ERROR: RESOURCE_RESOLVE response missing primary_provider";
        return score::Result<CryptoResourceId>{
            score::unexpect,
            MakeError(CryptoErrorCode::kInternalError, "RESOURCE_RESOLVE response missing primary_provider")};
    }

    CryptoResourceId resolved{};
    resolved.id = id_result.value();
    resolved.type = static_cast<ResourceType>(type_result.value());
    resolved.persistence =
        persistence_result.value() ? ResourcePersistence::kPersistent : ResourcePersistence::kEphemeral;
    resolved.primary_provider = primary_provider.value();

    return resolved;
}

// ---------------------------------------------------------------------------
// Context Factory stubs — not yet implemented
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<IMacContext>> CryptoContextImpl::CreateMacContext(const MacContextConfig& config)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    if (config.key.id == 0)
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: CreateMacContext invalid / missing key id";
        return score::Result<std::unique_ptr<IMacContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CreateMacContext invalid / missing key id")};
    }

    if (config.key.type != ResourceType::kKey && config.key.type != ResourceType::kKeySlot)
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: CreateMacContext invalid key type";
        return score::Result<std::unique_ptr<IMacContext>>{
            score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "CreateMacContext invalid key type")};
    }

    // Send CTX_CREATE to the daemon to create a server-side MAC context.
    // MAC context requires: context type "MAC", algorithm, and key id.
    auto request_builder = proto::ControlRequestBuilder()
                               .forDataNodeId(m_connection->GetConnectionNodeId())
                               .operation(score::crypto::daemon::mediator::operations::CreateContext())
                               .with_in_string("MAC")
                               .with_in_string(config.algorithm);

    if (config.provider_type.has_value())
    {
        request_builder =
            request_builder.with_in_val_uint8(ProviderTypeConverter::ToWireValue(config.provider_type.value()));
    }
    else
    {
        request_builder = request_builder.with_no_param();
    }

    request_builder = request_builder.with_in_val_uint64(config.key.id);

    // Serialize operation_mode (param[4]) so the daemon can route to C_Sign* or C_Verify*.
    request_builder = request_builder.with_in_val_uint8(static_cast<std::uint8_t>(config.operation_mode));

    auto control_req_result = request_builder.build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: Failed to build CTX_CREATE request for MAC";
        return score::Result<std::unique_ptr<IMacContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "Failed to build CTX_CREATE request for MAC")};
    }

    // Send CTX_CREATE request to daemon
    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    // Validate CTX_CREATE response
    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CreateContext()).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR:" << validator.getError();
        return score::Result<std::unique_ptr<IMacContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE MAC daemon response invalid")};
    }

    auto ctx_id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctx_id_result.has_value())
    {
        score::mw::log::LogError()
            << "[API][CryptoContextImpl] ERROR: CTX_CREATE MAC response has invalid context_id type";
        return score::Result<std::unique_ptr<IMacContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE MAC response has invalid context_id type")};
    }

    const uint64_t context_id = ctx_id_result.value();
    auto mac_ctx = std::make_unique<MacContextImpl>(m_connection, context_id, config.algorithm);

    return mac_ctx;
}

score::Result<std::unique_ptr<IKeyManagementContext>> CryptoContextImpl::CreateKeyManagementContext(
    const KeyManagementContextConfig& config)
{
    namespace proto = ::score::crypto::daemon::control_plane::protocol;

    // Send CTX_CREATE to the daemon to create a server-side key management context.
    auto request_builder = proto::ControlRequestBuilder()
                               .forDataNodeId(m_connection->GetConnectionNodeId())
                               .operation(score::crypto::daemon::mediator::operations::CreateContext())
                               .with_in_string("KEY_MANAGEMENT")
                               .with_in_string("");  // no algorithm for key management

    if (config.provider_type.has_value())
    {
        request_builder =
            request_builder.with_in_val_uint8(ProviderTypeConverter::ToWireValue(config.provider_type.value()));
    }
    else
    {
        request_builder = request_builder.with_no_param();
    }

    auto control_req_result = request_builder.build();
    if (!control_req_result.has_value())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: Failed to build CTX_CREATE request for KEY_MGMT";
        return score::Result<std::unique_ptr<IKeyManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "Failed to build CTX_CREATE request for KEY_MGMT")};
    }

    auto control_response_res = m_connection->SendRequest(control_req_result.value());

    auto validator = proto::ControlResponseValidator::FromResult(control_response_res);
    validator.expectOperation(score::crypto::daemon::mediator::operations::CreateContext()).expectSuccess();

    if (!validator.isValid())
    {
        score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR:" << validator.getError();
        return score::Result<std::unique_ptr<IKeyManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed, "CTX_CREATE KEY_MGMT daemon response invalid")};
    }

    auto ctx_id_result = validator.getParameterAt<std::uint64_t>(0, 0);
    if (!ctx_id_result.has_value())
    {
        score::mw::log::LogError()
            << "[API][CryptoContextImpl] ERROR: CTX_CREATE KEY_MGMT response has invalid context_id type";
        return score::Result<std::unique_ptr<IKeyManagementContext>>{
            score::unexpect,
            MakeError(CryptoErrorCode::kContextCreationFailed,
                      "CTX_CREATE KEY_MGMT response has invalid context_id type")};
    }

    const uint64_t context_id = ctx_id_result.value();
    auto key_mgmt_ctx = std::make_unique<KeyManagementContextImpl>(m_connection, context_id);

    return key_mgmt_ctx;
}

// ---------------------------------------------------------------------------
// Queries (TODO)
// ---------------------------------------------------------------------------

score::Result<AlgorithmCapabilities> CryptoContextImpl::QueryCapabilities(const AlgorithmId& /*algorithm*/)
{
    // TODO: Implement algorithm capability query via daemon IPC
    score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: QueryCapabilities(algorithm) not yet implemented";
    return score::Result<AlgorithmCapabilities>{
        score::unexpect,
        MakeError(CryptoErrorCode::kUnsupportedOperation, "QueryCapabilities(algorithm) not yet implemented")};
}

score::Result<SystemCapabilities> CryptoContextImpl::QueryCapabilities()
{
    // TODO: Implement system capability query via daemon IPC
    score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: QueryCapabilities() not yet implemented";
    return score::Result<SystemCapabilities>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "QueryCapabilities() not yet implemented")};
}

score::Result<ProviderInfo> CryptoContextImpl::GetProviderInfo(uint16_t /*provider_id*/)
{
    // TODO: Implement provider info query via daemon IPC
    score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: GetProviderInfo not yet implemented";
    return score::Result<ProviderInfo>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetProviderInfo not yet implemented")};
}

score::Result<ProviderInfo> CryptoContextImpl::GetProviderInfo(const CryptoResourceId& /*resourceId*/)
{
    // TODO: Implement provider info query via daemon IPC
    score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: GetProviderInfo not yet implemented";
    return score::Result<ProviderInfo>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetProviderInfo not yet implemented")};
}

// ---------------------------------------------------------------------------
// Typed Object Access (TODO)
// ---------------------------------------------------------------------------

score::Result<std::unique_ptr<IKeyObject>> CryptoContextImpl::GetKeyObject(const CryptoResourceId& /*id*/)
{
    // TODO: Implement key object retrieval via daemon IPC
    score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: GetKeyObject not yet implemented";
    return score::Result<std::unique_ptr<IKeyObject>>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetKeyObject not yet implemented")};
}

score::Result<std::unique_ptr<IKeySlotObject>> CryptoContextImpl::GetKeySlotObject(const CryptoResourceId& /*id*/)
{
    // TODO: Implement key slot object retrieval via daemon IPC
    score::mw::log::LogError() << "[API][CryptoContextImpl] ERROR: GetKeySlotObject not yet implemented";
    return score::Result<std::unique_ptr<IKeySlotObject>>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "GetKeySlotObject not yet implemented")};
}

}  // namespace crypto
}  // namespace mw
}  // namespace score
