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
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/context/context_data_node.hpp"
#include "score/crypto/src/daemon/common/context/context_mode.hpp"
#include "score/crypto/src/daemon/common/context/context_types.hpp"
#include "score/crypto/src/daemon/common/context/i_handler.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/key_compatibility.hpp"
#include "score/crypto/src/daemon/common/operation_names.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/src/daemon/data_manager/data_node_accessor.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/src/daemon/data_plane/src/shm_data_node.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/mediator/context_algorithm.hpp"
#include "score/crypto/src/daemon/mediator/i_mediator.hpp"
#include "score/crypto/src/daemon/mediator/mediator_impl.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/mediator/src/context_assembler.hpp"
#include "score/crypto/src/daemon/mediator/src/context_creation_decoder.hpp"
#include "score/crypto/src/daemon/mediator/src/provider_arbiter.hpp"
#include "score/crypto/src/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

namespace control_plane = score::crypto::daemon::control_plane;

using ControlRequest = control_plane::ControlRequest;
using ControlResponse = control_plane::ControlResponse;

namespace score::crypto::daemon::mediator
{

MediatorImpl::MediatorImpl(MediatorDependencies deps) : IMediator(std::move(deps)) {}

control_plane::ControlResponse MediatorImpl::processRequest(control_plane::ControlRequest& request)
{
    auto responseBuilder = control_plane::protocol::OperationResponseBuilder();

    for (size_t idx = 0; idx < request.operation.operations.size(); ++idx)
    {
        const auto& operation = request.operation.operations[idx];

        // Stop processing requests, once one fails. They may depend on each other
        if (!HandleSingleOperation(request, operation, responseBuilder))
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR at operation index:"
                                       << static_cast<std::uint64_t>(idx);
            break;
        }
    }

    // Build response
    auto opResponse = responseBuilder.build().value_or(control_plane::protocol::OperationResponse());

    ControlResponse response;
    response.request_id = request.request_id;
    response.operation = opResponse;

    score::mw::log::LogVerbose() << "[SCORE_API_MED] Response operations: "
                                 << static_cast<std::uint64_t>(opResponse.operations.size());

    return response;
}

// ============================================================================
// Helper Method Implementations
// ============================================================================
bool MediatorImpl::HandleSingleOperation(const control_plane::ControlRequest& request,
                                         const control_plane::SingleOperationRequest& operation,
                                         control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    if (operation.operationId.operationActor == common::actors::OP_ACTOR_MEDIATOR)
    {
        auto success = HandleMediatorOperation(request, operation, responseBuilder);
        if (!success)
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Failed to handle mediator operation: "
                                       << common::OpId{operation.operationId};
        }
        return success;
    }

    auto success = ForwardSingleOperation(request, operation, responseBuilder);
    if (!success)
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Failed to forward operation: "
                                   << common::OpId{operation.operationId};
    }
    return success;
}

bool MediatorImpl::HandleMediatorOperation(const control_plane::ControlRequest& request,
                                           const control_plane::SingleOperationRequest& operation,
                                           control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    auto operationIdentifier = operation.operationId;

    if (operationIdentifier.operationAction == operations::CTX_CREATE)
    {
        auto success = HandleContextCreationOperation(request, operation, responseBuilder);
        if (!success)
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Failed to handle context creation operation";
        }

        return success;
    }
    else if (operationIdentifier.operationAction == operations::CTX_CLOSE)
    {
        auto success = DeleteNodeAndRespond(request, operation, responseBuilder);
        if (!success)
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Failed to handle context close operation";
        }

        return success;
    }
    else if (operationIdentifier.operationAction == operations::RESOLVE_RESOURCE)
    {
        auto success =
            HandleResourceResolutionOperation(request.client_id, request.data_node_id, operation, responseBuilder);
        if (!success)
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Failed to handle resource resolution operation";
        }
        return success;
    }
    else if (operationIdentifier.operationAction == operations::SHM_SETUP)
    {
        auto success = HandleShmCreateObject(request, operation, responseBuilder);
        if (!success)
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Failed to handle SHM create operation";
        }
        return success;
    }
    else if (operationIdentifier.operationAction == operations::SHM_DESTROY_OBJECT)
    {
        auto success = DeleteNodeAndRespond(request, operation, responseBuilder);
        if (!success)
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Failed to handle SHM destroy operation";
        }
        return success;
    }

    // Operation codes the mediator does not implement are offered to the registered queries.
    if (const auto query = m_mediator_queries->Find(operationIdentifier.operationAction); query)
    {
        const auto success = query->Handle(request, operation, responseBuilder);
        if (!success)
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Mediator query failed: "
                                       << common::OpId{operationIdentifier};
        }
        return success;
    }

    score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Unknown mediator operation: "
                               << common::OpId{operationIdentifier};

    return false;
}

bool MediatorImpl::ForwardSingleOperation(const control_plane::ControlRequest& request,
                                          const control_plane::SingleOperationRequest& operation,
                                          control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    auto operationIdentifier = operation.operationId;
    auto client_id = request.client_id;
    auto context_id = request.data_node_id;

    // Try to retrieve context from data manager
    auto node_accessor_res = m_data_manager->getNodeAccessor(client_id, context_id);
    if (!node_accessor_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - No context found for context_id:" << context_id;
        responseBuilder.operation(operationIdentifier).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    auto context_node_accessor_res =
        std::move(node_accessor_res).value().downCast<score::crypto::daemon::common::ContextDataNode>();
    if (!context_node_accessor_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Context node for context_id:" << context_id
                                   << " is not a ContextDataNode";
        responseBuilder.operation(operationIdentifier).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }
    auto context_node_accessor = std::move(context_node_accessor_res).value();

    auto handler = context_node_accessor->GetHandler();
    if (!handler)
    {
        score::mw::log::LogError()
            << "[SCORE_API_MED] ERROR - Context node accessor does not contain a handler for context_id: "
            << context_id;
        responseBuilder.operation(operationIdentifier).return_error(score::crypto::CryptoErrorCode::kInternalError);
        return false;
    }

    // TODO: Once requests are non-const, we can drop the copy here.
    auto mutable_params = operation.parameters;

    // Build execution context
    const OperationExecutionContext exec_ctx{
        .operationId = operation.operationId, .context_id = context_id, .parameters = mutable_params};

    // Call handler with handler copy, not under lock
    return ExecuteOperation(exec_ctx, handler, responseBuilder);
}

bool MediatorImpl::CreateContextFromFactory(const control_plane::ControlRequest& request,
                                            const control_plane::SingleOperationRequest& operation,
                                            const common::ContextCreationRequest& decoded,
                                            common::IContextFactory& factory,
                                            control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    if (decoded.key_node_id.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Context type " << decoded.context_type
                                   << " is served by a subsystem and does not accept a key reference";
        responseBuilder.operation(operation.operationId)
            .return_error(score::crypto::CryptoErrorCode::kKeyOperationNotPermitted);
        return false;
    }

    auto handler = factory.Create(decoded);
    if (!handler.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Context factory failed for: " << decoded.context_type;
        responseBuilder.operation(operation.operationId).return_error(handler.error());
        return false;
    }

    // A context created by a factory is not bound to a provider, so no provider identifier is recorded.
    const auto context_node_id = m_assembler->Assemble(ContextAssemblyRequest{.client_id = request.client_id,
                                                                              .connection_id = request.data_node_id,
                                                                              .provider_id = common::kInvalidProviderId,
                                                                              .algorithm = decoded.algorithm_descriptor,
                                                                              .context_type = decoded.context_type,
                                                                              .key_node_id = std::nullopt,
                                                                              .mode = decoded.mode,
                                                                              .raw_parameters = operation.parameters},
                                                       handler.value());
    if (!context_node_id.has_value())
    {
        responseBuilder.operation(operation.operationId).return_error(context_node_id.error());
        return false;
    }

    score::mw::log::LogVerbose() << "[SCORE_API_MED] CTX_CREATE [" << decoded.context_type
                                 << "] created by registered factory, context_id=" << context_node_id.value();

    responseBuilder.operation(operation.operationId).return_success().return_value_uint64(context_node_id.value());
    return true;
}

bool MediatorImpl::HandleContextCreationOperation(const score::crypto::daemon::control_plane::ControlRequest& request,
                                                  const control_plane::SingleOperationRequest& operation,
                                                  control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    // Wire-level validation: parameter count, types, provider preference, key reference, algorithm name.
    const auto decoded = DecodeContextCreationRequest(operation);
    if (!decoded.has_value())
    {
        responseBuilder.operation(operation.operationId).return_error(decoded.error());
        return false;
    }
    const auto& req = decoded.value();

    // A context type with a registered factory is created by that factory and skips provider selection.
    if (const auto factory = m_context_factories->Find(req.context_type); factory)
    {
        return CreateContextFromFactory(request, operation, req, *factory, responseBuilder);
    }

    // Provider and handler selection.
    const auto selection = m_arbiter->Select(ProviderSelectionRequest{.client_id = request.client_id,
                                                                      .key_node_id = req.key_node_id,
                                                                      .context_type = req.context_type,
                                                                      .algorithm = req.algorithm_descriptor,
                                                                      .provider = req.provider,
                                                                      .required_capability = req.required_capability});
    if (!selection.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - No compatible provider/handler for: " << req.context_type
                                   << "/" << req.algorithm;
        responseBuilder.operation(operation.operationId).return_error(selection.error());
        return false;
    }
    const auto& chosen = selection.value();

    // Context node creation, optional key binding, and handler initialization.
    const auto context_node_id =
        m_assembler->Assemble(ContextAssemblyRequest{.client_id = request.client_id,
                                                     .connection_id = request.data_node_id,
                                                     .provider_id = chosen.provider->GetProviderId(),
                                                     .algorithm = req.algorithm_descriptor,
                                                     .context_type = req.context_type,
                                                     .key_node_id = req.key_node_id,
                                                     .mode = req.mode,
                                                     .raw_parameters = operation.parameters},
                              chosen.handler);
    if (!context_node_id.has_value())
    {
        responseBuilder.operation(operation.operationId).return_error(context_node_id.error());
        return false;
    }

    const std::string_view provider_selection = chosen.used_fallback          ? " (preferred-provider fallback)"
                                                : req.key_node_id.has_value() ? " (key-affinity resolved)"
                                                : req.required_capability != common::ProviderCapability::kNone
                                                    ? " (capability-based selection)"
                                                    : " (type-based selection)";
    score::mw::log::LogVerbose() << "[SCORE_API_MED] CTX_CREATE [" << req.context_type << "/" << req.algorithm
                                 << "] selected provider: name='" << chosen.provider->GetProviderName()
                                 << "' id=" << chosen.provider->GetProviderId() << provider_selection
                                 << ", context_id=" << context_node_id.value();

    // Return context_id in response (no return_result for CTX_* operations)
    responseBuilder.operation(operation.operationId).return_success().return_value_uint64(context_node_id.value());
    return true;
}

// ============================================================================
// Shared Operation Execution Helper
// ============================================================================
bool MediatorImpl::ExecuteOperation(const OperationExecutionContext& exec_ctx,
                                    const std::shared_ptr<score::crypto::daemon::common::Handler>& handler,
                                    control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    auto execute_result = handler->Execute(exec_ctx.operationId, exec_ctx.parameters);

    if (!execute_result.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Operation execution failed with error code: "
                                   << static_cast<int>(execute_result.error());
        responseBuilder.operation(exec_ctx.operationId).return_error(execute_result.error());
        return false;
    }

    // Add all output parameters to response
    responseBuilder.return_crypto_operation_response(
        exec_ctx.operationId, control_plane::protocol::OPERATION_RESULT_SUCCESS, std::move(execute_result.value()));
    return true;
}

bool MediatorImpl::DeleteNodeAndRespond(
    const control_plane::ControlRequest& request,
    const control_plane::SingleOperationRequest& operation,
    score::crypto::daemon::control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    // Node deletion is idempotent: a missing node means the desired end-state (node absent)
    // already holds, so it is reported as success rather than an error. This mirrors
    // ConnectionHandler's connection-close handling.
    control_plane::protocol::DataNodeId node_id{};
    if (operation.operationId.operationAction == operations::CTX_CLOSE)
    {
        node_id = request.data_node_id;
    }
    else
    {
        const auto node_id_res = operation.getParameter<std::uint64_t>(0);
        if (!node_id_res.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - SHM destroy request has no node id";
            responseBuilder.operation(operation.operationId)
                .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }
        node_id = node_id_res.value();
    }

    if (!m_data_manager->deleteNode(request.client_id, node_id).has_value())
    {
        score::mw::log::LogWarn() << "[SCORE_API_MED] WARNING - node_id: " << node_id << " not found in data manager";
    }

    responseBuilder.operation(operation.operationId).return_success();
    return true;
}

// ============================================================================
// SHM Lifecycle Operation Handling
// ============================================================================

bool MediatorImpl::HandleShmCreateObject(const control_plane::ControlRequest& request,
                                         const control_plane::SingleOperationRequest& operation,
                                         control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    if (!m_shm_registry)
    {
        score::mw::log::LogError() << "[SCORE_API_MED] [SHM_SETUP_FAILED] SHM registry not available";
        responseBuilder.operation(operation.operationId)
            .return_error(score::crypto::CryptoErrorCode::kUnsupportedOperation);
        return false;
    }

    // param[3]: is_pool (0=bulk, 1=pool).
    const auto is_pool_param = operation.getParameter<std::uint64_t>(3);
    const bool is_pool = is_pool_param.has_value() && (is_pool_param.value() != 0U);
    const std::uint32_t uid = control_plane::protocol::GetUidFromClientId(request.client_id);

    std::size_t size{};
    std::shared_ptr<data_plane::IShmFactory> factory_override{};
    data_plane::IShmRegistry::ShmClientConfig pool_config{};

    if (!is_pool)
    {
        auto size_res = operation.getParameter<std::uint64_t>(0);
        if (!size_res.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] [SHM_SETUP_FAILED] missing size parameter";
            responseBuilder.operation(operation.operationId)
                .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }
        size = static_cast<std::size_t>(size_res.value());

        // Decode provider hints encoded by ShmMemoryAllocator::AllocateInternal().
        // param(1): wire ProviderType (SHM_WIRE_PROVIDER_TYPE_ABSENT = absent/DEFAULT)
        // param(2): primary_provider numeric ID (SHM_WIRE_PROVIDER_ID_UNBOUND = absent/unbound)
        const auto type_hint = operation.getParameter<std::uint64_t>(1);
        const auto id_hint = operation.getParameter<std::uint64_t>(2);

        std::shared_ptr<provider::IProvider> provider{};
        if (id_hint.has_value() && id_hint.value() != operations::SHM_WIRE_PROVIDER_ID_UNBOUND)
        {
            provider = m_provider_manager->GetProvider(static_cast<common::ProviderId>(id_hint.value()));
        }
        else if (type_hint.has_value() && type_hint.value() != operations::SHM_WIRE_PROVIDER_TYPE_ABSENT)
        {
            if (type_hint.value() > std::numeric_limits<std::uint8_t>::max())
            {
                score::mw::log::LogError() << "[SCORE_API_MED] [SHM_SETUP_FAILED] Invalid provider type hint";
                responseBuilder.operation(operation.operationId)
                    .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
                return false;
            }

            const auto provider_preference = DecodeProviderTypePreference(static_cast<std::uint8_t>(type_hint.value()));
            if (!provider_preference.has_value())
            {
                score::mw::log::LogError() << "[SCORE_API_MED] [SHM_SETUP_FAILED] Unknown provider type hint";
                responseBuilder.operation(operation.operationId)
                    .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
                return false;
            }

            provider = m_provider_manager->GetProvider(provider_preference.value().primary);
            if (!provider && provider_preference.value().fallback.has_value())
            {
                provider = m_provider_manager->GetProvider(provider_preference.value().fallback.value());
            }
        }
        else
        {
            provider = m_provider_manager->GetProvider(common::CryptoProviderType::DEFAULT);
        }

        if (provider)
        {
            factory_override = provider->GetShmFactory();
        }
    }
    else
    {
        // Pool path — use deployment config size and per-app pool factory.
        auto config_res = m_shm_registry->GetConfig(uid);
        if (!config_res.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] [SHM_SETUP_FAILED] GetConfig failed";
            responseBuilder.operation(operation.operationId).return_error(config_res.error());
            return false;
        }
        pool_config = config_res.value();
        size = pool_config.pool_size;
        factory_override = pool_config.pool_factory;
    }

    if (!factory_override)
    {
        score::mw::log::LogError() << "[SCORE_API_MED] [SHM_SETUP_FAILED] No SHM factory available for client_id="
                                   << request.client_id;
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInternalError);
        return false;
    }

    // Create SHM data node (handles Register + Create + rollback)
    auto node_res = data_plane::ShmDataNode::Create(m_shm_registry, factory_override, size, request.client_id);

    if (!node_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] [SHM_SETUP_FAILED] ShmDataNode::Create error:"
                                   << static_cast<int>(node_res.error());
        responseBuilder.operation(operation.operationId).return_error(node_res.error());
        return false;
    }

    auto node = std::move(node_res).value();

    // Add to data manager
    auto node_id_res = m_data_manager->addChildNode(request.client_id, request.data_node_id, node);
    if (!node_id_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] [SHM_SETUP_FAILED] addChildNode failed:"
                                   << static_cast<int>(node_id_res.error());
        responseBuilder.operation(operation.operationId).return_error(node_id_res.error());
        return false;
    }

    const auto node_id = node_id_res.value();

    // Build IPC response using IShmDataNode interface
    const auto shm_name = node->GetName();
    const auto actual_size = node->GetSize();
    const auto transport_type = node->GetTransportType();

    const std::string_view name_sv = shm_name;
    std::vector<std::uint8_t> name_bytes(name_sv.begin(), name_sv.end());

    auto& resp = responseBuilder.operation(operation.operationId)
                     .return_value_uint64(static_cast<std::uint64_t>(node_id))
                     .return_value_uint64(static_cast<std::uint64_t>(actual_size))
                     .return_value_data_buffer_out(std::move(name_bytes))
                     .return_value_uint64(static_cast<std::uint64_t>(transport_type));
    if (is_pool)
    {
        resp.return_value_uint64(static_cast<std::uint64_t>(pool_config.pool_slot_size))
            .return_value_uint64(static_cast<std::uint64_t>(pool_config.total_quota));
    }

    resp.return_success();
    return true;
}

// ============================================================================
// Resource Resolution
// ============================================================================

bool MediatorImpl::HandleResourceResolutionOperation(uint64_t client_id,
                                                     uint64_t session_id,
                                                     const control_plane::SingleOperationRequest& operation,
                                                     control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    if (operation.parameters.empty())
    {
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    // param[0]: resource name (String)
    const auto* name_param = std::get_if<std::string_view>(&operation.parameters[0]);
    if (!name_param)
    {
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }
    const std::string resource_name{*name_param};

    // param[1]: ResourceType cast to uint64. Defaults to kKeySlot for
    // backward compatibility when the client omits the type parameter.
    auto resource_type = score::crypto::ResourceType::kKeySlot;
    if (operation.parameters.size() > 1U)
    {
        if (const auto* type_param = std::get_if<std::uint64_t>(&operation.parameters[1]))
        {
            resource_type = static_cast<score::crypto::ResourceType>(static_cast<uint8_t>(*type_param));
        }
    }

    const auto resolver = m_resource_resolvers->Find(resource_type);
    if (!resolver)
    {
        score::mw::log::LogError() << "[SCORE_API_MED] RESOLVE_RESOURCE: no resolver registered for ResourceType="
                                   << static_cast<unsigned>(resource_type);
        responseBuilder.operation(operation.operationId)
            .return_error(score::crypto::CryptoErrorCode::kUnsupportedOperation);
        return false;
    }

    return resolver->Resolve(client_id, session_id, resource_name, operation.operationId, responseBuilder);
}

}  // namespace score::crypto::daemon::mediator
