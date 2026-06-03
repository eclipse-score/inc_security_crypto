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
#include <cstddef>
#include <cstdint>

#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/common/operation_names.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/config/inc/config.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/daemon/data_manager/data_node_accessor.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/daemon/mediator/i_mediator.hpp"
#include "score/crypto/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/daemon/mediator/src/mediator_impl.hpp"
#include "score/crypto/daemon/provider/handler/context_data_node.hpp"
#include "score/crypto/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/crypto/daemon/provider/handler/i_handler.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"
#include "score/mw/crypto/api/common/error_domain.hpp"

namespace control_plane = score::crypto::daemon::control_plane;

using ControlRequest = control_plane::ControlRequest;
using ControlResponse = control_plane::ControlResponse;

namespace score::crypto::daemon::mediator
{

/// @brief Decode a ProviderType wire value (from the IPC protocol) into the
///        daemon-internal CryptoProviderType capability classification.
///
/// The wire encoding is the uint8_t value of the client-side mw::crypto::ProviderType
/// enumerator (0=kDefault, 1=kHardware, 2=kSoftware, 3=kHardwarePreferred, 4=kSoftwarePreferred).
/// kHardwarePreferred / kSoftwarePreferred are resolved to their primary type; the
/// daemon's ProviderManager::GetProvider() handles fallback to SOFTWARE/HARDWARE if
/// the preferred type is not registered.
static common::CryptoProviderType FromWireProviderType(std::uint8_t wire_value) noexcept
{
    // Wire values match mw::crypto::ProviderType enumerator positions:
    //   0=kDefault, 1=kHardware, 2=kSoftware, 3=kHardwarePreferred, 4=kSoftwarePreferred
    switch (wire_value)
    {
        case 1:
            return common::CryptoProviderType::HARDWARE;
        case 2:
            return common::CryptoProviderType::SOFTWARE;
        case 3:
            return common::CryptoProviderType::HARDWARE;
        case 4:
            return common::CryptoProviderType::SOFTWARE;
        default:
            return common::CryptoProviderType::DEFAULT;
    }
}

MediatorImpl::MediatorImpl(data_manager::IDataManager::Sptr data_manager,
                           provider::ProviderManager::Sptr provider_manager,
                           const config::Config& config,
                           key_management::KeyManagementService::Sptr km_service)
    : IMediator(std::move(data_manager), std::move(provider_manager), config, std::move(km_service))
{
    if (m_km_service)
    {
        RegisterResourceResolvers();
    }
}

control_plane::ControlResponse MediatorImpl::processRequest(const control_plane::ControlRequest& request)
{
    score::mw::log::LogDebug() << "[SCORE_API_MED] Processing request - "
                               << "RequestId:" << request.request_id << ", Client Id:" << request.client_id
                               << ", DataNodeId:" << request.data_node_id;
    auto responseBuilder = control_plane::protocol::OperationResponseBuilder();

    for (size_t idx = 0; idx < request.operation.operations.size(); ++idx)
    {
        const auto& operation = request.operation.operations[idx];

        // Stop processing requests, once one fails. They may depend on each other
        if (!HandleSingleOperation(request, operation, responseBuilder))
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR at operation index:" << idx;
            break;
        }
    }

    // Build response
    auto opResponse = responseBuilder.build().value_or(control_plane::protocol::OperationResponse());

    ControlResponse response;
    response.request_id = request.request_id;
    response.operation = opResponse;

    score::mw::log::LogDebug() << "[SCORE_API_MED] Response operations:" << opResponse.operations.size();

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
        auto success = HandleContextCloseOperation(request, operation, responseBuilder);
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
        responseBuilder.operation(operationIdentifier)
            .return_error(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    auto context_node_accessor_res =
        std::move(node_accessor_res).value().downCast<provider::handler::ContextDataNode>();
    if (!context_node_accessor_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Context node for context_id:" << context_id
                                   << " is not a ContextDataNode";
        responseBuilder.operation(operationIdentifier)
            .return_error(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }
    auto context_node_accessor = std::move(context_node_accessor_res).value();

    auto handler = context_node_accessor->GetHandler();
    if (!handler)
    {
        score::mw::log::LogError()
            << "[SCORE_API_MED] ERROR - Context node accessor does not contain a handler for context_id: "
            << context_id;
        responseBuilder.operation(operationIdentifier).return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
        return false;
    }

    score::mw::log::LogDebug() << "[SCORE_API_MED] Context found in data manager for context_id:" << context_id;

    // TODO: Once requests are non-const, we can drop the copy here.
    auto mutable_params = operation.parameters;

    // Build execution context
    const OperationExecutionContext exec_ctx{
        .operationId = operation.operationId, .context_id = context_id, .parameters = mutable_params};

    // Call handler with handler copy, not under lock
    return ExecuteOperation(exec_ctx, handler, responseBuilder);
}

bool MediatorImpl::HandleContextCreationOperation(const score::crypto::daemon::control_plane::ControlRequest& request,
                                                  const control_plane::SingleOperationRequest& operation,
                                                  control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    score::mw::log::LogDebug() << "[SCORE_API_MED] Creating context node";

    if (operation.parameters.size() < 2)
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Not enough parameters for request";
        responseBuilder.operation(operation.operationId)
            .return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
        return false;
    }
    auto context_type_res = operation.getParameter<std::string_view>(0);
    if (!context_type_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Wrong parameter type for context_type";
        responseBuilder.operation(operation.operationId)
            .return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
        return false;
    }
    auto context_type = context_type_res.value();

    auto algorithm_res = operation.getParameter<std::string_view>(1);
    if (!algorithm_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Wrong parameter type for algorithm";
        responseBuilder.operation(operation.operationId)
            .return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
        return false;
    }
    auto algorithm = algorithm_res.value();

    // Read optional provider type parameter (param[2])
    // Default to DEFAULT provider type if not specified or invalid
    common::CryptoProviderType requested_provider_type = common::CryptoProviderType::DEFAULT;
    if (operation.parameters.size() >= 3)
    {
        auto provider_type_res = operation.getParameter<std::uint8_t>(2);
        if (provider_type_res.has_value())
        {
            requested_provider_type = FromWireProviderType(provider_type_res.value());
            score::mw::log::LogDebug() << "[SCORE_API_MED] Requested ProviderType: wire="
                                       << static_cast<int>(provider_type_res.value())
                                       << " resolved_daemon_type=" << static_cast<int>(requested_provider_type);
        }
    }

    // Read optional key_node_id parameter (param[3]) — for binding a key at context creation
    std::uint64_t key_node_id{0U};
    bool has_key_binding = false;
    if (operation.parameters.size() >= 4)
    {
        auto key_node_res = operation.getParameter<std::uint64_t>(3);
        if (key_node_res.has_value())
        {
            key_node_id = key_node_res.value();
            has_key_binding = true;
        }
    }

    // --- Resolve target provider (considers key/slot affinity when available) ---
    std::shared_ptr<provider::IProvider> provider;
    if (m_km_service && has_key_binding)
    {
        auto resolved_id_res = m_km_service->ResolveTargetProvider(
            request.client_id, requested_provider_type, std::optional<data_manager::DataNodeId>{key_node_id});
        if (!resolved_id_res.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Provider resolution failed for keyed context"
                                       << " (key_node_id=" << key_node_id << ")";
            responseBuilder.operation(operation.operationId)
                .return_error(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }
        score::mw::log::LogDebug() << "[SCORE_API_MED] CTX_CREATE [" << context_type << "/" << algorithm
                                   << "] resolved provider via key affinity (key_node_id=" << key_node_id
                                   << "): provider_id=" << resolved_id_res.value();
        provider = m_provider_manager->GetProvider(resolved_id_res.value());
    }
    else
    {
        provider = m_provider_manager->GetProvider(requested_provider_type);
    }
    if (!provider)
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - No providers available for type: "
                                   << static_cast<int>(requested_provider_type);
        responseBuilder.operation(operation.operationId)
            .return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
        return false;
    }
    score::mw::log::LogDebug() << "[SCORE_API_MED] CTX_CREATE [" << context_type << "/" << algorithm
                               << "] selected provider: name='" << provider->GetProviderName()
                               << "' id=" << provider->GetProviderId()
                               << (has_key_binding ? " (key-affinity resolved)" : " (type-based selection)");

    auto crypto_ops = provider->GetCryptoHandlerFactory();
    if (crypto_ops == nullptr)
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Crypto operations not available";
        responseBuilder.operation(operation.operationId)
            .return_error(score::mw::crypto::CryptoErrorCode::kUnsupportedOperation);
        return false;
    }

    auto create_result = crypto_ops->CreateHandler(std::string(context_type), std::string(algorithm));
    if (!create_result.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Handler or algorithm not supported:" << context_type
                                   << "/" << algorithm;
        responseBuilder.operation(operation.operationId)
            .return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
        return false;
    }

    auto handler = create_result.value();
    score::mw::log::LogDebug() << "[SCORE_API_MED] Created handler pointer:" << handler.get();

    // --- Create the context node FIRST so we have its node-id for InitializationParams ---
    auto client_id = request.client_id;
    auto connection_id = request.data_node_id;
    auto context_node = std::make_shared<provider::handler::ContextDataNode>(handler, std::string(algorithm));

    auto context_id_res = m_data_manager->addChildNode(client_id, connection_id, context_node);
    if (!context_id_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] Adding Context to DataNodeManager failed";
        responseBuilder.operation(operation.operationId).return_error(context_id_res.error());
        return false;
    }
    auto context_node_id = context_id_res.value();

    // --- Optional key binding: resolve key and bind to context node ---
    key_management::IKeyHandler::Sptr bound_key_handler;
    if (has_key_binding)
    {
        if (!m_km_service)
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - key binding requires key management service";
            m_data_manager->deleteNode(client_id, context_node_id);
            responseBuilder.operation(operation.operationId)
                .return_error(score::mw::crypto::CryptoErrorCode::kUnsupportedOperation);
            return false;
        }

        auto bind_res =
            m_km_service->BindKeyToContext(client_id, context_node_id, key_node_id, provider->GetProviderId());
        if (!bind_res.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - key binding failed for key_node_id=" << key_node_id;
            m_data_manager->deleteNode(client_id, context_node_id);
            responseBuilder.operation(operation.operationId)
                .return_error(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }

        key_node_id = static_cast<std::uint64_t>(bind_res.value().resolved_node_id);
        bound_key_handler = bind_res.value().key_handler;
    }

    // --- Build InitializationParams and initialize the handler ---
    provider::handler::InitializationParams init_params{};
    init_params.client_id = client_id;
    init_params.context_node_id = context_node_id;
    init_params.provider_id = provider->GetProviderId();
    init_params.key_node_id = key_node_id;
    init_params.bound_key_handler = bound_key_handler.get();

    // Pass raw CTX_CREATE parameters so handlers can extract extended fields
    // (e.g. MAC handlers read operation_mode from param[4]).
    init_params.context_creation_params = operation.parameters;

    auto init_result = handler->InitializeContext(init_params);
    if (!init_result.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Handler initialization failed for context with error: "
                                   << static_cast<int>(init_result.error());
        m_data_manager->deleteNode(client_id, context_node_id);
        responseBuilder.operation(operation.operationId)
            .return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
        return false;
    }

    score::mw::log::LogDebug() << "[SCORE_API_MED] Context node created for context_id:" << context_node_id;

    // Return context_id in response (no return_result for CTX_* operations)
    responseBuilder.operation(operation.operationId).return_success().return_value_uint64(context_node_id);
    return true;
}

// ============================================================================
// Shared Operation Execution Helper
// ============================================================================
bool MediatorImpl::ExecuteOperation(const OperationExecutionContext& exec_ctx,
                                    const std::shared_ptr<provider::handler::Handler>& handler,
                                    control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    // Execute operation
    score::mw::log::LogDebug() << "[SCORE_API_MED] Calling handler->Execute:" << common::OpId{exec_ctx.operationId};
    auto execute_result = handler->Execute(exec_ctx.operationId, exec_ctx.parameters);

    if (!execute_result.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Operation execution failed with error code: "
                                   << static_cast<int>(execute_result.error());
        responseBuilder.operation(exec_ctx.operationId).return_error(execute_result.error());
        return false;
    }

    // Build response
    score::mw::log::LogDebug() << "[SCORE_API_MED]" << common::OpId{exec_ctx.operationId} << " completed successfully";
    // Add all output parameters to response
    responseBuilder.return_crypto_operation_response(
        exec_ctx.operationId, control_plane::protocol::OPERATION_RESULT_SUCCESS, std::move(execute_result.value()));
    return true;
}

// ============================================================================
// Private Helper: Get Handler Configuration by Handler Type and Algorithm
// ============================================================================
bool MediatorImpl::HandleContextCloseOperation(
    const score::crypto::daemon::control_plane::ControlRequest& request,
    const control_plane::SingleOperationRequest& operation,
    score::crypto::daemon::control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    auto client_id = request.client_id;
    auto context_id = request.data_node_id;

    score::mw::log::LogDebug() << "[SCORE_API_MED] Closing context_id:" << context_id;

    // Remove context node from data manager
    const bool removed = m_data_manager->deleteNode(client_id, context_id).has_value();

    if (removed)
    {
        score::mw::log::LogDebug() << "[SCORE_API_MED] Context_id:" << context_id << " removed from data manager";
        responseBuilder.operation(operation.operationId).return_success();
        return true;
    }
    else
    {
        // Context not found - this is not necessarily an error
        score::mw::log::LogDebug() << "[SCORE_API_MED] WARNING - Context_id:" << context_id
                                   << " not found in data manager";
        responseBuilder.operation(operation.operationId).return_success();
        return true;
    }
}

// ============================================================================
// Key Management Operation Handling
// ============================================================================

void MediatorImpl::RegisterResourceResolvers()
{
    using RT = score::mw::crypto::ResourceType;

    // --- kKeySlot -----------------------------------------------------------
    // Resolves an application resource name to a session-scoped KeySlotDataNode
    // and returns its DataNodeId as an opaque handle to the client.
    // The DataNodeId is enforced per-session by the DataManager and does NOT
    // expose any internal SlotRegistry registry index to user space.
    m_resource_resolvers[static_cast<uint8_t>(RT::kKeySlot)] =
        [this](uint64_t client_id,
               uint64_t /*session_id*/,
               const std::string& resource_name,
               const common::OperationIdentifier& op_id,
               control_plane::protocol::OperationResponseBuilder& responseBuilder) -> bool {
        if (!m_km_service)
        {
            responseBuilder.operation(op_id).return_error(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }

        auto node_id_result = m_km_service->ResolveKeySlot(resource_name, client_id);
        if (!node_id_result.has_value())
        {
            responseBuilder.operation(op_id).return_error(score::mw::crypto::CryptoErrorCode::kInternalError);
            return false;
        }

        // TODO: How to get the primary provider ?
        // For now just return 0
        responseBuilder.operation(op_id)
            .return_value_uint64(static_cast<uint64_t>(node_id_result.value()))
            .return_value_uint8(static_cast<uint8_t>(RT::kKeySlot))
            .return_value_bool(true)  // KeySlots are always persistent
            .return_value_uint16(0)
            .return_success();
        return true;
    };

    // Additional resource types (kProvider, kCertSlot, kTrustAnchor, …) are
    // registered here as those subsystems are implemented. Each entry is
    // self-contained; no existing resolvers are modified.
}

bool MediatorImpl::HandleResourceResolutionOperation(uint64_t client_id,
                                                     uint64_t session_id,
                                                     const control_plane::SingleOperationRequest& operation,
                                                     control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    if (operation.parameters.empty())
    {
        responseBuilder.operation(operation.operationId)
            .return_error(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    // param[0]: resource name (String)
    const auto* name_param = std::get_if<std::string_view>(&operation.parameters[0]);
    if (!name_param)
    {
        responseBuilder.operation(operation.operationId)
            .return_error(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }
    const std::string resource_name{*name_param};

    // param[1]: ResourceType cast to uint64. Defaults to kKeySlot for
    // backward compatibility when the client omits the type parameter.
    auto resource_type = score::mw::crypto::ResourceType::kKeySlot;
    if (operation.parameters.size() > 1U)
    {
        if (const auto* type_param = std::get_if<std::uint64_t>(&operation.parameters[1]))
        {
            resource_type = static_cast<score::mw::crypto::ResourceType>(static_cast<uint8_t>(*type_param));
        }
    }

    const auto key = static_cast<uint8_t>(resource_type);
    const auto it = m_resource_resolvers.find(key);
    if (it == m_resource_resolvers.end())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] RESOLVE_RESOURCE: no resolver registered for ResourceType="
                                   << static_cast<unsigned>(key);
        responseBuilder.operation(operation.operationId)
            .return_error(score::mw::crypto::CryptoErrorCode::kUnsupportedOperation);
        return false;
    }

    return it->second(client_id, session_id, resource_name, operation.operationId, responseBuilder);
}

}  // namespace score::crypto::daemon::mediator
