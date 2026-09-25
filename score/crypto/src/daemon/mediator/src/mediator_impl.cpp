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

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/operation_names.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/src/daemon/data_manager/data_node_accessor.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/src/daemon/data_plane/src/shm_data_node.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/mediator/i_mediator.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/mediator/src/mediator_impl.hpp"
#include "score/crypto/src/daemon/provider/handler/context_data_node.hpp"
#include "score/crypto/src/daemon/provider/handler/i_crypto_handler_factory.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

namespace control_plane = score::crypto::daemon::control_plane;

using ControlRequest = control_plane::ControlRequest;
using ControlResponse = control_plane::ControlResponse;

namespace score::crypto::daemon::mediator
{

struct ProviderTypePreference
{
    common::CryptoProviderType primary{common::CryptoProviderType::DEFAULT};
    std::optional<common::CryptoProviderType> fallback{};
};

/// @brief Decode the stable public ProviderType wire values while retaining
///        preferred-provider fallback semantics.
static std::optional<ProviderTypePreference> DecodeProviderTypePreference(const std::uint8_t wire_value) noexcept
{
    switch (wire_value)
    {
        case 0:
            return ProviderTypePreference{common::CryptoProviderType::DEFAULT, std::nullopt};
        case 1:
            return ProviderTypePreference{common::CryptoProviderType::HARDWARE, std::nullopt};
        case 2:
            return ProviderTypePreference{common::CryptoProviderType::SOFTWARE, std::nullopt};
        case 3:
            return ProviderTypePreference{common::CryptoProviderType::HARDWARE, common::CryptoProviderType::SOFTWARE};
        case 4:
            return ProviderTypePreference{common::CryptoProviderType::SOFTWARE, common::CryptoProviderType::HARDWARE};
        default:
            return std::nullopt;
    }
}

static bool IsContextParameterPresent(const control_plane::SingleOperationRequest& operation,
                                      const std::size_t parameter_index) noexcept
{
    return (operation.parameters.size() > parameter_index) &&
           !std::holds_alternative<common::NoParam>(operation.parameters[parameter_index]);
}

/// @brief Validate the handler-specific portion of the generic CTX_CREATE layout.
///
/// Provider implementations receive the raw parameter vector, but the mediator
/// owns the stable wire schema and rejects malformed requests before selecting a
/// provider or creating a data node.
static bool IsContextCreationSchemaValid(const control_plane::SingleOperationRequest& operation,
                                         const std::string_view context_type) noexcept
{
    const bool has_key = IsContextParameterPresent(operation, operations::CTX_PARAM_KEY_NODE_ID);
    const bool has_operation_mode = IsContextParameterPresent(operation, operations::CTX_PARAM_OPERATION_MODE);

    if ((context_type == "HASH") || (context_type == "KEY_MANAGEMENT"))
    {
        return !has_key && !has_operation_mode;
    }

    if (context_type == "MAC")
    {
        if (!has_key || !has_operation_mode)
        {
            return false;
        }

        const auto key_node = operation.getParameter<std::uint64_t>(operations::CTX_PARAM_KEY_NODE_ID);
        const auto operation_mode = operation.getParameter<std::uint8_t>(operations::CTX_PARAM_OPERATION_MODE);
        return key_node.has_value() && (key_node.value() != 0U) && operation_mode.has_value() &&
               (operation_mode.value() <= static_cast<std::uint8_t>(score::crypto::OperationMode::kVerify));
    }

    // Unknown context types are rejected by provider factories. Their parameter
    // schemas remain unrestricted here so future context types stay extensible.
    return true;
}

MediatorImpl::MediatorImpl(MediatorDependencies deps) : IMediator(std::move(deps))
{
    RegisterResourceResolvers();
}

control_plane::ControlResponse MediatorImpl::processRequest(control_plane::ControlRequest& request)
{
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

    score::mw::log::LogVerbose() << "[SCORE_API_MED] Response operations: " << opResponse.operations.size();

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
        std::move(node_accessor_res).value().downCast<provider::handler::ContextDataNode>();
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

bool MediatorImpl::HandleContextCreationOperation(const score::crypto::daemon::control_plane::ControlRequest& request,
                                                  const control_plane::SingleOperationRequest& operation,
                                                  control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    if ((operation.parameters.size() < 2U) ||
        (operation.parameters.size() > (operations::CTX_PARAM_EXPLICIT_PROVIDER_ID + 1U)))
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Invalid CTX_CREATE parameter count";
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }
    auto context_type_res = operation.getParameter<std::string_view>(operations::CTX_PARAM_HANDLER_TYPE);
    if (!context_type_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Wrong parameter type for context_type";
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }
    auto context_type = context_type_res.value();

    auto algorithm_res = operation.getParameter<std::string_view>(operations::CTX_PARAM_ALGORITHM);
    if (!algorithm_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Wrong parameter type for algorithm";
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }
    auto algorithm = algorithm_res.value();

    if (!IsContextCreationSchemaValid(operation, context_type))
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Invalid CTX_CREATE schema for context type: "
                                   << context_type;
        responseBuilder.operation(operation.operationId).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
        return false;
    }

    ProviderTypePreference provider_preference{};
    if (operation.parameters.size() > operations::CTX_PARAM_PROVIDER_TYPE &&
        !std::holds_alternative<common::NoParam>(operation.parameters[operations::CTX_PARAM_PROVIDER_TYPE]))
    {
        const auto provider_type_res = operation.getParameter<std::uint8_t>(operations::CTX_PARAM_PROVIDER_TYPE);
        if (!provider_type_res.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Wrong parameter type for provider preference";
            responseBuilder.operation(operation.operationId)
                .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }

        const auto decoded_preference = DecodeProviderTypePreference(provider_type_res.value());
        if (!decoded_preference.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Unknown provider preference value: "
                                       << static_cast<unsigned int>(provider_type_res.value());
            responseBuilder.operation(operation.operationId)
                .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }
        provider_preference = decoded_preference.value();
    }

    // Read optional key_node_id parameter (param[3]) — for binding a key at context creation
    std::uint64_t key_node_id{0U};
    bool has_key_binding = false;
    if (operation.parameters.size() > operations::CTX_PARAM_KEY_NODE_ID &&
        !std::holds_alternative<common::NoParam>(operation.parameters[operations::CTX_PARAM_KEY_NODE_ID]))
    {
        const auto key_node_res = operation.getParameter<std::uint64_t>(operations::CTX_PARAM_KEY_NODE_ID);
        if (!key_node_res.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Wrong parameter type for key resource";
            responseBuilder.operation(operation.operationId)
                .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }
        key_node_id = key_node_res.value();
        has_key_binding = true;
    }

    std::optional<common::ProviderId> explicit_provider_id{};
    if (operation.parameters.size() > operations::CTX_PARAM_EXPLICIT_PROVIDER_ID &&
        !std::holds_alternative<common::NoParam>(operation.parameters[operations::CTX_PARAM_EXPLICIT_PROVIDER_ID]))
    {
        const auto provider_id_res = operation.getParameter<std::uint16_t>(operations::CTX_PARAM_EXPLICIT_PROVIDER_ID);
        if (!provider_id_res.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Wrong parameter type for explicit provider";
            responseBuilder.operation(operation.operationId)
                .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }
        explicit_provider_id = provider_id_res.value();
    }

    const auto resolve_provider_by_type = [&](const common::CryptoProviderType provider_type) {
        if (m_km_service && has_key_binding)
        {
            const auto resolved_id_res = m_km_service->ResolveTargetProvider(
                request.client_id, provider_type, std::optional<data_manager::DataNodeId>{key_node_id});
            return resolved_id_res.has_value() ? m_provider_manager->GetProvider(resolved_id_res.value())
                                               : std::shared_ptr<provider::IProvider>{};
        }
        return m_provider_manager->GetProvider(provider_type);
    };

    // --- Resolve target provider. Explicit selection takes precedence, followed
    //     by key affinity and finally provider-type preference. ---
    std::shared_ptr<provider::IProvider> provider;
    bool used_fallback = false;
    if (explicit_provider_id.has_value())
    {
        provider = m_provider_manager->GetProvider(explicit_provider_id.value());
    }
    else
    {
        provider = resolve_provider_by_type(provider_preference.primary);
        if (!provider && provider_preference.fallback.has_value())
        {
            provider = resolve_provider_by_type(provider_preference.fallback.value());
            used_fallback = static_cast<bool>(provider);
        }
    }
    if (!provider)
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - No providers available for requested preference";
        responseBuilder.operation(operation.operationId)
            .return_error(score::crypto::CryptoErrorCode::kProviderNotAvailable);
        return false;
    }

    const auto create_handler =
        [&](const std::shared_ptr<provider::IProvider>& candidate) -> score::Result<provider::handler::Handler::Sptr> {
        const auto crypto_ops = candidate->GetCryptoHandlerFactory();
        if (!crypto_ops)
        {
            return score::Result<provider::handler::Handler::Sptr>{
                score::unexpect,
                MakeError(score::crypto::CryptoErrorCode::kUnsupportedOperation,
                          "Crypto operations not available for provider")};
        }
        return crypto_ops->CreateHandler(std::string(context_type), std::string(algorithm));
    };

    auto create_result = create_handler(provider);
    const auto may_fallback_after_creation_error = [&create_result]() {
        if (create_result.has_value())
        {
            return false;
        }
        const auto error_code = *create_result.error();
        return (error_code == static_cast<score::result::ErrorCode>(CryptoErrorCode::kUnsupportedOperation)) ||
               (error_code == static_cast<score::result::ErrorCode>(CryptoErrorCode::kUnsupportedAlgorithm));
    };
    if (may_fallback_after_creation_error() && !explicit_provider_id.has_value() && !used_fallback &&
        provider_preference.fallback.has_value())
    {
        const auto fallback_provider = resolve_provider_by_type(provider_preference.fallback.value());
        if (fallback_provider && (fallback_provider->GetProviderId() != provider->GetProviderId()))
        {
            provider = fallback_provider;
            create_result = create_handler(fallback_provider);
            used_fallback = create_result.has_value();
        }
    }
    if (!create_result.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Handler or algorithm not supported:" << context_type
                                   << "/" << algorithm;
        responseBuilder.operation(operation.operationId).return_error(create_result.error());
        return false;
    }

    auto handler = create_result.value();

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
                .return_error(score::crypto::CryptoErrorCode::kUnsupportedOperation);
            return false;
        }

        auto bind_res =
            m_km_service->BindKeyToContext(client_id, context_node_id, key_node_id, provider->GetProviderId());
        if (!bind_res.has_value())
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - key binding failed for key_node_id=" << key_node_id;
            m_data_manager->deleteNode(client_id, context_node_id);
            responseBuilder.operation(operation.operationId)
                .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
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
        responseBuilder.operation(operation.operationId).return_error(init_result.error());
        return false;
    }

    std::string_view provider_selection{" (type-based selection)"};
    if (explicit_provider_id.has_value())
    {
        provider_selection = " (explicit selection)";
    }
    else if (used_fallback)
    {
        provider_selection = " (preferred-provider fallback)";
    }
    else if (has_key_binding)
    {
        provider_selection = " (key-affinity resolved)";
    }
    score::mw::log::LogVerbose() << "[SCORE_API_MED] CTX_CREATE [" << context_type << "/" << algorithm
                                 << "] selected provider: name='" << provider->GetProviderName()
                                 << "' id=" << provider->GetProviderId() << provider_selection
                                 << ", context_id=" << context_node_id;

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

        if (id_hint.has_value() &&
            (id_hint.value() > static_cast<std::uint64_t>(std::numeric_limits<common::ProviderId>::max())))
        {
            score::mw::log::LogError() << "[SCORE_API_MED] [SHM_SETUP_FAILED] Provider ID hint is out of range";
            responseBuilder.operation(operation.operationId)
                .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }

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

            const auto preference = DecodeProviderTypePreference(static_cast<std::uint8_t>(type_hint.value()));
            if (!preference.has_value())
            {
                score::mw::log::LogError() << "[SCORE_API_MED] [SHM_SETUP_FAILED] Unknown provider type hint";
                responseBuilder.operation(operation.operationId)
                    .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
                return false;
            }

            provider = m_provider_manager->GetProvider(preference->primary);
            if (!provider && preference->fallback.has_value())
            {
                provider = m_provider_manager->GetProvider(preference->fallback.value());
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
// Key Management Operation Handling
// ============================================================================

void MediatorImpl::RegisterResourceResolvers()
{
    using RT = score::crypto::ResourceType;

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
            responseBuilder.operation(op_id).return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }

        auto node_id_result = m_km_service->ResolveKeySlot(resource_name, client_id);
        if (!node_id_result.has_value())
        {
            responseBuilder.operation(op_id).return_error(score::crypto::CryptoErrorCode::kInternalError);
            return false;
        }

        // The slot API does not yet expose its owning provider. Return the
        // reserved unbound sentinel rather than provider zero, which is valid.
        responseBuilder.operation(op_id)
            .return_value_uint64(static_cast<uint64_t>(node_id_result.value()))
            .return_value_uint8(static_cast<uint8_t>(RT::kKeySlot))
            .return_value_bool(true)  // KeySlots are always persistent
            .return_value_uint16(common::kInvalidProviderId)
            .return_success();
        return true;
    };

    // --- kProvider ----------------------------------------------------------
    // Provider resources are process-wide and do not require a DataNode. The
    // numeric provider ID is returned both as the opaque resource ID and as
    // primary_provider so BaseContextConfig::SetProvider() can route CTX_CREATE.
    m_resource_resolvers[static_cast<uint8_t>(RT::kProvider)] =
        [this](uint64_t /*client_id*/,
               uint64_t /*session_id*/,
               const std::string& resource_name,
               const common::OperationIdentifier& op_id,
               control_plane::protocol::OperationResponseBuilder& responseBuilder) -> bool {
        const auto provider = m_provider_manager->GetProvider(resource_name);
        if (!provider)
        {
            responseBuilder.operation(op_id).return_error(score::crypto::CryptoErrorCode::kProviderNotAvailable);
            return false;
        }

        const auto provider_id = provider->GetProviderId();
        responseBuilder.operation(op_id)
            .return_value_uint64(static_cast<std::uint64_t>(provider_id))
            .return_value_uint8(static_cast<std::uint8_t>(RT::kProvider))
            .return_value_bool(true)
            .return_value_uint16(provider_id)
            .return_success();
        return true;
    };

    // Additional resource types (kCertSlot, kTrustAnchor, …) are registered
    // here as those subsystems are implemented.
}

bool MediatorImpl::HandleResourceResolutionOperation(uint64_t client_id,
                                                     uint64_t session_id,
                                                     const control_plane::SingleOperationRequest& operation,
                                                     control_plane::protocol::OperationResponseBuilder& responseBuilder)
{
    if (operation.parameters.empty() || (operation.parameters.size() > 2U))
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

    // param[1]: ResourceType encoded as uint8. Defaults to kKeySlot for
    // backward compatibility when the client omits the type parameter.
    auto resource_type = score::crypto::ResourceType::kKeySlot;
    if (operation.parameters.size() > 1U)
    {
        const auto type_result = operation.getParameter<std::uint8_t>(1U);
        if (!type_result.has_value() ||
            (type_result.value() > static_cast<std::uint8_t>(score::crypto::ResourceType::kDataObject)))
        {
            responseBuilder.operation(operation.operationId)
                .return_error(score::crypto::CryptoErrorCode::kInvalidArgument);
            return false;
        }
        resource_type = static_cast<score::crypto::ResourceType>(type_result.value());
    }

    const auto key = static_cast<uint8_t>(resource_type);
    const auto it = m_resource_resolvers.find(key);
    if (it == m_resource_resolvers.end())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] RESOLVE_RESOURCE: no resolver registered for ResourceType="
                                   << static_cast<unsigned>(key);
        responseBuilder.operation(operation.operationId)
            .return_error(score::crypto::CryptoErrorCode::kUnsupportedOperation);
        return false;
    }

    return it->second(client_id, session_id, resource_name, operation.operationId, responseBuilder);
}

}  // namespace score::crypto::daemon::mediator
