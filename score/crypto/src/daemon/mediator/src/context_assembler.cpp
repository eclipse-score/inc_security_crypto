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

#include "score/crypto/src/daemon/mediator/src/context_assembler.hpp"

#include "score/crypto/src/daemon/common/context/context_data_node.hpp"
#include "score/crypto/src/daemon/common/context/handler_init_params.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"

#include "score/mw/log/logging.h"

#include <memory>
#include <string>
#include <utility>

namespace score::crypto::daemon::mediator
{

ContextAssembler::ContextAssembler(data_manager::IDataManager::Sptr data_manager,
                                   key_management::KeyManagementService::Sptr km_service) noexcept
    : m_data_manager(std::move(data_manager)), m_km_service(std::move(km_service))
{
}

void ContextAssembler::RollbackContext(const std::uint64_t client_id,
                                       const data_manager::DataNodeId context_node_id,
                                       const std::string_view reason) const
{
    const auto cleanup_result = m_data_manager->deleteNode(client_id, context_node_id);
    if (!cleanup_result.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Failed to remove context after " << reason << ": "
                                   << static_cast<int>(cleanup_result.error());
    }
}

score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> ContextAssembler::Assemble(
    const ContextAssemblyRequest& request,
    const provider::handler::Handler::Sptr& handler) const
{
    auto context_node = std::make_shared<provider::handler::ContextDataNode>(handler, request.algorithm);

    auto context_id_res = m_data_manager->addChildNode(request.client_id, request.connection_id, context_node);
    if (!context_id_res.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] Adding Context to DataNodeManager failed";
        return score::crypto::make_unexpected(context_id_res.error());
    }
    const auto context_node_id = context_id_res.value();

    // Optional key binding: resolve key, bind to context node, authorize.
    const bool has_key_binding = request.key_node_id.has_value();
    key_management::IKeyHandler::Sptr bound_key_handler;
    std::uint64_t init_key_node_id{0U};
    if (has_key_binding)
    {
        if (!m_km_service)
        {
            score::mw::log::LogError() << "[SCORE_API_MED] ERROR - key binding requires key management service";
            RollbackContext(request.client_id, context_node_id, "key-binding failure");
            return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
        }

        key_management::KeyBindRequest bind_request{};
        bind_request.client_id = request.client_id;
        bind_request.context_node_id = context_node_id;
        bind_request.key_node_id = request.key_node_id.value();
        bind_request.provider_id = request.provider_id;
        bind_request.context_type = request.context_type;
        bind_request.mode = request.mode;
        bind_request.algorithm = request.algorithm;

        auto bind_res = m_km_service->BindAndAuthorize(bind_request);
        if (!bind_res.has_value())
        {
            RollbackContext(request.client_id, context_node_id, "key-binding failure");
            return score::crypto::make_unexpected(bind_res.error());
        }
        bound_key_handler = bind_res.value().key_handler;
        init_key_node_id = bind_res.value().resolved_node_id;
    }

    // Build InitializationParams and initialize the handler.
    provider::handler::InitializationParams init_params{};
    init_params.client_id = request.client_id;
    init_params.context_node_id = context_node_id;
    init_params.provider_id = request.provider_id;
    init_params.key_node_id = init_key_node_id;
    init_params.bound_key_handler = bound_key_handler.get();

    // Pass raw CTX_CREATE parameters so handlers can extract extended fields
    // (e.g. MAC handlers read operation_mode from param[4]).
    init_params.context_creation_params = request.raw_parameters;

    auto init_result = handler->InitializeContext(init_params);
    if (!init_result.has_value())
    {
        score::mw::log::LogError() << "[SCORE_API_MED] ERROR - Handler initialization failed for context with error: "
                                   << static_cast<int>(init_result.error());
        RollbackContext(request.client_id, context_node_id, "handler initialization failure");
        return score::crypto::make_unexpected(init_result.error());
    }

    return context_node_id;
}

}  // namespace score::crypto::daemon::mediator
