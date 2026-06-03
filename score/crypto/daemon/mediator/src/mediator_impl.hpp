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

#ifndef SCORE_CRYPTO_DAEMON_MEDIATOR_IMPL_HPP_
#define SCORE_CRYPTO_DAEMON_MEDIATOR_IMPL_HPP_

#include "score/crypto/daemon/mediator/i_mediator.hpp"

#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/config/inc/config.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/daemon/data_manager/data_node_accessor.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/daemon/provider/handler/context_data_node.hpp"
#include "score/crypto/daemon/provider/handler/i_handler.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace score::crypto::daemon::mediator
{

/**
 * @brief Struct to hold context for executing a crypto operation, used to pass information
 */
struct OperationExecutionContext
{
    common::OperationIdentifier operationId;  ///< Operation identifier
    std::uint64_t context_id;                 ///< Context ID for logging/tracking
    common::RequestParameters& parameters;    ///< Parameters from the request
};

class MediatorImpl : public IMediator
{
  public:
    MediatorImpl(data_manager::IDataManager::Sptr data_manager,
                 provider::ProviderManager::Sptr provider_manager,
                 const config::Config& config,
                 key_management::KeyManagementService::Sptr km_service = nullptr);

    MediatorImpl(const MediatorImpl&) = delete;
    MediatorImpl& operator=(const MediatorImpl&) = delete;

    MediatorImpl(MediatorImpl&&) = default;
    MediatorImpl& operator=(MediatorImpl&&) = default;

    ~MediatorImpl() override = default;
    score::crypto::daemon::control_plane::ControlResponse processRequest(
        const score::crypto::daemon::control_plane::ControlRequest& request) override;

  private:
    bool HandleContextCreationOperation(
        const score::crypto::daemon::control_plane::ControlRequest& request,
        const control_plane::SingleOperationRequest& operation,
        score::crypto::daemon::control_plane::protocol::OperationResponseBuilder& responseBuilder);

    bool HandleContextCloseOperation(
        const score::crypto::daemon::control_plane::ControlRequest& request,
        const control_plane::SingleOperationRequest& operation,
        score::crypto::daemon::control_plane::protocol::OperationResponseBuilder& responseBuilder);

    // Private helpers
    // Shared operation execution helper - handles parameter extraction, execution, and response building
    bool ExecuteOperation(const OperationExecutionContext& exec_ctx,
                          const std::shared_ptr<score::crypto::daemon::provider::handler::Handler>& handler,
                          score::crypto::daemon::control_plane::protocol::OperationResponseBuilder& responseBuilder);

    bool HandleSingleOperation(const control_plane::ControlRequest& request,
                               const control_plane::SingleOperationRequest& operation,
                               control_plane::protocol::OperationResponseBuilder& responseBuilder);

    bool HandleResourceResolutionOperation(uint64_t client_id,
                                           uint64_t session_id,
                                           const control_plane::SingleOperationRequest& operation,
                                           control_plane::protocol::OperationResponseBuilder& responseBuilder);
    void RegisterResourceResolvers();

    /// Dispatch table for session-level resource resolution.
    /// Key: static_cast<uint8_t>(ResourceType). Populated once in RegisterResourceResolvers().
    /// Adding a new resource type: register one lambda here — no other code changes required.
    using ResourceResolverFn = std::function<bool(uint64_t client_id,
                                                  uint64_t session_id,
                                                  const std::string& resource_name,
                                                  const common::OperationIdentifier& op_id,
                                                  control_plane::protocol::OperationResponseBuilder& responseBuilder)>;
    std::unordered_map<uint8_t, ResourceResolverFn> m_resource_resolvers;

    bool HandleMediatorOperation(const control_plane::ControlRequest& request,
                                 const control_plane::SingleOperationRequest& operation,
                                 control_plane::protocol::OperationResponseBuilder& responseBuilder);
    bool ForwardSingleOperation(const control_plane::ControlRequest& request,
                                const control_plane::SingleOperationRequest& operation,
                                control_plane::protocol::OperationResponseBuilder& responseBuilder);
};

}  // namespace score::crypto::daemon::mediator

#endif  // SCORE_CRYPTO_DAEMON_MEDIATOR_IMPL_HPP_
