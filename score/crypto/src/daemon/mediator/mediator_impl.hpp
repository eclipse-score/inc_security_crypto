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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_SRC_MEDIATOR_IMPL_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_SRC_MEDIATOR_IMPL_HPP

#include "score/crypto/src/daemon/mediator/i_mediator.hpp"

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"

#include "score/crypto/src/daemon/common/context/context_data_node.hpp"
#include "score/crypto/src/daemon/common/context/i_handler.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/src/daemon/data_manager/data_node_accessor.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace score::crypto::daemon::mediator
{

/**
 * @brief Request data passed to the shared crypto-operation execution helper.
 */
struct OperationExecutionContext
{
    common::OperationIdentifier operationId;  ///< Operation identifier
    std::uint64_t context_id;                 ///< Context ID for logging/tracking
    common::RequestParameters& parameters;    ///< Parameters from the request
};

/// @brief Routes control-plane operations to mediator handlers or provider contexts.
class MediatorImpl : public IMediator
{
  public:
    /// @brief Construct a mediator from its subsystem dependencies.
    /// @param deps Dependencies used to resolve resources, providers, and handlers.
    explicit MediatorImpl(MediatorDependencies deps);

    /// @brief Copy construction is disabled.
    MediatorImpl(const MediatorImpl&) = delete;
    /// @brief Copy assignment is disabled.
    MediatorImpl& operator=(const MediatorImpl&) = delete;

    /// @brief Move-construct a mediator.
    MediatorImpl(MediatorImpl&&) = default;
    /// @brief Move-assign a mediator.
    MediatorImpl& operator=(MediatorImpl&&) = default;

    /// @brief Destroy the mediator and its owned state.
    ~MediatorImpl() override = default;

    /// @brief Process the operations in a control-plane request in order.
    ///
    /// Processing stops after the first operation that cannot be handled.
    /// @param request Request whose operations are dispatched.
    /// @return Response containing the results accumulated before processing stopped.
    score::crypto::daemon::control_plane::ControlResponse processRequest(
        score::crypto::daemon::control_plane::ControlRequest& request) override;

  private:
    /// @brief Select a provider, assemble a context, and add its identifier to the response.
    /// @param request Control-plane request containing the client and connection identifiers.
    /// @param operation CTX_CREATE operation to decode and execute.
    /// @param responseBuilder Builder receiving the operation result.
    /// @return True if the context was created successfully.
    bool HandleContextCreationOperation(
        const score::crypto::daemon::control_plane::ControlRequest& request,
        const control_plane::SingleOperationRequest& operation,
        score::crypto::daemon::control_plane::protocol::OperationResponseBuilder& responseBuilder);

    /// @brief Create a context through the factory registered for its context type.
    ///
    /// A context created this way is not bound to a provider. A request that references a key is
    /// refused before the factory is called.
    /// @param request Control-plane request containing the client and connection identifiers.
    /// @param operation CTX_CREATE operation the request was decoded from.
    /// @param decoded Validated CTX_CREATE request.
    /// @param factory Factory registered for the request's context type.
    /// @param responseBuilder Builder receiving the context identifier or an error.
    /// @return True if the context was created successfully.
    bool CreateContextFromFactory(const control_plane::ControlRequest& request,
                                  const control_plane::SingleOperationRequest& operation,
                                  const common::ContextCreationRequest& decoded,
                                  common::IContextFactory& factory,
                                  control_plane::protocol::OperationResponseBuilder& responseBuilder);

    /// @brief Execute a provider handler and append its result to the response.
    /// @param exec_ctx Operation identifier, context identifier, and request parameters.
    /// @param handler Handler that executes the operation.
    /// @param responseBuilder Builder receiving the operation result.
    /// @return True if execution succeeded.
    bool ExecuteOperation(const OperationExecutionContext& exec_ctx,
                          const std::shared_ptr<score::crypto::daemon::common::Handler>& handler,
                          score::crypto::daemon::control_plane::protocol::OperationResponseBuilder& responseBuilder);

    /// @brief Shared node-deletion helper used by both CTX_CLOSE and SHM_DESTROY_OBJECT.
    ///
    /// Deletes @p node_id from the data manager and writes the response. Deletion is
    /// idempotent: a missing node means the desired end-state already holds and is
    /// reported as success (mirrors ConnectionHandler's connection-close handling).
    /// @param request Control-plane request identifying the client and, for CTX_CLOSE, the node.
    /// @param operation CTX_CLOSE or SHM_DESTROY_OBJECT operation to handle.
    /// @param responseBuilder Builder receiving the operation result.
    /// @return Always true; the caller can return the value directly.
    bool DeleteNodeAndRespond(
        const control_plane::ControlRequest& request,
        const control_plane::SingleOperationRequest& operation,
        score::crypto::daemon::control_plane::protocol::OperationResponseBuilder& responseBuilder);

    /// @brief Dispatch one operation to the mediator or forward it to a context handler.
    /// @param request Parent control-plane request.
    /// @param operation Operation to dispatch.
    /// @param responseBuilder Builder receiving the operation result.
    /// @return True if the operation was handled successfully.
    bool HandleSingleOperation(const control_plane::ControlRequest& request,
                               const control_plane::SingleOperationRequest& operation,
                               control_plane::protocol::OperationResponseBuilder& responseBuilder);

    /// @brief Resolve a session resource using the resolver registered for its type.
    /// @param client_id Client requesting the resource.
    /// @param session_id Session in which the resource is resolved.
    /// @param operation Resource-resolution operation containing the resource name and type.
    /// @param responseBuilder Builder receiving the resolved resource or an error.
    /// @return True if a resolver resolved the resource successfully.
    bool HandleResourceResolutionOperation(uint64_t client_id,
                                           uint64_t session_id,
                                           const control_plane::SingleOperationRequest& operation,
                                           control_plane::protocol::OperationResponseBuilder& responseBuilder);

    /// @brief Handle a mediator-owned control-plane operation.
    /// @param request Parent control-plane request.
    /// @param operation Mediator operation to handle.
    /// @param responseBuilder Builder receiving the operation result.
    /// @return True if the operation was handled successfully.
    bool HandleMediatorOperation(const control_plane::ControlRequest& request,
                                 const control_plane::SingleOperationRequest& operation,
                                 control_plane::protocol::OperationResponseBuilder& responseBuilder);

    /// @brief Create a shared-memory object and register its data node.
    /// @param request Parent control-plane request containing the client identity.
    /// @param operation SHM_SETUP operation with the object configuration.
    /// @param responseBuilder Builder receiving the object identifier or an error.
    /// @return True if the object was created successfully.
    bool HandleShmCreateObject(const control_plane::ControlRequest& request,
                               const control_plane::SingleOperationRequest& operation,
                               control_plane::protocol::OperationResponseBuilder& responseBuilder);

    /// @brief Find a context and forward a non-mediator operation to its handler.
    /// @param request Parent control-plane request identifying the client and context.
    /// @param operation Operation to forward.
    /// @param responseBuilder Builder receiving the handler result or an error.
    /// @return True if the handler executed the operation successfully.
    bool ForwardSingleOperation(const control_plane::ControlRequest& request,
                                const control_plane::SingleOperationRequest& operation,
                                control_plane::protocol::OperationResponseBuilder& responseBuilder);
};

}  // namespace score::crypto::daemon::mediator

#endif  // SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_SRC_MEDIATOR_IMPL_HPP
