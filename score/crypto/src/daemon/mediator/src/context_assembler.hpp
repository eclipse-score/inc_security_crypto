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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_CONTEXT_ASSEMBLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_CONTEXT_ASSEMBLER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/context/context_mode.hpp"
#include "score/crypto/src/daemon/common/context/i_handler.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace score::crypto::daemon::mediator
{

/// @brief Inputs for creating a context node and initializing its handler.
struct ContextAssemblyRequest final
{
    std::uint64_t client_id{0U};                      ///< Client that owns the context.
    std::uint64_t connection_id{0U};                  ///< Connection node under which to create the context.
    common::ProviderId provider_id{0U};               ///< Provider selected to own the context handler.
    std::optional<AlgorithmDescriptor> algorithm{};   ///< Resolved algorithm; none for a context bound to no algorithm.
    std::string_view context_type{};                  ///< Context type used for optional key authorization.
    std::optional<std::uint64_t> key_node_id{};       ///< Optional key or key-slot node to bind.
    std::optional<common::ContextMode> mode{};        ///< Optional operation mode used for key authorization.
    const common::RequestParameters& raw_parameters;  ///< Original CTX_CREATE parameters forwarded to the handler.
};

/// @brief Creates a context node under the connection, binds the optional key, and
/// initializes the handler.
///
/// Order: add node, bind key (if requested), initialize handler. A failure after the
/// node is added removes the node again before the error is returned.
class ContextAssembler final
{
  public:
    /// @brief Construct an assembler with the services used to create and initialize contexts.
    /// @param data_manager Creates and removes context nodes.
    /// @param km_service Service for key authorization and binding; may be null when no key is bound.
    ContextAssembler(data_manager::IDataManager::Sptr data_manager,
                     key_management::KeyManagementService::Sptr km_service) noexcept;

    /// @brief Create and initialize a context, rolling back its node if a later step fails.
    /// @param request Validated context data, including the original creation parameters.
    /// @param handler Provider handler to initialize for the new context.
    /// @return The new context node id, or the error to return to the client.
    [[nodiscard]] score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> Assemble(
        const ContextAssemblyRequest& request,
        const provider::handler::Handler::Sptr& handler) const;

  private:
    /// @brief Remove a partially assembled context node and log cleanup failures.
    /// @param client_id Client that owns the context node.
    /// @param context_node_id Node to remove.
    /// @param reason Operation that failed and triggered rollback.
    void RollbackContext(std::uint64_t client_id,
                         data_manager::DataNodeId context_node_id,
                         std::string_view reason) const;

    data_manager::IDataManager::Sptr m_data_manager;          ///< DataManager used for context-node lifecycle.
    key_management::KeyManagementService::Sptr m_km_service;  ///< Key service used for optional key binding.
};

}  // namespace score::crypto::daemon::mediator

#endif  // SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_CONTEXT_ASSEMBLER_HPP
