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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_KEY_MANAGEMENT_SCORE_KEY_MANAGEMENT_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_KEY_MANAGEMENT_SCORE_KEY_MANAGEMENT_HANDLER_HPP

#include "score/crypto/daemon/provider/executors/key_mgmt_context.hpp"
#include "score/crypto/daemon/provider/executors/key_mgmt_executor.hpp"
#include "score/crypto/daemon/provider/handler/i_handler.hpp"

#include <memory>

namespace score::crypto::daemon::provider::score_provider::operations::key_management
{

/// @brief Abstract base handler for key management operations under the score
///        interface family.
///
/// Acts as the bridge between the daemon dispatch interface (Handler) and the
/// shared KeyManagementExecutor. All collaborators are constructor-injected.
/// InitializeContext() stores the per-context runtime identity; Execute()
/// delegates to the executor.
class ScoreKeyManagementHandler : public handler::Handler
{
  public:
    explicit ScoreKeyManagementHandler(std::unique_ptr<crypto_executor::KeyManagementExecutor> executor);

    ~ScoreKeyManagementHandler() override = default;

    ScoreKeyManagementHandler(const ScoreKeyManagementHandler&) = delete;
    ScoreKeyManagementHandler& operator=(const ScoreKeyManagementHandler&) = delete;
    ScoreKeyManagementHandler(ScoreKeyManagementHandler&&) = delete;
    ScoreKeyManagementHandler& operator=(ScoreKeyManagementHandler&&) = delete;

    /// Stores the runtime context (client_id, context_node_id, provider_id).
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

    /// Delegates to KeyManagementExecutor::Execute.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request) override;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;

  protected:
    std::unique_ptr<crypto_executor::KeyManagementExecutor> m_executor;
    crypto_executor::KeyMgmtExecutionContext m_ctx;
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::key_management

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_KEY_MANAGEMENT_SCORE_KEY_MANAGEMENT_HANDLER_HPP
