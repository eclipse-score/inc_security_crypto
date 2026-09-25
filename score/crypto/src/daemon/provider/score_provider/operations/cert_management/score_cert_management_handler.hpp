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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CERT_MANAGEMENT_SCORE_CERT_MANAGEMENT_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CERT_MANAGEMENT_SCORE_CERT_MANAGEMENT_HANDLER_HPP

#include "score/crypto/src/daemon/provider/executors/cert_mgmt_context.hpp"
#include "score/crypto/src/daemon/provider/executors/cert_mgmt_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"

#include <memory>

namespace score::crypto::daemon::provider::score_provider::operations::cert_management
{

/// Handler for CERT:MANAGEMENT context operations.
///
/// Bridges the daemon's Handler interface to the stateless CertManagementExecutor.
/// Per-context identity is stored in m_ctx on InitializeContext() and passed to
/// the executor on every Execute() call.
class ScoreCertManagementHandler : public handler::Handler
{
  public:
    explicit ScoreCertManagementHandler(std::unique_ptr<crypto_executor::CertManagementExecutor> executor);

    ~ScoreCertManagementHandler() override = default;

    ScoreCertManagementHandler(const ScoreCertManagementHandler&) = delete;
    ScoreCertManagementHandler& operator=(const ScoreCertManagementHandler&) = delete;
    ScoreCertManagementHandler(ScoreCertManagementHandler&&) = delete;
    ScoreCertManagementHandler& operator=(ScoreCertManagementHandler&&) = delete;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request) override;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;

  private:
    std::unique_ptr<crypto_executor::CertManagementExecutor> m_executor;
    crypto_executor::CertMgmtExecutionContext m_ctx{};
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CERT_MANAGEMENT_SCORE_CERT_MANAGEMENT_HANDLER_HPP
