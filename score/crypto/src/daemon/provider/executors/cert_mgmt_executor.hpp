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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_CERT_MGMT_EXECUTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_CERT_MGMT_EXECUTOR_HPP

#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"
#include "score/crypto/src/daemon/provider/executors/cert_mgmt_context.hpp"

#include <memory>

namespace score::crypto::daemon::provider::crypto_executor
{

/// Stateless executor for CERT:MANAGEMENT context operations.
///
/// Owns references to the shared ICertParser (for CERT_PARSE / CERT_PARSE_CHAIN)
/// and the CertManagementService (for all slot / registry / read-only trust-store
/// operations). Trust-store membership mutations live in TrustStoreManagementExecutor
/// (CERT:TRUST_STORE context); trust-store info queries are served entirely by
/// the mediator-level GET_TRUST_STORE_OBJECT op (no round-trip through this
/// executor).
/// Per-context identity is passed through CertMgmtExecutionContext.
class CertManagementExecutor final
{
  public:
    CertManagementExecutor(cert_management::ICertParser::Sptr cert_parser,
                           std::shared_ptr<::score::crypto::daemon::cert_management::CertManagementService> service);
    ~CertManagementExecutor() = default;

    CertManagementExecutor(const CertManagementExecutor&) = delete;
    CertManagementExecutor& operator=(const CertManagementExecutor&) = delete;
    CertManagementExecutor(CertManagementExecutor&&) = delete;
    CertManagementExecutor& operator=(CertManagementExecutor&&) = delete;

    [[nodiscard]] Expected<common::ResponseParameters, daemon::common::DaemonErrorCode> Execute(
        const CertMgmtExecutionContext& ctx,
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request);

  private:
    using Error = daemon::common::DaemonErrorCode;

    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleParse(const CertMgmtExecutionContext& ctx,
                                                                          common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleParseChain(const CertMgmtExecutionContext& ctx,
                                                                               common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleLoad(const CertMgmtExecutionContext& ctx,
                                                                         common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleSave(const CertMgmtExecutionContext& ctx,
                                                                         common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleExport(const CertMgmtExecutionContext& ctx,
                                                                           common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleGetExportSize(const CertMgmtExecutionContext& ctx,
                                                                                  common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleClear(const CertMgmtExecutionContext& ctx,
                                                                          common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleRelease(const CertMgmtExecutionContext& ctx,
                                                                            common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleCrlImport(
        const CertMgmtExecutionContext& ctx,
        const common::OperationIdentifier& operation_id,
        common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleCrlDelete(const CertMgmtExecutionContext& ctx,
                                                                              common::RequestParameters& request);
    // Trust-store mutation handlers (add/remove/enable/disable/ack-update/import-CRL-for-member)
    // and trust-store info queries are handled by TrustStoreManagementExecutor and the
    // mediator's GET_TRUST_STORE_OBJECT op respectively (CERT:TRUST_STORE context).

    cert_management::ICertParser::Sptr m_cert_parser;
    std::shared_ptr<::score::crypto::daemon::cert_management::CertManagementService> m_service;
};

}  // namespace score::crypto::daemon::provider::crypto_executor

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_CERT_MGMT_EXECUTOR_HPP
