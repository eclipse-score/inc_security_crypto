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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_TRUST_STORE_MGMT_EXECUTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_TRUST_STORE_MGMT_EXECUTOR_HPP

#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"
#include "score/crypto/src/daemon/provider/executors/cert_mgmt_context.hpp"

#include <memory>

namespace score::crypto::daemon::provider::crypto_executor
{

/// Stateless executor for CERT:TRUST_STORE context operations.
///
/// Trust-store membership curation is a separate client-facing capability from
/// certificate lifecycle management (see CertManagementExecutor), but shares the
/// same CertManagementService/TrustStoreManager backing and the existing
/// TRUST_STORE_* operation codes. Per-context identity is passed through
/// CertMgmtExecutionContext, identical to CertManagementExecutor.
class TrustStoreManagementExecutor final
{
  public:
    TrustStoreManagementExecutor(
        cert_management::ICertParser::Sptr cert_parser,
        std::shared_ptr<::score::crypto::daemon::cert_management::CertManagementService> service);
    ~TrustStoreManagementExecutor() = default;

    TrustStoreManagementExecutor(const TrustStoreManagementExecutor&) = delete;
    TrustStoreManagementExecutor& operator=(const TrustStoreManagementExecutor&) = delete;
    TrustStoreManagementExecutor(TrustStoreManagementExecutor&&) = delete;
    TrustStoreManagementExecutor& operator=(TrustStoreManagementExecutor&&) = delete;

    [[nodiscard]] Expected<common::ResponseParameters, daemon::common::DaemonErrorCode> Execute(
        const CertMgmtExecutionContext& ctx,
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request);

  private:
    using Error = daemon::common::DaemonErrorCode;

    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleTrustStoreAdd(const CertMgmtExecutionContext& ctx,
                                                                                  common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleTrustStoreRemove(
        const CertMgmtExecutionContext& ctx,
        common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleTrustStoreRemoveById(
        const CertMgmtExecutionContext& ctx,
        common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleTrustStoreEnable(
        const CertMgmtExecutionContext& ctx,
        common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleTrustStoreDisable(
        const CertMgmtExecutionContext& ctx,
        common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleTrustStoreAckUpdate(
        const CertMgmtExecutionContext& ctx,
        common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleTrustStoreImportCrlForMember(
        const CertMgmtExecutionContext& ctx,
        common::RequestParameters& request);
    [[nodiscard]] Expected<common::ResponseParameters, Error> HandleTrustStoreDeleteCrlForMember(
        const CertMgmtExecutionContext& ctx,
        common::RequestParameters& request);

    cert_management::ICertParser::Sptr m_cert_parser;
    std::shared_ptr<::score::crypto::daemon::cert_management::CertManagementService> m_service;
};

}  // namespace score::crypto::daemon::provider::crypto_executor

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXECUTORS_TRUST_STORE_MGMT_EXECUTOR_HPP
