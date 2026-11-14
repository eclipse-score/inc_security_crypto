/*******************************************************************************
 *
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
 *******************************************************************************
 */

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_TRUST_STORE_EXECUTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_TRUST_STORE_EXECUTOR_HPP

#include "score/crypto/src/daemon/cert_management/context/cert_execution_context.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"

#include <cstdint>

namespace score::crypto::daemon::cert_management
{

/// @brief Executes CERT:TRUST_STORE operations: trust-store membership curation and the CRLs of exclusive members.
///
/// Each operation resolves the caller's data nodes through the service, performs the membership change through the
/// trust-store manager, and returns the wire response. Certificate lifecycle operations belong to
/// CertManagementExecutor. Operation codes outside the trust-store set are refused with kUnsupportedOperation.
///
/// The executor holds no mutable state. Execute() may be called concurrently; the synchronization of the operations
/// it reaches is documented on TrustStoreManager.
class TrustStoreManagementExecutor final
{
  public:
    /// @brief Construct the executor.
    /// @param cert_parser Parser used to validate CRLs imported for exclusive members. Must be non-null.
    /// @param service Certificate management service that owns the trust stores and slots. Must be non-null.
    TrustStoreManagementExecutor(provider::cert_management::ICertParser::Sptr cert_parser,
                                 CertManagementService::Sptr service);

    /// @brief Execute one CERT:TRUST_STORE operation.
    /// @param ctx Caller identity and context node for the operation.
    /// @param operation_id Actor and action codes of the operation.
    /// @param request Operation parameters, in the layout documented per operation in the implementation.
    /// @return The response parameters, or the error code of the failed step.
    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const CertExecutionContext& ctx,
        const common::OperationIdentifier& operation_id,
        common::RequestParameters& request) const;

  private:
    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleAddMember(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleRemoveMember(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleRemoveMemberById(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleEnableMember(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleDisableMember(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleAcknowledgeMemberUpdate(const CertExecutionContext& ctx, common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleImportCrlForMember(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleDeleteCrlForMember(
        const CertExecutionContext& ctx,
        common::RequestParameters& request) const;

    provider::cert_management::ICertParser::Sptr m_cert_parser;  ///< Validates imported member CRLs.
    CertManagementService::Sptr m_service;                       ///< Owns the trust stores, slots, and nodes.
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_TRUST_STORE_EXECUTOR_HPP
