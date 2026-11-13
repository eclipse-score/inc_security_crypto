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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_EXECUTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_EXECUTOR_HPP

#include "score/crypto/src/daemon/cert_management/context/verification/session.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

#include <cstddef>
#include <cstdint>

namespace score::crypto::daemon::cert_management
{

/// @brief Executes CERT:VERIFICATION operations against the verification session of one context.
///
/// Each operation extracts its parameters, calls the matching session method, and builds the wire response. The
/// request layouts are documented per operation in the implementation. The executor holds no state.
class CertVerificationExecutor final
{
  public:
    /// @brief Execute one CERT:VERIFICATION operation.
    /// @param session Session of the context the operation is issued on.
    /// @param operation_id Actor and action codes. The actor must be the certificate verification actor.
    /// @param request Operation parameters. Output buffers are written in place.
    /// @return The response parameters, kUnsupportedOperation for an unknown action or actor,
    ///         kInsufficientParameters or kInvalidArgument for a malformed request, or the error of the session call.
    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        CertVerificationSession& session,
        const common::OperationIdentifier& operation_id,
        common::RequestParameters& request) const;

  private:
    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleSetLeaf(
        CertVerificationSession& session,
        const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleSetChain(
        CertVerificationSession& session,
        const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleSetTrustStore(CertVerificationSession& session, const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleSetTrusted(
        CertVerificationSession& session,
        const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleSetChainTerminationPolicy(CertVerificationSession& session, const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleSetUntrusted(CertVerificationSession& session, const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleSetVerificationTime(CertVerificationSession& session, const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleSetRevocationCheckPolicy(CertVerificationSession& session, const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleSetRevocationCoveragePolicy(CertVerificationSession& session, const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleSetEvidenceMode(CertVerificationSession& session, const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> HandleVerify(
        CertVerificationSession& session);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleGetVerifiedChainExportSize(CertVerificationSession& session, const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleExportVerifiedChain(CertVerificationSession& session, common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleGetVerifiedCertificateExportSize(CertVerificationSession& session, const common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleExportVerifiedCertificate(CertVerificationSession& session, common::RequestParameters& request);

    [[nodiscard]] static score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode>
    HandleGetSelectedCrlMetadata(CertVerificationSession& session, common::RequestParameters& request);
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_EXECUTOR_HPP
