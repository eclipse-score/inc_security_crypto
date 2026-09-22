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
#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CERT_VERIFICATION_CERT_VERIFICATION_EXECUTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CERT_VERIFICATION_CERT_VERIFICATION_EXECUTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::cert_verification
{

class ScoreCertVerificationHandler;

/// @brief Stateless executor implementing the strategy / visitor pattern for
///        CERT:VERIFICATION context operations under the score interface family.
///
/// Mirrors the MacExecutor pattern:
///   - Extracts IPC parameters from RequestParameters
///   - Routes operations to the typed ScoreCertVerificationHandler methods
///   - Packs results back into ResponseParameters
///
/// All state accumulation (leaf, chain, trust store, policy) lives in the
/// handler. The executor is stateless and shared across all score-family providers.
class CertVerificationExecutor
{
  public:
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        ScoreCertVerificationHandler& handler,
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request);

  private:
    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSetLeaf(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSetChain(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSetTrustStore(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSetTrusted(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSetPolicy(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSetAdditional(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSetVerificationTime(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSetRevocationPolicy(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSetEvidenceMode(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteVerify(
        ScoreCertVerificationHandler& handler);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode>
    ExecuteGetVerifiedChainExportSize(ScoreCertVerificationHandler& handler, common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteExportVerifiedChain(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode>
    ExecuteGetVerifiedCertificateExportSize(ScoreCertVerificationHandler& handler, common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteExportVerifiedCertificate(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteGetSelectedCrlMetadata(
        ScoreCertVerificationHandler& handler,
        common::RequestParameters& request);
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::cert_verification

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CERT_VERIFICATION_CERT_VERIFICATION_EXECUTOR_HPP
