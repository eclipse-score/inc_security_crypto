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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_I_CERT_PATH_VALIDATOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_I_CERT_PATH_VALIDATOR_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace score::crypto::daemon::cert_management
{
class CertObject;
struct CrlData;
}  // namespace score::crypto::daemon::cert_management

namespace score::crypto::daemon::provider::cert_management
{

/// @brief Provider-neutral input to one path validation.
///
/// Cert management resolves every certificate, trust anchor, and CRL before the call. The validator receives values
/// only. It holds no trust-store, data-node, or slot reference.
struct PathValidationRequest
{
    /// Certificate whose path is validated.
    std::shared_ptr<score::crypto::daemon::cert_management::CertObject> leaf;
    /// Presented intermediates: the supplied chain and the additional certificates, leaf excluded.
    std::vector<std::shared_ptr<score::crypto::daemon::cert_management::CertObject>> untrusted;
    /// Trust anchors for the check. Never empty for a request that reaches the validator.
    std::vector<std::shared_ptr<score::crypto::daemon::cert_management::CertObject>> trust_anchors;
    /// CRLs available to the check. Entries are non-null.
    std::vector<std::shared_ptr<const score::crypto::daemon::cert_management::CrlData>> crls;
    /// Where the chain may terminate. Standalone verification against ephemeral anchors uses
    /// kTrustStoreTerminated, so the chain ends at the provided anchor.
    score::crypto::ChainTerminationPolicy chain_termination{score::crypto::ChainTerminationPolicy::kRootRequired};
    /// Revocation sources to consult.
    score::crypto::RevocationCheckPolicy revocation_check{score::crypto::RevocationCheckPolicy::kNone};
    /// Behavior when the selected sources lack fresh evidence.
    score::crypto::RevocationCoveragePolicy revocation_coverage{score::crypto::RevocationCoveragePolicy::kFailClosed};
    /// Verification time in epoch seconds. Empty means the current time.
    std::optional<int64_t> verification_time_epoch_s;
};

/// @brief Outcome of one path validation.
struct PathValidationResult
{
    /// Verification verdict, set on every return path of the validator. A failed verdict is a result, not an error.
    score::crypto::CertVerifyResult result{score::crypto::CertVerifyResult::kValid};
    /// Established chain, leaf first. Empty unless @c result is kValid.
    std::vector<std::shared_ptr<score::crypto::daemon::cert_management::CertObject>> chain;
    /// Metadata of the CRLs the validator used for revocation checks, in the order it used them.
    std::vector<score::crypto::CrlMetadata> selected_crl_metadata;
};

/// @brief Provider capability that performs X.509 path validation.
///
/// The validator parses nothing, reads no trust store, and keeps no cert-management state. It is the only
/// verification step a provider contributes. Each verification context takes its validator from the provider that its
/// provider preference selects.
///
/// Each call to a provider's GetCertPathValidator() returns a new instance that the caller owns. An instance may keep
/// state for the context that owns it. It must not be used after the provider that created it has shut down.
class ICertPathValidator
{
  public:
    ICertPathValidator() = default;
    virtual ~ICertPathValidator() = default;

    ICertPathValidator(const ICertPathValidator&) = delete;
    ICertPathValidator& operator=(const ICertPathValidator&) = delete;
    ICertPathValidator(ICertPathValidator&&) = delete;
    ICertPathValidator& operator=(ICertPathValidator&&) = delete;

    /// @brief Validate the path described by @p request.
    /// @return The verdict and, for kValid, the chain. An error only for an infrastructure failure.
    [[nodiscard]] virtual score::crypto::Expected<PathValidationResult, common::DaemonErrorCode> Validate(
        const PathValidationRequest& request) = 0;
};

}  // namespace score::crypto::daemon::provider::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_I_CERT_PATH_VALIDATOR_HPP
