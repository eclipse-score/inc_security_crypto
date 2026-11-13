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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_REQUEST_BUILDER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_REQUEST_BUILDER_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_path_validator.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// @brief Assembles the provider-neutral path validation request of one verification.
///
/// The builder reads the certificate values and CRLs that the session resolved, together with the trust store that
/// the session bound, and returns a request made of values only. It holds no provider object and no data-node
/// reference. Trust anchors and untrusted inputs are deduplicated by SHA-256 fingerprint. A certificate that is also a
/// trust anchor is never passed as untrusted, because the anchor copy takes precedence.
class VerificationRequestBuilder final
{
  public:
    /// @brief One certificate input, resolved when it was set on the session.
    struct Certificate
    {
        data_manager::DataNodeId node_id{0U};  ///< Resolved node; its CRL is read when the request is built.
        CertObject::Sptr object;               ///< Parsed certificate value.
    };

    /// @brief Verification inputs as set on the session. A default-constructed value selects the default policies.
    struct Inputs
    {
        std::optional<Certificate> leaf;     ///< Certificate to verify.
        std::vector<Certificate> chain;      ///< Presented intermediates; the leaf is not part of this list.
        std::vector<Certificate> untrusted;  ///< Untrusted certificates for chain building.
        std::vector<Certificate> trusted;    ///< Explicit trust anchors.
        score::crypto::ChainTerminationPolicy chain_termination{score::crypto::ChainTerminationPolicy::kRootRequired};
        score::crypto::RevocationCheckPolicy revocation_check{score::crypto::RevocationCheckPolicy::kNone};
        score::crypto::RevocationCoveragePolicy revocation_coverage{
            score::crypto::RevocationCoveragePolicy::kFailClosed};
        std::optional<std::int64_t> verification_time_epoch_s;  ///< Empty selects the current time.
    };

    /// @brief Construct the builder.
    /// @param service Service that resolves CRLs for the client's nodes. Must be non-null.
    /// @param client_id Client that owns the certificate nodes of the inputs.
    VerificationRequestBuilder(CertManagementService::Sptr service, data_manager::ClientId client_id);

    /// @brief Build the request for one verification.
    ///
    /// Anchors are the explicit trusted certificates followed by the enabled members of the bound trust store. In
    /// standalone mode, with no trust store bound, the chain termination policy is kTrustStoreTerminated whatever the
    /// inputs say, because the standalone anchors end the chain. CRLs are collected only when a revocation source is
    /// selected, from the certificate nodes and then from the bound store. A CRL without a nextUpdate is not passed to
    /// the validator.
    /// @param inputs Verification inputs.
    /// @param trust_store Trust store bound by the session, when one is bound.
    /// @return The request. kInvalidArgument when no leaf is set or no trust anchor is available. A read failure
    ///         returns its error unchanged, so an unknown node or an unusable trust store is never treated as "no CRL".
    [[nodiscard]] score::crypto::Expected<provider::cert_management::PathValidationRequest, common::DaemonErrorCode>
    Build(const Inputs& inputs, std::optional<TrustStoreHandle> trust_store) const;

  private:
    CertManagementService::Sptr m_service;  ///< Resolves CRLs and the bound trust store.
    data_manager::ClientId m_client_id;     ///< Client that owns the certificate nodes.
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_REQUEST_BUILDER_HPP
