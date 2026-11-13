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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_SESSION_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_SESSION_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/cert_management/context/cert_execution_context.hpp"
#include "score/crypto/src/daemon/cert_management/context/verification/request_builder.hpp"
#include "score/crypto/src/daemon/cert_management/context/verification/result_encoder.hpp"
#include "score/crypto/src/daemon/cert_management/context/verification/trust_store_binding.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_path_validator.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// @brief State of one CERT:VERIFICATION context: the inputs accumulated by the setters, the trust-store binding, and
///        the result of the last verification.
///
/// The session resolves each certificate node when its setter runs, so an unknown node fails at the setter. Verify()
/// builds the provider-neutral request, hands it to the path validator, and keeps the outcome for the result accessors.
/// The session is single-threaded: one client drives one context.
class CertVerificationSession final
{
  public:
    /// @brief Collaborators of a session. Every member must be non-null.
    struct Services
    {
        CertManagementService::Sptr service;                  ///< Resolves nodes, CRLs, and stores.
        provider::cert_management::ICertParser::Sptr parser;  ///< Encodes the verified outputs.
        std::shared_ptr<provider::cert_management::ICertPathValidator> validator;  ///< Performs path validation.
    };

    /// @brief Construct an empty session.
    /// @param ctx Caller identity of the context.
    /// @param services Collaborators of the session.
    CertVerificationSession(CertExecutionContext ctx, Services services);

    CertVerificationSession(const CertVerificationSession&) = delete;
    CertVerificationSession& operator=(const CertVerificationSession&) = delete;
    CertVerificationSession(CertVerificationSession&&) = delete;
    CertVerificationSession& operator=(CertVerificationSession&&) = delete;

    /// @brief Set the certificate to verify, replacing the leaf and the chain.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> SetLeaf(
        data_manager::DataNodeId node_id);

    /// @brief Set a chain given leaf first. Replaces the leaf and the chain.
    /// @return kInvalidArgument for an empty list, or the error of the first node that cannot be resolved.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> SetChain(
        const std::vector<data_manager::DataNodeId>& node_ids);

    /// @brief Bind a trust store. A failed bind leaves the previous binding in place.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> SetTrustStore(
        data_manager::DataNodeId node_id);

    /// @brief Set the explicit trust anchors, replacing the previous explicit set.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> SetTrusted(
        const std::vector<data_manager::DataNodeId>& node_ids);

    /// @brief Set the untrusted certificates, replacing the previous set.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> SetUntrusted(
        const std::vector<data_manager::DataNodeId>& node_ids);

    /// @brief Set the chain termination policy. It applies to trust-store verification only.
    void SetChainTerminationPolicy(score::crypto::ChainTerminationPolicy policy) noexcept;

    /// @brief Set the verification time in epoch seconds.
    void SetVerificationTime(std::int64_t epoch_s) noexcept;

    /// @brief Set the revocation sources to consult.
    void SetRevocationCheckPolicy(score::crypto::RevocationCheckPolicy policy) noexcept;

    /// @brief Set the behavior when the selected sources lack fresh evidence.
    void SetRevocationCoveragePolicy(score::crypto::RevocationCoveragePolicy policy) noexcept;

    /// @brief Set which verification evidence the session retains.
    void SetEvidenceMode(score::crypto::VerificationEvidenceMode mode) noexcept;

    /// @brief Run the verification.
    /// @return The verdict. A failed verdict is a result, not an error. An error means the request could not be built
    ///         or the validator failed.
    [[nodiscard]] score::crypto::Expected<score::crypto::CertVerifyResult, common::DaemonErrorCode> Verify();

    /// @brief Number of certificates in the verified chain of the last Verify(); zero unless the verdict is kValid.
    [[nodiscard]] std::uint32_t GetVerifiedChainCertificateCount() const noexcept;

    /// @brief Encode the verified chain, leaf first, in @p format.
    /// @return The bytes, or kInvalidArgument when no chain is held or the format is not DER or PEM.
    [[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> ExportVerifiedChain(
        score::crypto::FormatType format) const;

    /// @brief Encode one certificate of the verified chain.
    /// @return The bytes, or kInvalidArgument for an index outside the chain or a format that is not DER or PEM.
    [[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> ExportVerifiedCertificate(
        std::size_t index,
        score::crypto::FormatType format) const;

    /// @brief Return the CRL metadata the last verification selected, packed in the CrlMetadataWireLayout encoding.
    /// @return The packed entries, or kUnsupportedOperation unless the evidence mode is kChainAndCrl. The metadata is
    ///         kept after a failed verdict as well.
    [[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> GetSelectedCrlMetadata()
        const;

    /// @brief Clear the inputs, the evidence mode, and the result, and release the trust-store binding.
    void Reset();

  private:
    /// Resolve one certificate node to its parsed value.
    [[nodiscard]] score::crypto::Expected<VerificationRequestBuilder::Certificate, common::DaemonErrorCode>
    ResolveCertificate(data_manager::DataNodeId node_id) const;

    /// Resolve every node of a list, in order; fails on the first node that cannot be resolved.
    [[nodiscard]] score::crypto::Expected<std::vector<VerificationRequestBuilder::Certificate>, common::DaemonErrorCode>
    ResolveCertificates(const std::vector<data_manager::DataNodeId>& node_ids) const;

    CertExecutionContext m_ctx;                    ///< Caller identity of the context.
    Services m_services;                           ///< Collaborators; members are non-null.
    VerificationRequestBuilder m_request_builder;  ///< Assembles the request from the inputs.
    TrustStoreBinding m_binding;                   ///< Trust store reference held by this session.
    VerifiedResultEncoder m_encoder;               ///< Encodes the verified outputs.
    VerificationRequestBuilder::Inputs m_inputs;   ///< Inputs accumulated by the setters.
    score::crypto::VerificationEvidenceMode m_evidence_mode{score::crypto::VerificationEvidenceMode::kNone};
    std::vector<std::shared_ptr<CertObject>> m_verified_chain;        ///< Chain of the last kValid verdict.
    std::vector<score::crypto::CrlMetadata> m_selected_crl_metadata;  ///< CRL metadata of the last verification.
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_SESSION_HPP
