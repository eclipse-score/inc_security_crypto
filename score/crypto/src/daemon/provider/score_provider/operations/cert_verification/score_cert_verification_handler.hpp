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
#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CERT_VERIFICATION_SCORE_CERT_VERIFICATION_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CERT_VERIFICATION_SCORE_CERT_VERIFICATION_HANDLER_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_trust_store_handler.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"
#include "score/crypto/src/daemon/provider/executors/cert_mgmt_context.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::operations::cert_verification
{

class CertVerificationExecutor;
class CertEntry;

/// @brief Abstract base handler for CERT:VERIFICATION context operations under
///        the score interface family.
///
/// Implements the daemon's Handler interface by delegating Execute() to the
/// injected CertVerificationExecutor. Concrete score-interface providers
/// (e.g. OpenSSL) inherit from this class and override DoVerify().
///
/// The executor handles all IPC parameter extraction and state accumulation.
/// The handler holds the accumulated context state and drives CertManagementService
/// lookups before delegating to the provider-specific DoVerify().
class ScoreCertVerificationHandler : public handler::Handler
{
  public:
    using CertSptr = ::score::crypto::daemon::cert_management::CertObject::Sptr;

    struct VerificationInput
    {
        CertSptr leaf;
        std::vector<CertSptr> chain;
        std::vector<CertSptr> additional;
        /// Trust anchors — always resolved before DoVerify() is called.
        /// Populated from either SetTrustedCertificates (explicit anchors) or
        /// SetVerificationTrustStore (GetAnchors() result). Never empty on a valid call.
        std::vector<CertSptr> trusted;
        /// Set when trust-store mode is active. DoVerify() sees pre-resolved anchors
        /// in trusted; this field is informational (e.g. for ChainTerminationPolicy).
        std::optional<uint64_t> trust_store_node_id;
        uint8_t chain_termination_policy{0U};
        /// Optional verification time (epoch seconds). Empty = use current time.
        std::optional<int64_t> verification_time_epoch_s;
        /// Revocation check policy (0=kNone; matches RevocationCheckPolicy numeric values).
        uint8_t revocation_policy{0U};
        score::crypto::VerificationEvidenceMode evidence_mode{score::crypto::VerificationEvidenceMode::kNone};
        std::vector<::score::crypto::daemon::cert_management::CrlEntry> crls;
        /// Trust store handler — non-null in trust-store mode when revocation_policy != kNone.
        /// DoVerify() calls GetCrls() on this handler; CRLs are lazily cached alongside anchors.
        ::score::crypto::daemon::cert_management::ITrustStoreHandler::Sptr trust_store_handler;
    };

    /// Outcome returned by DoVerify(). On success (kValid), chain is non-empty.
    /// On verification failure (kExpired etc.), chain is empty and result_code is non-zero.
    /// Infrastructure failures still return an error via Expected.
    struct VerifyOutcome
    {
        uint8_t result_code{0U};                    ///< Numeric value of CertVerifyResult (0=kValid)
        std::vector<CertSptr> chain;                ///< Established chain, leaf-first; empty if not kValid
        common::OwnedBuffer selected_crl_metadata;  ///< Packed selected CrlMetadata entries when requested.
    };

    ScoreCertVerificationHandler(
        std::unique_ptr<CertVerificationExecutor> executor,
        std::shared_ptr<::score::crypto::daemon::provider::cert_management::ICertParser> cert_parser,
        std::shared_ptr<::score::crypto::daemon::cert_management::CertManagementService> service);

    ~ScoreCertVerificationHandler() override;

    ScoreCertVerificationHandler(const ScoreCertVerificationHandler&) = delete;
    ScoreCertVerificationHandler& operator=(const ScoreCertVerificationHandler&) = delete;
    ScoreCertVerificationHandler(ScoreCertVerificationHandler&&) = delete;
    ScoreCertVerificationHandler& operator=(ScoreCertVerificationHandler&&) = delete;

    // -----------------------------------------------------------------------
    // Handler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request) override;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;

    // -----------------------------------------------------------------------
    // Typed setters — called by CertVerificationExecutor after IPC extraction
    // -----------------------------------------------------------------------

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> SetLeaf(uint64_t node_id);
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> SetChain(const std::vector<uint64_t>& node_ids);
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> SetTrustStore(uint64_t node_id);
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> SetTrusted(const std::vector<uint64_t>& node_ids);
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> SetPolicy(uint8_t policy);
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> SetAdditional(
        const std::vector<uint64_t>& node_ids);

    void SetVerificationTime(int64_t epoch_s) noexcept;
    void SetRevocationPolicy(uint8_t policy) noexcept;
    void SetEvidenceMode(uint8_t mode) noexcept;

    /// Assembles VerificationInput from retained certificate entries and
    /// delegates to DoVerify(). Caches the resulting chain.
    [[nodiscard]] Expected<uint8_t, common::DaemonErrorCode> Verify();

    /// Returns the number of certificates in the chain from the last successful Verify().
    [[nodiscard]] uint32_t GetVerifiedChainCertificateCount() const noexcept;

    [[nodiscard]] Expected<std::size_t, common::DaemonErrorCode> GetVerifiedChainExportSize(
        score::crypto::FormatType format) const;

    [[nodiscard]] Expected<common::OwnedBuffer, common::DaemonErrorCode> ExportVerifiedChain(
        score::crypto::FormatType format) const;

    [[nodiscard]] Expected<std::size_t, common::DaemonErrorCode> GetVerifiedCertificateExportSize(
        std::size_t index,
        score::crypto::FormatType format) const;

    [[nodiscard]] Expected<common::OwnedBuffer, common::DaemonErrorCode> ExportVerifiedCertificate(
        std::size_t index,
        score::crypto::FormatType format) const;
    [[nodiscard]] Expected<common::OwnedBuffer, common::DaemonErrorCode> GetSelectedCrlMetadata() const;

  protected:
    /// Override in a concrete provider to perform the actual path verification.
    /// Returns a VerifyOutcome with result_code and (for kValid) the established chain.
    /// Only infrastructure failures should return an error via Expected.
    [[nodiscard]] virtual Expected<VerifyOutcome, common::DaemonErrorCode> DoVerify(const VerificationInput& input);

  private:
    using CertService = ::score::crypto::daemon::cert_management::CertManagementService;
    using CertEntrySptr = std::shared_ptr<::score::crypto::daemon::cert_management::CertEntry>;

    [[nodiscard]] Expected<CertEntrySptr, common::DaemonErrorCode> ResolveCertEntry(uint64_t node_id) const;
    [[nodiscard]] Expected<common::OwnedBuffer, common::DaemonErrorCode> EncodeCertificate(
        const CertSptr& cert,
        score::crypto::FormatType format) const;

    std::unique_ptr<CertVerificationExecutor> m_executor;
    std::shared_ptr<::score::crypto::daemon::provider::cert_management::ICertParser> m_cert_parser;
    std::shared_ptr<CertService> m_service;
    crypto_executor::CertMgmtExecutionContext m_ctx{};

    // Accumulated setter state
    CertEntrySptr m_leaf_cert_entry;
    std::vector<CertEntrySptr> m_chain_cert_entries;
    std::optional<uint64_t> m_trust_store_node_id;
    std::vector<CertEntrySptr> m_trusted_cert_entries;
    uint8_t m_chain_termination_policy{0U};
    std::vector<CertEntrySptr> m_additional_cert_entries;
    std::optional<int64_t> m_verification_time_epoch_s;
    uint8_t m_revocation_policy{0U};
    score::crypto::VerificationEvidenceMode m_evidence_mode{score::crypto::VerificationEvidenceMode::kNone};

    // Cached result from last successful Verify()
    std::vector<CertSptr> m_verified_chain;
    common::OwnedBuffer m_selected_crl_metadata;

    // Trust store ref-count tracking: non-empty while a trust store is bound.
    // AddRef() called in SetTrustStore(); ReleaseRef() in Reset()/destructor.
    std::optional<::score::crypto::daemon::cert_management::TrustStoreHandle> m_trust_store_handle;
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::cert_verification

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_CERT_VERIFICATION_SCORE_CERT_VERIFICATION_HANDLER_HPP
