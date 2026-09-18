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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CERT_VERIFICATION_CONTEXT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CERT_VERIFICATION_CONTEXT_IMPL_HPP

#include "score/crypto/src/api/common/src/i_release_callback.hpp"
#include "score/crypto/src/api/contexts/i_certificate_verification_context.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace score
{

namespace crypto
{

/// @brief Concrete ICertificateVerificationContext implementation that delegates to the crypto daemon via IPC.
///
/// Accumulates verification parameters via setter calls and exposes the
/// verified certificate chain as encoded certificate data.
class CertVerificationContextImpl final : public ICertificateVerificationContext
{
  public:
    /// @brief Constructs a cert verification context bound to a daemon-side context.
    /// @param connection Shared connection for IPC communication
    /// @param context_id Daemon-assigned context identifier (from CTX_CREATE response)
    CertVerificationContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                uint64_t context_id);

    ~CertVerificationContextImpl() override;

    CertVerificationContextImpl(const CertVerificationContextImpl&) = delete;
    CertVerificationContextImpl& operator=(const CertVerificationContextImpl&) = delete;
    CertVerificationContextImpl(CertVerificationContextImpl&&) = delete;
    CertVerificationContextImpl& operator=(CertVerificationContextImpl&&) = delete;

    // ---- Configuration setters (call before Verify()) ----

    score::Result<std::monostate> SetCertificate(const CryptoResourceId& cert) override;
    score::Result<std::monostate> SetCertificateChain(score::cpp::span<const CryptoResourceId> chain) override;
    score::Result<std::monostate> SetVerificationTrustStore(const CryptoResourceId& trust_store) override;
    score::Result<std::monostate> SetTrustedCertificates(score::cpp::span<const CryptoResourceId> certs) override;
    score::Result<std::monostate> SetChainTerminationPolicy(ChainTerminationPolicy policy) override;
    score::Result<std::monostate> SetAdditionalCertificates(
        score::cpp::span<const CryptoResourceId> certificates) override;
    score::Result<std::monostate> SetVerificationTime(int64_t epoch_seconds) override;
    score::Result<std::monostate> SetRevocationCheckPolicy(RevocationCheckPolicy policy) override;
    score::Result<std::monostate> SetEvidenceMode(VerificationEvidenceMode mode) override;

    // ---- Execution ----

    score::Result<CertVerifyResult> Verify() override;
    score::Result<std::size_t> GetVerifiedChainCertificateCount() const override;
    score::Result<std::size_t> GetVerifiedChainExportSize(FormatType format) const override;
    score::Result<std::size_t> ExportVerifiedChain(FormatType format, score::cpp::span<uint8_t> out) const override;
    score::Result<std::size_t> GetVerifiedCertificateExportSize(std::size_t index, FormatType format) const override;
    score::Result<std::size_t> ExportVerifiedCertificate(std::size_t index,
                                                         FormatType format,
                                                         score::cpp::span<uint8_t> out) const override;
    score::Result<std::size_t> GetSelectedCrlMetadataCount() const override;
    score::Result<std::size_t> GetSelectedCrlMetadata(score::cpp::span<CrlMetadata> out) const override;

  private:
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    daemon::control_plane::protocol::DataNodeId m_context_id;

    std::optional<CertVerifyResult> m_verify_result;
    uint32_t m_chain_count{0U};
    VerificationEvidenceMode m_evidence_mode{VerificationEvidenceMode::kNone};

    /// @brief Sends a no-argument IPC request and returns ok-or-error.
    [[nodiscard]] score::Result<std::monostate> SendSimpleOp(
        const daemon::control_plane::protocol::OperationIdentifier& op_id) const;

    class ContextReleaseCallbackImpl;
    std::shared_ptr<IReleaseCallback> m_context_release_callback;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CERT_VERIFICATION_CONTEXT_IMPL_HPP
