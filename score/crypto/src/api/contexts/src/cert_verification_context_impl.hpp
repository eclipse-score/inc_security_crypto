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

#include "score/crypto/src/api/contexts/i_certificate_verification_context.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <variant>

namespace score
{

namespace crypto
{

/// @brief Certificate verification context backed by a daemon-side CERT:VERIFICATION context.
///
/// Each setter sends one CERT_VERIFY_SET_* operation, and Verify() sends CERT_VERIFY. The daemon accumulates the
/// verification inputs for the context and applies them when Verify() runs. The client keeps only the outcome and
/// chain length of the most recent successful verification; chain and CRL evidence is read back through the export
/// and metadata operations.
class CertVerificationContextImpl final : public ICertificateVerificationContext
{
  public:
    /// @brief Constructs a certificate verification context bound to an existing daemon-side context.
    /// @param connection Shared connection for IPC communication
    /// @param context_id Daemon-assigned context identifier (from CTX_CREATE response)
    /// @param transcoder Buffer-routing abstraction for exported chain and CRL metadata buffers
    CertVerificationContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                uint64_t context_id,
                                std::shared_ptr<IBufferTranscoder> transcoder = nullptr);

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
    score::Result<std::monostate> SetUntrustedCertificates(
        score::cpp::span<const CryptoResourceId> certificates) override;
    score::Result<std::monostate> SetVerificationTime(int64_t epoch_seconds) override;
    score::Result<std::monostate> SetRevocationCheckPolicy(RevocationCheckPolicy policy) override;
    score::Result<std::monostate> SetRevocationCoveragePolicy(RevocationCoveragePolicy policy) override;
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
    std::shared_ptr<IBufferTranscoder> m_transcoder;

    /// Outcome of the most recent successful CERT_VERIFY. Empty until a verification completes.
    std::optional<CertVerifyResult> m_verify_result;
    /// Chain length reported by the most recent successful CERT_VERIFY.
    uint32_t m_chain_count{0U};

    /// Sends CTX_CLOSE for the daemon-side context. Called from the destructor.
    void CloseContext() noexcept;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CERT_VERIFICATION_CONTEXT_IMPL_HPP
