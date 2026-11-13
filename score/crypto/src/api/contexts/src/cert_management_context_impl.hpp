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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CERT_MANAGEMENT_CONTEXT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CERT_MANAGEMENT_CONTEXT_IMPL_HPP

#include "score/crypto/src/api/common/crypto_resource_guard.hpp"
#include "score/crypto/src/api/common/src/i_release_callback.hpp"
#include "score/crypto/src/api/contexts/i_certificate_management_context.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"
#include "score/crypto/src/api/objects/i_cert_slot_object.hpp"
#include "score/crypto/src/api/objects/i_certificate_object.hpp"
#include "score/crypto/src/api/objects/src/cert_slot_object_impl.hpp"
#include "score/crypto/src/api/objects/src/certificate_object_impl.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace score
{

namespace crypto
{

// ---------------------------------------------------------------------------
// CertManagementContextImpl
// ---------------------------------------------------------------------------

/// @brief Concrete ICertificateManagementContext that delegates all operations
///        to the crypto daemon via IPC.
///
/// Follows the same release-callback pattern as KeyManagementContextImpl.
/// Parsed certificate resources are owned by CryptoResourceGuard instances;
/// typed certificate objects are non-owning views.
class CertManagementContextImpl final : public ICertificateManagementContext
{
  public:
    CertManagementContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                              uint64_t context_id,
                              std::shared_ptr<IBufferTranscoder> transcoder = nullptr);

    ~CertManagementContextImpl() override;

    CertManagementContextImpl(const CertManagementContextImpl&) = delete;
    CertManagementContextImpl& operator=(const CertManagementContextImpl&) = delete;
    CertManagementContextImpl(CertManagementContextImpl&&) = delete;
    CertManagementContextImpl& operator=(CertManagementContextImpl&&) = delete;

    // ---- Parsing ----
    score::Result<CryptoResourceGuard> ParseCertificate(score::cpp::span<const uint8_t> cert_data,
                                                        FormatType format) override;
    score::Result<std::vector<CryptoResourceGuard>> ParseCertificates(score::cpp::span<const uint8_t> cert_data,
                                                                      FormatType format) override;

    // ---- Persistence ----
    score::Result<std::monostate> SaveCertificate(const CryptoResourceId& cert,
                                                  const CryptoResourceId& target_slot) override;
    score::Result<std::monostate> SaveCertificateWithCrl(const CryptoResourceId& cert,
                                                         const CryptoResourceId& target_slot) override;

    // ---- Export ----
    score::Result<std::size_t> GetCertificateExportSize(const CryptoResourceId& cert, FormatType format) override;
    score::Result<std::size_t> ExportCertificate(const CryptoResourceId& cert,
                                                 FormatType format,
                                                 score::cpp::span<uint8_t> output) override;

    // ---- Format conversion ----
    score::Result<std::size_t> GetConvertedCertificateSize(score::cpp::span<const uint8_t> input,
                                                           FormatType input_format,
                                                           FormatType output_format) override;
    score::Result<std::size_t> ConvertCertificateFormat(score::cpp::span<const uint8_t> input,
                                                        FormatType input_format,
                                                        FormatType output_format,
                                                        score::cpp::span<uint8_t> output) override;

    // ---- Slot management ----
    score::Result<std::monostate> ClearCertificate(const CryptoResourceId& slot) override;
    score::Result<CryptoResourceGuard> LoadCertificate(const CryptoResourceId& slot) override;

    // ---- Key extraction ----
    score::Result<std::pair<CryptoResourceGuard, AlgorithmId>> LoadCertificatePublicKey(
        const CryptoResourceId& cert) override;

    // ---- CRL management ----
    score::Result<std::monostate> ImportCrl(score::cpp::span<const uint8_t> crl_data,
                                            FormatType format,
                                            const CryptoResourceId& issuer_cert) override;
    score::Result<std::monostate> ImportCrlToSlot(score::cpp::span<const uint8_t> crl_data,
                                                  FormatType format,
                                                  const CryptoResourceId& cert_slot) override;
    score::Result<std::monostate> DeleteCrl(const CryptoResourceId& cert_slot) override;

  private:
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    daemon::control_plane::protocol::DataNodeId m_context_id;
    std::shared_ptr<IBufferTranscoder> m_transcoder;

    class ContextReleaseCallbackImpl;
    std::shared_ptr<IReleaseCallback> m_context_release_callback;

    class ReleaseCallbackImpl;
    std::shared_ptr<IReleaseCallback> m_release_callback;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CERT_MANAGEMENT_CONTEXT_IMPL_HPP
