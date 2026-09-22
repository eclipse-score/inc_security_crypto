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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_TRUST_STORE_MANAGEMENT_CONTEXT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_TRUST_STORE_MANAGEMENT_CONTEXT_IMPL_HPP

#include "score/crypto/src/api/common/src/i_release_callback.hpp"
#include "score/crypto/src/api/contexts/i_trust_store_management_context.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include "score/result/result.h"
#include "score/span.hpp"

#include <cstdint>
#include <memory>

namespace score
{

namespace crypto
{

// ---------------------------------------------------------------------------
// TrustStoreManagementContextImpl
// ---------------------------------------------------------------------------

/// @brief Concrete ITrustStoreManagementContext that delegates all operations
///        to the crypto daemon via IPC.
///
/// Trust-store membership mutations share the CERT:TRUST_STORE daemon context
/// type and the same `CertManagementService`/`TrustStoreManager` backing as
/// `ICertificateManagementContext`, but are exposed through a separate
/// client-facing capability. See i_trust_store_management_context.hpp.
class TrustStoreManagementContextImpl final : public ITrustStoreManagementContext
{
  public:
    TrustStoreManagementContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                    uint64_t context_id,
                                    std::shared_ptr<IBufferTranscoder> transcoder = nullptr);

    ~TrustStoreManagementContextImpl() override;

    TrustStoreManagementContextImpl(const TrustStoreManagementContextImpl&) = delete;
    TrustStoreManagementContextImpl& operator=(const TrustStoreManagementContextImpl&) = delete;
    TrustStoreManagementContextImpl(TrustStoreManagementContextImpl&&) = delete;
    TrustStoreManagementContextImpl& operator=(TrustStoreManagementContextImpl&&) = delete;

    score::Result<std::monostate> AddCertificateToTrustStore(const CryptoResourceId& trust_store,
                                                             const CryptoResourceId& cert) override;
    score::Result<std::monostate> AddCertificateToTrustStoreWithCrl(const CryptoResourceId& trust_store,
                                                                    const CryptoResourceId& cert) override;
    score::Result<std::monostate> RemoveCertificateFromTrustStore(const CryptoResourceId& trust_store,
                                                                  const CryptoResourceId& cert) override;
    score::Result<std::monostate> RemoveCertificateFromTrustStore(
        const CryptoResourceId& trust_store,
        score::cpp::span<const uint8_t> sha256_fingerprint) override;
    score::Result<std::monostate> EnableTrustStoreMember(const CryptoResourceId& trust_store,
                                                         const CryptoResourceId& slot) override;
    score::Result<std::monostate> DisableTrustStoreMember(const CryptoResourceId& trust_store,
                                                          const CryptoResourceId& slot) override;
    score::Result<std::monostate> AcknowledgeTrustStoreMemberUpdate(const CryptoResourceId& trust_store,
                                                                    const CryptoResourceId& slot) override;
    score::Result<std::monostate> ImportCrlForTrustStoreMember(const CryptoResourceId& trust_store,
                                                               const CryptoResourceId& slot,
                                                               score::cpp::span<const uint8_t> crl_data,
                                                               FormatType format) override;
    score::Result<std::monostate> DeleteCrlForTrustStoreMember(const CryptoResourceId& trust_store,
                                                               const CryptoResourceId& slot) override;

  private:
    static score::Result<daemon::control_plane::protocol::ControlRequest> MakeControlRequest(
        daemon::control_plane::protocol::OperationRequestBuilder builder,
        daemon::control_plane::protocol::DataNodeId context_id);

    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    daemon::control_plane::protocol::DataNodeId m_context_id;
    std::shared_ptr<IBufferTranscoder> m_transcoder;

    class ContextReleaseCallbackImpl;
    std::shared_ptr<IReleaseCallback> m_context_release_callback;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_TRUST_STORE_MANAGEMENT_CONTEXT_IMPL_HPP
