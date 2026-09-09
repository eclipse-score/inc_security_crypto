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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_VERIFY_SIGNATURE_CONTEXT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_VERIFY_SIGNATURE_CONTEXT_IMPL_HPP

#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <variant>

namespace score
{

namespace crypto
{

/// @brief Concrete IVerifySignatureContext implementation that delegates to the
///        crypto daemon via IPC.
///
/// Each instance is bound to a daemon-side verification context (identified by
/// context_id) created during construction. The public key and algorithm are
/// fixed at CTX_CREATE time.
///
/// A signature that does not verify is reported as a successful call returning
/// false — only transport or state errors produce an error Result.
class VerifySignatureContextImpl final : public IVerifySignatureContext
{
  public:
    /// @brief Constructs a verification context bound to an existing daemon-side context.
    /// @param connection Shared connection for IPC communication
    /// @param context_id Daemon-assigned context identifier (from CTX_CREATE response)
    /// @param algorithm Algorithm name (e.g., "ECDSA-P256-SHA256")
    /// @param transcoder Stack-shared buffer-routing abstraction (pool/bulk/in-band).
    ///                   Shared with all other contexts in the same CryptoStack.
    ///                   When non-null, handles transparent copying via pool SHM.
    VerifySignatureContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                               uint64_t context_id,
                               AlgorithmId algorithm,
                               std::shared_ptr<IBufferTranscoder> transcoder = nullptr);

    ~VerifySignatureContextImpl() override;

    VerifySignatureContextImpl(const VerifySignatureContextImpl&) = delete;
    VerifySignatureContextImpl& operator=(const VerifySignatureContextImpl&) = delete;
    VerifySignatureContextImpl(VerifySignatureContextImpl&&) noexcept;
    VerifySignatureContextImpl& operator=(VerifySignatureContextImpl&&) noexcept;

    // -- IStreamingContext --
    score::Result<std::monostate> Init(std::optional<score::cpp::span<const uint8_t>> iv) override;
    score::Result<std::monostate> Update(score::cpp::span<const uint8_t> data) override;
    score::Result<std::monostate> Reset() override;

    // -- IVerifySignatureContext --
    score::Result<bool> VerifyFinalize(score::cpp::span<const uint8_t> signature) override;
    score::Result<bool> SingleShot(score::cpp::span<const uint8_t> data,
                                   score::cpp::span<const uint8_t> signature) override;

  private:
    void CloseContext() noexcept;

    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    score::crypto::daemon::control_plane::protocol::DataNodeId m_context_id;
    AlgorithmId m_algorithm;
    std::shared_ptr<IBufferTranscoder> m_transcoder;  ///< Stack-shared transcoder; null allowed.
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_VERIFY_SIGNATURE_CONTEXT_IMPL_HPP
