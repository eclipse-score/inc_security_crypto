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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CIPHER_CONTEXT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CIPHER_CONTEXT_IMPL_HPP

#include "score/crypto/src/api/contexts/i_cipher_context.hpp"

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

/// @brief Concrete ICipherContext implementation that delegates to the crypto daemon via IPC.
///
/// Each instance is bound to a daemon-side cipher context (identified by context_id)
/// created during construction. The key, algorithm and direction (encrypt / decrypt)
/// are fixed at CTX_CREATE time and are not repeated per operation.
class CipherContextImpl final : public ICipherContext
{
  public:
    /// @brief Constructs a cipher context bound to an existing daemon-side context.
    /// @param connection Shared connection for IPC communication
    /// @param context_id Daemon-assigned context identifier (from CTX_CREATE response)
    /// @param algorithm Algorithm name (e.g., "AES-256-CBC")
    /// @param transcoder Stack-shared buffer-routing abstraction (pool/bulk/in-band).
    ///                   Shared with all other contexts in the same CryptoStack.
    ///                   When non-null, handles transparent copying via pool SHM.
    CipherContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                      uint64_t context_id,
                      AlgorithmId algorithm,
                      std::shared_ptr<IBufferTranscoder> transcoder = nullptr);

    ~CipherContextImpl() override;

    CipherContextImpl(const CipherContextImpl&) = delete;
    CipherContextImpl& operator=(const CipherContextImpl&) = delete;
    CipherContextImpl(CipherContextImpl&&) noexcept;
    CipherContextImpl& operator=(CipherContextImpl&&) noexcept;

    // -- IStreamingContext --
    score::Result<std::monostate> Init(std::optional<score::cpp::span<const uint8_t>> iv) override;
    score::Result<std::monostate> Update(score::cpp::span<const uint8_t> data) override;
    score::Result<std::monostate> Reset() override;

    // -- IStreamingOutputContext --
    score::Result<std::size_t> Finalize(score::cpp::span<uint8_t> output) override;
    std::size_t GetOutputSize() const noexcept override;

    // -- ICipherContext --
    score::Result<std::size_t> Update(score::cpp::span<const uint8_t> input, score::cpp::span<uint8_t> output) override;
    score::Result<std::size_t> SingleShot(score::cpp::span<const uint8_t> iv,
                                          score::cpp::span<const uint8_t> input,
                                          score::cpp::span<uint8_t> output) override;

  private:
    void CloseContext() noexcept;

    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    score::crypto::daemon::control_plane::protocol::DataNodeId m_context_id;
    AlgorithmId m_algorithm;
    std::shared_ptr<IBufferTranscoder> m_transcoder;  ///< Stack-shared transcoder; null allowed.
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CIPHER_CONTEXT_IMPL_HPP
