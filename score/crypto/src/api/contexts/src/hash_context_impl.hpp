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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_HASH_CONTEXT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_HASH_CONTEXT_IMPL_HPP

#include "score/crypto/src/api/contexts/i_hash_context.hpp"

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"

#include <cstdint>
#include <memory>
#include <optional>

namespace score
{

namespace crypto
{

/// @brief Concrete IHashContext implementation that delegates to the crypto daemon via IPC.
///
/// Each instance is bound to a daemon-side hash context (identified by context_id)
/// created during construction. All streaming and single-shot operations are
/// forwarded to the daemon through the session's RequestOperation() API.
class HashContextImpl final : public IHashContext
{
  public:
    /// @brief Constructs a hash context bound to an existing daemon-side context.
    /// @param connection Shared connection for IPC communication (contains DataNodeId)
    /// @param context_id Daemon-assigned context identifier (from CTX_CREATE response)
    /// @param algorithm Algorithm name (e.g., "SHA-256") for digest size queries
    /// @param transcoder Stack-shared buffer-routing abstraction (pool/bulk/in-band).
    ///                   Shared with all other contexts in the same CryptoStack.
    ///                   When non-null, handles transparent copying via pool SHM.
    HashContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                    uint64_t context_id,
                    AlgorithmId algorithm,
                    std::shared_ptr<IBufferTranscoder> transcoder = nullptr);

    ~HashContextImpl() override;

    HashContextImpl(const HashContextImpl&) = delete;
    HashContextImpl& operator=(const HashContextImpl&) = delete;
    HashContextImpl(HashContextImpl&&) noexcept;
    HashContextImpl& operator=(HashContextImpl&&) noexcept;

    // -- IStreamingContext --
    score::Result<std::monostate> Init(std::optional<score::cpp::span<const uint8_t>> iv) override;
    score::Result<std::monostate> Update(score::cpp::span<const uint8_t> data) override;
    score::Result<std::monostate> Reset() override;

    // -- IStreamingOutputContext --
    score::Result<std::size_t> Finalize(score::cpp::span<uint8_t> output) override;
    std::size_t GetOutputSize() const noexcept override;

    // -- IHashContext --
    score::Result<std::size_t> SingleShot(score::cpp::span<const uint8_t> input,
                                          score::cpp::span<uint8_t> output) override;
    std::size_t GetDigestSize() const noexcept override;

  private:
    void CloseContext() noexcept;

    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    score::crypto::daemon::control_plane::protocol::DataNodeId m_context_id;
    AlgorithmId m_algorithm;
    std::shared_ptr<IBufferTranscoder> m_transcoder;  ///< Stack-shared transcoder; null allowed.
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_HASH_CONTEXT_IMPL_HPP
