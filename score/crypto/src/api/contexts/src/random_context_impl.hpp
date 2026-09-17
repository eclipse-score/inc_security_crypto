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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_RANDOM_CONTEXT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_RANDOM_CONTEXT_IMPL_HPP

#include "score/crypto/src/api/contexts/i_random_context.hpp"

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"

#include <cstdint>
#include <memory>
#include <variant>

namespace score
{

namespace crypto
{

/// @brief Concrete IRandomContext implementation that delegates to the crypto daemon via IPC.
///
/// Each instance is bound to a daemon-side random context (identified by
/// context_id) created during construction. Unlike the streaming contexts the
/// random context carries no state machine: Generate() and Seed() are valid at
/// any point in the context's lifetime.
class RandomContextImpl final : public IRandomContext
{
  public:
    /// @brief Constructs a random context bound to an existing daemon-side context.
    /// @param connection Shared connection for IPC communication
    /// @param context_id Daemon-assigned context identifier (from CTX_CREATE response)
    /// @param algorithm RNG algorithm name; empty selects the provider default
    /// @param transcoder Stack-shared buffer-routing abstraction (pool/bulk/in-band).
    ///                   Shared with all other contexts in the same CryptoStack.
    ///                   When non-null, handles transparent copying via pool SHM.
    RandomContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                      uint64_t context_id,
                      AlgorithmId algorithm,
                      std::shared_ptr<IBufferTranscoder> transcoder = nullptr);

    ~RandomContextImpl() override;

    RandomContextImpl(const RandomContextImpl&) = delete;
    RandomContextImpl& operator=(const RandomContextImpl&) = delete;
    RandomContextImpl(RandomContextImpl&&) noexcept;
    RandomContextImpl& operator=(RandomContextImpl&&) noexcept;

    // -- IRandomContext --
    score::Result<std::size_t> Generate(score::cpp::span<uint8_t> output) override;
    score::Result<std::monostate> Seed(score::cpp::span<const uint8_t> seed) override;

  private:
    void CloseContext() noexcept;

    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    score::crypto::daemon::control_plane::protocol::DataNodeId m_context_id;
    AlgorithmId m_algorithm;
    std::shared_ptr<IBufferTranscoder> m_transcoder;  ///< Stack-shared transcoder; null allowed.
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_RANDOM_CONTEXT_IMPL_HPP
