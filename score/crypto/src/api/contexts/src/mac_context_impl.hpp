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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_MAC_CONTEXT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_MAC_CONTEXT_IMPL_HPP

#include "score/crypto/src/api/contexts/i_mac_context.hpp"

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

/// @brief Concrete IMacContext implementation that delegates to the crypto daemon via IPC.
///
/// Each instance is bound to a daemon-side MAC context (identified by context_id)
/// created during construction. All streaming operations and verification are
/// forwarded to the daemon through the session's IPC connection.
class MacContextImpl final : public IMacContext
{
  public:
    /// @brief Constructs a MAC context bound to an existing daemon-side context.
    /// @param connection Shared connection for IPC communication
    /// @param context_id Daemon-assigned context identifier (from CTX_CREATE response)
    /// @param algorithm Algorithm name (e.g., "HMAC-SHA256") for MAC size queries
    /// @param transcoder Stack-shared buffer-routing abstraction (pool/bulk/in-band).
    ///                   Shared with all other contexts in the same CryptoStack.
    ///                   When non-null, handles transparent copying via pool SHM.
    MacContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                   uint64_t context_id,
                   AlgorithmId algorithm,
                   std::shared_ptr<IBufferTranscoder> transcoder = nullptr);

    ~MacContextImpl() override;

    MacContextImpl(const MacContextImpl&) = delete;
    MacContextImpl& operator=(const MacContextImpl&) = delete;
    MacContextImpl(MacContextImpl&&) noexcept;
    MacContextImpl& operator=(MacContextImpl&&) noexcept;

    // -- IStreamingContext --
    score::Result<std::monostate> Init(std::optional<score::cpp::span<const uint8_t>> iv) override;
    score::Result<std::monostate> Update(score::cpp::span<const uint8_t> data) override;
    score::Result<std::monostate> Reset() override;

    // -- IStreamingOutputContext --
    score::Result<std::size_t> Finalize(score::cpp::span<uint8_t> output) override;
    std::size_t GetOutputSize() const noexcept override;

    // -- IMacContext --
    score::Result<bool> Verify(score::cpp::span<const uint8_t> mac) override;
    std::size_t GetMacSize() const noexcept override;

  private:
    void CloseContext() noexcept;

    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    score::crypto::daemon::control_plane::protocol::DataNodeId m_context_id;
    AlgorithmId m_algorithm;
    std::shared_ptr<IBufferTranscoder> m_transcoder;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_MAC_CONTEXT_IMPL_HPP
