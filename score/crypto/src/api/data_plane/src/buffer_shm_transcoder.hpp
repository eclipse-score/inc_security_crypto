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

#ifndef SCORE_CRYPTO_API_DATA_PLANE_SRC_BUFFER_SHM_TRANSCODER_HPP
#define SCORE_CRYPTO_API_DATA_PLANE_SRC_BUFFER_SHM_TRANSCODER_HPP

/// @file buffer_shm_transcoder.hpp
/// @brief INTERNAL header — not part of the public crypto API.
/// Concrete IBufferTranscoder that routes heap-based spans through the session-shared
/// PoolAllocator, and passes already-mapped bulk SHM spans directly without copying.

///   TODO: Add multi-sector chunked support for large spans.

#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"
#include "score/crypto/src/api/data_plane/i_pool_allocator.hpp"
#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"

#include <memory>

namespace score
{

namespace crypto
{

/// @brief Stateless IBufferTranscoder implementation
///
/// One BufferShmTranscoder is created per CryptoStack (owned by CryptoStackImpl) and
/// shared across all contexts via shared_ptr.  All per-call state is carried in the
/// TranscoderSpan returned to the caller
class BufferShmTranscoder final : public IBufferTranscoder
{
  public:
    /// @param pool_allocator  Session-shared pool allocator.  Shared ownership.
    /// @param registry        Unified SHM region registry.  Shared ownership.
    explicit BufferShmTranscoder(std::shared_ptr<IPoolAllocator> pool_allocator,
                                 std::shared_ptr<IShmRegionRegistry> registry);

    ~BufferShmTranscoder() override = default;

    BufferShmTranscoder(const BufferShmTranscoder&) = delete;
    BufferShmTranscoder& operator=(const BufferShmTranscoder&) = delete;
    BufferShmTranscoder(BufferShmTranscoder&&) = delete;
    BufferShmTranscoder& operator=(BufferShmTranscoder&&) = delete;

    score::crypto::Expected<TranscoderSpan, score::result::Error> Acquire(score::cpp::span<const uint8_t> data,
                                                                          bool is_output = false) override;

    void AppendInputBuffer(score::crypto::daemon::control_plane::protocol::OperationRequestBuilder& builder,
                           TranscoderSpan& tspan) override;

    void AppendOutputBuffer(score::crypto::daemon::control_plane::protocol::OperationRequestBuilder& builder,
                            TranscoderSpan& tspan) override;

    score::Result<std::size_t> ExtractOutputBuffer(
        TranscoderSpan& tspan,
        score::crypto::daemon::control_plane::protocol::ControlResponseValidator& validator,
        std::size_t param_idx) override;

    // -----------------------------------------------------------------------
    // Public constants
    // -----------------------------------------------------------------------
    /// Heap spans at or below this size bypass pool SHM and use in-band transport.
    /// Bulk SHM detection always supersedes this threshold.
    static constexpr std::size_t kInBandThreshold = 32U;

  private:
    // -----------------------------------------------------------------------
    // Members
    // -----------------------------------------------------------------------
    std::shared_ptr<IPoolAllocator> m_pool_allocator;  ///< Session-scoped pool allocator.
    std::shared_ptr<IShmRegionRegistry> m_registry;    ///< For bulk + pool pointer identification.
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_DATA_PLANE_SRC_BUFFER_SHM_TRANSCODER_HPP
