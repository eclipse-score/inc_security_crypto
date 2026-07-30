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

#ifndef SCORE_CRYPTO_API_DATA_PLANE_I_BUFFER_TRANSCODER_HPP
#define SCORE_CRYPTO_API_DATA_PLANE_I_BUFFER_TRANSCODER_HPP

/// @file i_buffer_transcoder.hpp
/// @brief INTERNAL header — not part of the public crypto API.
#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"

#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <memory>

namespace score
{

namespace crypto
{

// Forward declaration
class IPoolAllocator;

/// @brief Descriptor for a resolved SHM region (node_id + offset).
struct ShmObjectNodeAndOffset
{
    std::uint64_t node_id{0};  ///< Daemon-assigned DataNodeId — used in DataShm IPC parameters.
    std::size_t offset{0};     ///< Byte offset within region (for pool slot allocation).
};
/// @brief RAII token returned by IBufferTranscoder::Acquire() for both input and output paths.
///
/// Automatically releases pool slots on destruction. Move-only to prevent double-free.
class TranscoderSpan
{
  public:
    enum class Kind : std::uint8_t
    {
        kInBand,  ///< In-band: daemon returns result inline in response.
        kPool,    ///< Pool SHM: slot reserved; freed automatically on destruction.
        kBulk     ///< Bulk SHM: caller span already in a mapped region; zero-copy.
    };

    /// @brief Current buffer routing kind.
    Kind kind() const noexcept
    {
        return kind_;
    }
    /// @brief Set the buffer routing kind.
    void set_kind(Kind kind) noexcept
    {
        kind_ = kind;
    }

    /// @brief Caller's span (const for input; mutable output spans convert implicitly).
    score::cpp::span<uint8_t> caller_span() const noexcept
    {
        return caller_span_;
    }
    /// @brief Set the caller's span.
    void set_caller_span(score::cpp::span<uint8_t> span) noexcept
    {
        caller_span_ = span;
    }

    /// @brief kPool only: slot span returned by IPoolAllocator::Allocate().
    score::cpp::span<uint8_t> pool_span() const noexcept
    {
        return pool_span_;
    }
    /// @brief Set the pool slot span.
    void set_pool_span(score::cpp::span<uint8_t> span) noexcept
    {
        pool_span_ = span;
    }

    /// @brief IPC node_id/offset for kBulk and kPool.
    const ShmObjectNodeAndOffset& obj_node_offset() const noexcept
    {
        return obj_node_offset_;
    }
    /// @brief Mutable IPC node_id/offset for kBulk and kPool.
    ShmObjectNodeAndOffset& obj_node_offset() noexcept
    {
        return obj_node_offset_;
    }

    /// @brief Weak reference to pool allocator for automatic cleanup.
    /// Only set for kPool spans. If PoolAllocator is destroyed before this span,
    /// cleanup is skipped (safe no-op).
    std::weak_ptr<IPoolAllocator> pool_allocator_weak() const noexcept
    {
        return pool_allocator_weak_;
    }
    /// @brief Set the weak reference to pool allocator for automatic cleanup.
    void set_pool_allocator_weak(const std::weak_ptr<IPoolAllocator>& allocator) noexcept
    {
        pool_allocator_weak_ = allocator;
    }

    /// @brief Destructor: automatically releases pool slot if kind == kPool.
    ~TranscoderSpan() noexcept;

    // Move-only semantics
    TranscoderSpan() = default;
    TranscoderSpan(const TranscoderSpan&) = delete;
    TranscoderSpan& operator=(const TranscoderSpan&) = delete;
    TranscoderSpan(TranscoderSpan&&) noexcept = default;
    TranscoderSpan& operator=(TranscoderSpan&&) noexcept = default;

  private:
    Kind kind_{Kind::kInBand};
    score::cpp::span<uint8_t> caller_span_{};
    score::cpp::span<uint8_t> pool_span_{};
    ShmObjectNodeAndOffset obj_node_offset_{};
    std::weak_ptr<IPoolAllocator> pool_allocator_weak_;
};

/// @brief Internal buffer-routing abstraction for context implementations.
///
/// A single concrete implementation (BufferShmTranscoder) handles bulk-SHM
/// detection and pool-SHM copy paths.  One instance is owned by CryptoStackImpl
/// (per CryptoStack) and shared via shared_ptr across all contexts belonging to
/// that stack.  The interface is stateless: all per-call state is carried in the
/// TranscoderSpan returned to the caller.
class IBufferTranscoder
{
  public:
    virtual ~IBufferTranscoder() = default;
    IBufferTranscoder(const IBufferTranscoder&) = delete;
    IBufferTranscoder& operator=(const IBufferTranscoder&) = delete;
    IBufferTranscoder(IBufferTranscoder&&) = default;
    IBufferTranscoder& operator=(IBufferTranscoder&&) = default;

    /// @brief Classify a span and determine buffer routing.
    ///
    /// Examines @p data to determine the routing kind (in-band, bulk SHM, or pool SHM).
    /// @param data  Caller's span (const for input; mutable output spans convert implicitly).
    /// @param is_output  Must be true for output buffers
    ///                   When true: forces SHM routing (bulk or pool), returns error if SHM unavailable.
    ///                   When false (default): allows in-band for small input buffers (≤32 bytes threshold).
    /// @return TranscoderSpan on success, or CryptoErrorCode on failure (e.g., output buffer requires
    ///         SHM but no registry/pool available).
    virtual score::crypto::Expected<TranscoderSpan, CryptoErrorCode> Acquire(score::cpp::span<const uint8_t> data,
                                                                             bool is_output = false) = 0;

    /// @brief attach a pre-acquired input span to @p builder.
    ///
    /// For kPool: copies heap->slot (the slot reserved by Acquire() is otherwise
    /// uninitialized), then adds a DataShm(In) parameter to @p builder.
    /// For kBulk: adds a DataShm(In) parameter to @p builder (zero-copy).
    /// For kInBand: adds the in-band data buffer to @p builder.
    /// @param builder  Request builder to receive the routing parameter.
    /// @param tspan    Token returned by Acquire() for this input span.
    virtual void AppendInputBuffer(score::crypto::daemon::control_plane::protocol::OperationRequestBuilder& builder,
                                   TranscoderSpan& tspan) = 0;

    /// @brief attach the output slot to @p builder.
    ///
    /// For kBulk/kPool: adds a DataShm(InOut) parameter to @p builder.
    /// For kInBand: no-op (daemon returns result in-band).
    /// @param builder  Request builder to receive the routing parameter.
    /// @param tspan    Token returned by Acquire() for this output span.
    virtual void AppendOutputBuffer(score::crypto::daemon::control_plane::protocol::OperationRequestBuilder& builder,
                                    TranscoderSpan& tspan) = 0;

    /// @brief Extract the daemon result into the caller's output span.
    ///
    /// kBulk: no copy (daemon wrote directly); returns span size.
    /// kPool: copies slot→caller_span. Pool slot is automatically released by ~TranscoderSpan().
    /// kInBand: copies inline response data→caller_span.
    /// @param tspan       Token returned by Acquire() for this output span.
    /// @param validator   Validated response (must already have isValid() == true).
    /// @param param_idx   Index of the output parameter within the response operation.
    ///                    Defaults to 0. Pass an explicit index for operations that
    ///                    return multiple output parameters.
    virtual score::Result<std::size_t> ExtractOutputBuffer(
        TranscoderSpan& tspan,
        score::crypto::daemon::control_plane::protocol::ControlResponseValidator& validator,
        std::size_t param_idx = 0) = 0;

  protected:
    IBufferTranscoder() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_DATA_PLANE_I_BUFFER_TRANSCODER_HPP
