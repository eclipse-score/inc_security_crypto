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

#ifndef SCORE_CRYPTO_API_DATA_PLANE_I_POOL_ALLOCATOR_HPP
#define SCORE_CRYPTO_API_DATA_PLANE_I_POOL_ALLOCATOR_HPP

#include "score/crypto/src/api/data_plane/src/allocation_error.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>

namespace score
{

namespace crypto
{

/// @brief Internal pool-allocator interface (not part of the public IMemoryAllocator API).
///
/// Limited to pool allocation of fixed-size chunks. All data is exchanged via
/// score::cpp::span, consistent with the rest of the public/internal data-plane API.
class IPoolAllocator
{
  public:
    virtual ~IPoolAllocator() = default;

    IPoolAllocator(const IPoolAllocator&) = delete;
    IPoolAllocator& operator=(const IPoolAllocator&) = delete;
    IPoolAllocator(IPoolAllocator&&) = default;
    IPoolAllocator& operator=(IPoolAllocator&&) = default;

    /// @brief Allocate a chunk of the specified size, without copying any data into it.
    ///
    /// The slot's contents are left uninitialized; it is the caller's responsibility to
    /// populate it (e.g. IBufferTranscoder::AppendInputBuffer() copies heap->slot for input
    /// spans) before the slot is handed to the daemon.
    ///
    /// @param size  Size of the chunk to allocate.
    /// @return A span over the pool-owned destination on success; AllocationError on failure.
    /// Caller is responsible for calling Deallocate() with the returned span when done.
    virtual score::crypto::Expected<score::cpp::span<std::uint8_t>, AllocationError> Allocate(std::size_t size) = 0;

    /// @brief Deallocate a region returned by Allocate().
    /// @param region  Span returned by Allocate()
    virtual void Deallocate(score::cpp::span<std::uint8_t> slot) noexcept = 0;

    /// @brief Chunk size in bytes.
    virtual std::size_t GetChunkSize() const noexcept = 0;

    /// @brief Returns the DataNodeId assigned by the daemon for this pool's SHM region.
    virtual std::uint64_t GetNodeId() const noexcept = 0;

    /// @brief Computes the byte offset of @p slot within the pool region.
    /// @param slot  A span returned by Allocate() from this pool allocator.
    /// @return Offset in bytes from the pool region base address on success; AllocationError on failure.
    virtual score::crypto::Expected<std::size_t, AllocationError> GetOffset(
        score::cpp::span<const std::uint8_t> slot) const = 0;

  protected:
    IPoolAllocator() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_DATA_PLANE_I_POOL_ALLOCATOR_HPP
