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

#ifndef SCORE_CRYPTO_API_DATA_PLANE_SRC_POOL_ALLOCATOR_HPP
#define SCORE_CRYPTO_API_DATA_PLANE_SRC_POOL_ALLOCATOR_HPP

#include "score/crypto/src/api/data_plane/i_pool_allocator.hpp"
#include "score/crypto/src/api/data_plane/i_read_write_memory_factory.hpp"
#include "score/crypto/src/api/data_plane/src/allocation_error.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace score
{

namespace crypto
{

/// @brief Allocator for the fixed pool SHM region.
///
/// Manages the pool SHM region created and mapped by IReadWriteMemoryFactory.
/// Responsible only for sector-level bookkeeping
class PoolAllocator final : public IPoolAllocator
{
  private:
    /// @brief Tag type to restrict constructor access to Create method only.
    struct ConstructorTag
    {
        explicit ConstructorTag() = default;
    };

  public:
    /// @brief Factory method to create a PoolAllocator instance.
    /// @param pool       ShmCreateResult from IReadWriteMemoryFactory::Create(is_pool=true).
    ///                   memory holds the RAII lifetime; its on_destroy callback handles
    ///                   SHM_DESTROY_OBJECT and IShmRegionRegistry::Unregister.
    /// @param slot_size  Slot size in bytes (from SHM_SETUP response param[4]).
    /// @return std::shared_ptr<PoolAllocator> on success, or AllocationError::kInvalidArgument if slot_size is 0.
    static score::crypto::Expected<std::shared_ptr<PoolAllocator>, AllocationError> Create(ShmCreateResult pool,
                                                                                           std::size_t slot_size);

    /// @brief Constructor with tag - only callable via Create method.
    /// @param tag        Tag to restrict construction to Create method.
    /// @param pool       ShmCreateResult from IReadWriteMemoryFactory::Create(is_pool=true).
    /// @param slot_size  Slot size in bytes. Must be > 0 (validated by Create).
    explicit PoolAllocator(ConstructorTag tag, ShmCreateResult pool, std::size_t slot_size);

    ~PoolAllocator() final;

    PoolAllocator(const PoolAllocator&) = delete;
    PoolAllocator& operator=(const PoolAllocator&) = delete;
    PoolAllocator(PoolAllocator&&) = default;
    PoolAllocator& operator=(PoolAllocator&&) = default;

    score::crypto::Expected<score::cpp::span<std::uint8_t>, AllocationError> Allocate(std::size_t size) override;

    void Deallocate(score::cpp::span<std::uint8_t> slot) noexcept override;

    std::size_t GetChunkSize() const noexcept override;

    std::uint64_t GetNodeId() const noexcept override;

    score::crypto::Expected<std::size_t, AllocationError> GetOffset(
        score::cpp::span<const std::uint8_t> slot) const override;

  private:
    /// @brief Marks a range of sectors as free.
    void ReleaseChunks(std::size_t offset, std::size_t size) noexcept;

    /// @brief Find @sectors_needed contiguous free sectors using first-fit algorithm.
    ///
    /// @return Index of the first sector in the run, or AllocationError::kFragmentationError if not found.
    score::crypto::Expected<std::size_t, AllocationError> AllocateContiguousChunks(std::size_t sectors_needed);

    const std::size_t m_chunk_size = 0;
    const std::uint64_t m_node_id = 0;  ///< DataNodeId assigned by daemon for this pool region.

    // Unique pointer for lifetime management (validated non-null by Create)
    IReadWriteMemory::Uptr
        m_pool_memory_ptr;  ///< RAII owner; on_destroy triggers unmap + SHM_DESTROY_OBJECT + Unregister.

    // Reference for guaranteed non-null access (safe even if moved)
    IReadWriteMemory& m_pool_memory;

    mutable std::mutex m_mutex;

    /// Bitmap: bit set (1) --> sector free; bit clear (0) --> sector occupied.
    std::vector<bool> m_free_sectors;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_DATA_PLANE_SRC_POOL_ALLOCATOR_HPP
