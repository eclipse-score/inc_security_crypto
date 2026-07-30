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

#include "score/crypto/src/api/data_plane/src/pool_allocator.hpp"

#include "score/crypto/src/api/data_plane/src/allocation_error.hpp"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <utility>

namespace score
{

namespace crypto
{

score::crypto::Expected<std::shared_ptr<PoolAllocator>, AllocationError> PoolAllocator::Create(ShmCreateResult pool,
                                                                                               std::size_t slot_size)
{
    if (slot_size == 0)
    {
        score::mw::log::LogError() << "[PoolAllocator] ERROR: Create called with slot_size = 0";
        return score::crypto::make_unexpected(AllocationError::kInvalidArgument);
    }

    if (!pool.memory)
    {
        score::mw::log::LogError() << "[PoolAllocator] ERROR: Create called with null pool memory";
        return score::crypto::make_unexpected(AllocationError::kPoolNotInitialized);
    }

    const std::size_t pool_size = pool.memory->size();
    if (pool_size == 0)
    {
        score::mw::log::LogError() << "[PoolAllocator] ERROR: Create called with zero-sized pool";
        return score::crypto::make_unexpected(AllocationError::kInvalidArgument);
    }

    if (pool_size < slot_size)
    {
        score::mw::log::LogError() << "[PoolAllocator] ERROR: Pool size (" << pool_size << ") smaller than slot size ("
                                   << slot_size << ")";
        return score::crypto::make_unexpected(AllocationError::kInvalidArgument);
    }

    return std::make_shared<PoolAllocator>(ConstructorTag{}, std::move(pool), slot_size);
}

PoolAllocator::PoolAllocator(ConstructorTag /* tag */, ShmCreateResult pool, std::size_t slot_size)
    : m_chunk_size{slot_size},
      m_node_id{pool.node_id},
      m_pool_memory_ptr{std::move(pool.memory)},
      m_pool_memory{*m_pool_memory_ptr},
      m_free_sectors(m_pool_memory.size() / slot_size,
                     true)  // Preconditions guaranteed by Create(): pool.memory != null, slot_size > 0, pool_size >=
                            // slot_size. Division and dereference are safe.
{
}

PoolAllocator::~PoolAllocator()
{
    m_pool_memory_ptr.reset();  // on_destroy fires: SHM_DESTROY_OBJECT + IShmRegionRegistry::Unregister
}

score::crypto::Expected<score::cpp::span<std::uint8_t>, AllocationError> PoolAllocator::Allocate(std::size_t size)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    if (size == 0)
    {
        return score::crypto::make_unexpected(AllocationError::kInvalidArgument);
    }

    const std::size_t sectors_needed = (size + m_chunk_size - 1U) / m_chunk_size;
    const auto start_sector_index = AllocateContiguousChunks(sectors_needed);
    if (!start_sector_index.has_value())
    {
        return score::crypto::make_unexpected(AllocationError::kFragmentationError);
    }

    for (std::size_t sector_offset = 0; sector_offset < sectors_needed; ++sector_offset)
    {
        m_free_sectors[start_sector_index.value() + sector_offset] = false;
    }

    // Slot is reserved but left uninitialized; populating it (heap->slot copy) is the
    // caller's responsibility, done by IBufferTranscoder::AppendInputBuffer() for input spans.
    return m_pool_memory.AsWritableSpan().subspan(start_sector_index.value() * m_chunk_size, size);
}

void PoolAllocator::Deallocate(score::cpp::span<std::uint8_t> slot) noexcept
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const auto* pool_begin = m_pool_memory.data();
    const auto* pool_end = pool_begin + m_pool_memory.size();
    if (slot.data() < pool_begin || (slot.data() + slot.size()) > pool_end)
    {
        score::mw::log::LogError() << "[PoolAllocator] ERROR: Deallocate called with a slot outside this pool";
        return;
    }

    const auto offset = static_cast<std::size_t>(slot.data() - pool_begin);
    if (m_chunk_size == 0 || offset % m_chunk_size != 0)
    {
        score::mw::log::LogError() << "[PoolAllocator] ERROR: Deallocate called with misaligned offset";
        return;
    }

    ReleaseChunks(offset, slot.size());
}

void PoolAllocator::ReleaseChunks(std::size_t offset, std::size_t size) noexcept
{
    const std::size_t start_index = offset / m_chunk_size;
    const std::size_t count = (size + m_chunk_size - 1U) / m_chunk_size;

    if (start_index + count > m_free_sectors.size())
    {
        score::mw::log::LogError() << "[PoolAllocator] ERROR: ReleaseChunks out of bounds (start=" << start_index
                                   << " count=" << count << " total=" << m_free_sectors.size() << ")";
        return;
    }

    for (std::size_t i = 0; i < count; ++i)
    {
        m_free_sectors[start_index + i] = true;
    }
}

score::crypto::Expected<std::size_t, AllocationError> PoolAllocator::AllocateContiguousChunks(
    std::size_t sectors_needed)
{
    if (m_free_sectors.size() < sectors_needed)
    {
        return score::crypto::make_unexpected(AllocationError::kFragmentationError);
    }

    std::size_t window_start = 0U;
    while (window_start + sectors_needed <= m_free_sectors.size())
    {
        std::size_t consecutive_free = 0U;
        while (consecutive_free < sectors_needed && m_free_sectors[window_start + consecutive_free])
        {
            ++consecutive_free;
        }

        if (consecutive_free == sectors_needed)
        {
            return window_start;
        }

        window_start += consecutive_free + 1U;  // skip past the blocker
    }

    return score::crypto::make_unexpected(AllocationError::kFragmentationError);
}

// No mutex required: the pool geometry (base address, size, chunk size) is fixed at construction and never changes.
std::uint64_t PoolAllocator::GetNodeId() const noexcept
{
    return m_node_id;
}

// No mutex required: the pool geometry (base address, size, chunk size) is fixed at construction and never changes.
std::size_t PoolAllocator::GetChunkSize() const noexcept
{
    return m_chunk_size;
}

// No mutex required: the pool geometry (base address, size, chunk size) is fixed at construction and never changes.
// Only m_free_sectors is mutated by Allocate/Deallocate, which is not accessed here.
score::crypto::Expected<std::size_t, AllocationError> PoolAllocator::GetOffset(
    score::cpp::span<const std::uint8_t> slot) const
{

    if (slot.empty())
    {
        score::mw::log::LogError() << "[PoolAllocator] ERROR: GetOffset called with empty slot";
        return score::crypto::make_unexpected(AllocationError::kInvalidArgument);
    }

    const auto* pool_begin = m_pool_memory.data();
    const auto* pool_end = pool_begin + m_pool_memory.size();

    // Validate slot is within this pool's range
    if (slot.data() < pool_begin || (slot.data() + slot.size()) > pool_end)
    {
        score::mw::log::LogError() << "[PoolAllocator] ERROR: GetOffset called with slot outside this pool";
        return score::crypto::make_unexpected(AllocationError::kPoolNotInitialized);
    }

    return static_cast<std::size_t>(slot.data() - pool_begin);
}

}  // namespace crypto

}  // namespace score
