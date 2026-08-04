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

#include "score/crypto/src/api/data_plane/src/shm_region_registry.hpp"

#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>

namespace score
{

namespace crypto
{

ShmRegionRegistry::ShmRegionRegistry(std::size_t total_quota) : m_total_quota{total_quota} {}

void ShmRegionRegistry::Register(const RegionEntry& entry)
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    const auto iterator = m_regions.find(entry.node_id);
    if (iterator != m_regions.end())
    {
        iterator->second = entry;
    }
    else
    {
        m_regions.insert({entry.node_id, entry});
    }
}

void ShmRegionRegistry::Unregister(std::uint64_t node_id)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_regions.erase(node_id);
}

std::uint64_t ShmRegionRegistry::IdentifyNode(score::cpp::span<const uint8_t> data) const noexcept
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const auto addr = reinterpret_cast<std::uintptr_t>(data.data());
    const std::size_t size = data.size();

    for (const auto& pair : m_regions)
    {
        const RegionEntry& region = pair.second;
        if (addr >= region.base_addr && (addr - region.base_addr) + size <= region.size)
        {
            return region.node_id;
        }
    }

    return 0;
}

score::crypto::Expected<std::size_t, CryptoErrorCode> ShmRegionRegistry::GetOffset(
    score::cpp::span<const uint8_t> data) const noexcept
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const auto addr = reinterpret_cast<std::uintptr_t>(data.data());
    const std::size_t size = data.size();

    for (const auto& pair : m_regions)
    {
        const RegionEntry& region = pair.second;
        if (addr >= region.base_addr && (addr - region.base_addr) + size <= region.size)
        {
            return static_cast<std::size_t>(addr - region.base_addr);
        }
    }

    return score::crypto::make_unexpected(CryptoErrorCode::kInvalidMemoryRegion);
}

std::size_t ShmRegionRegistry::GetTotalRegisteredSize() const noexcept
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    std::size_t total = 0U;
    for (const auto& pair : m_regions)
    {
        total += pair.second.size;
    }
    return total;
}

std::size_t ShmRegionRegistry::GetQuota() const noexcept
{
    return m_total_quota;
}

}  // namespace crypto

}  // namespace score
