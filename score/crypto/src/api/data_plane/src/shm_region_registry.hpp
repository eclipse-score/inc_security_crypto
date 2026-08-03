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

#ifndef SCORE_CRYPTO_API_DATA_PLANE_SRC_SHM_REGION_REGISTRY_HPP
#define SCORE_CRYPTO_API_DATA_PLANE_SRC_SHM_REGION_REGISTRY_HPP

#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>

namespace score
{

namespace crypto
{

/// @brief Concrete IShmRegionRegistry backed by a sorted interval map.
///
/// Manages all mapped SHM regions — both bulk (registered by ShmMemoryAllocator)
/// and pool (registered by PoolAllocator) — in a single sorted map keyed by the
/// region base address.  Identify() uses upper_bound + step-back for O(log n)
/// containment queries, matching the prior ShmMemoryAllocator::m_mapped_regions
/// approach but extended to both region types.
///
/// Thread safety: all public methods are serialized under m_mutex.
class ShmRegionRegistry final : public IShmRegionRegistry
{
  public:
    /// @param total_quota  Total SHM quota in bytes as reported by the daemon via SHM_SETUP.
    explicit ShmRegionRegistry(std::size_t total_quota);

    ~ShmRegionRegistry() override = default;

    ShmRegionRegistry(const ShmRegionRegistry&) = delete;
    ShmRegionRegistry& operator=(const ShmRegionRegistry&) = delete;
    ShmRegionRegistry(ShmRegionRegistry&&) = default;
    ShmRegionRegistry& operator=(ShmRegionRegistry&&) = default;

    void Register(const RegionEntry& entry) override;

    void Unregister(std::uint64_t node_id) override;

    std::uint64_t IdentifyNode(score::cpp::span<const uint8_t> data) const noexcept override;

    score::crypto::Expected<std::size_t, CryptoErrorCode> GetOffset(
        score::cpp::span<const uint8_t> data) const noexcept override;

    std::size_t GetTotalRegisteredSize() const noexcept override;

    std::size_t GetQuota() const noexcept override;

  private:
    mutable std::mutex m_mutex;
    /// Sorted by base address for O(log n) upper_bound containment checks.
    std::map<std::uint64_t, RegionEntry> m_regions;
    const std::size_t m_total_quota{0U};
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_DATA_PLANE_SRC_SHM_REGION_REGISTRY_HPP
