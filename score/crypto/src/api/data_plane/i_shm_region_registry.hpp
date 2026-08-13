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

#ifndef SCORE_CRYPTO_API_DATA_PLANE_I_SHM_REGION_REGISTRY_HPP
#define SCORE_CRYPTO_API_DATA_PLANE_I_SHM_REGION_REGISTRY_HPP

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>

namespace score
{

namespace crypto
{

/// @brief Registration info passed to IShmRegionRegistry::Register().
struct RegionEntry
{
    std::uint64_t node_id{0};     ///< Daemon-assigned DataNodeId for IPC DataShm parameters.
    std::uintptr_t base_addr{0};  ///< Region start address.
    std::size_t size{0};          ///< Mapped size in bytes.
    bool is_pool{false};          ///< Pool vs. bulk classification.
};

/// @brief Single source of truth for all mapped SHM regions on the client side.
///
/// @par Thread safety
/// All methods of this interface are thread-safe. Implementations must serialize
/// concurrent calls (e.g. via an internal mutex).
class IShmRegionRegistry
{
  public:
    virtual ~IShmRegionRegistry() = default;

    IShmRegionRegistry(const IShmRegionRegistry&) = delete;
    IShmRegionRegistry& operator=(const IShmRegionRegistry&) = delete;
    IShmRegionRegistry(IShmRegionRegistry&&) = default;
    IShmRegionRegistry& operator=(IShmRegionRegistry&&) = default;

    /// @brief Register a newly mapped SHM region.
    ///
    /// @param entry  Region metadata (node_id, base_addr, size, is_pool).
    /// @threadsafe   Safe to call concurrently with any other method.
    virtual void Register(const RegionEntry& entry) = 0;

    /// @brief Unregister a region when it is unmapped.
    ///
    /// @param node_id  The daemon-assigned DataNodeId that was passed to Register().
    /// @threadsafe     Safe to call concurrently with any other method.
    virtual void Unregister(std::uint64_t node_id) = 0;

    /// @brief Resolve an arbitrary pointer to its SHM region's DataNodeId.
    ///
    /// Scans registered regions (O(n)) to find the one whose [base_addr, base_addr+size)
    /// contains [data.data(), data.data()+data.size()).
    ///
    /// @param data   Span covering the bytes to resolve.
    /// @return DataNodeId if found in a registered region, 0 otherwise (0 is not a valid node_id).
    /// @threadsafe   Safe to call concurrently with any other method.
    virtual std::uint64_t IdentifyNode(score::cpp::span<const uint8_t> data) const noexcept = 0;

    /// @brief Compute the byte offset of @p data within its registered SHM region.
    ///
    /// @param data   Span within a registered region.
    /// @return Offset in bytes from the region's base address, or kInvalidMemoryRegion if not found.
    /// @threadsafe   Safe to call concurrently with any other method.
    virtual score::crypto::Expected<std::size_t, CryptoErrorCode> GetOffset(
        score::cpp::span<const uint8_t> data) const noexcept = 0;

    /// @brief Returns the sum of all registered region sizes (both bulk and pool).
    /// @threadsafe Safe to call concurrently with any other method.
    virtual std::size_t GetTotalRegisteredSize() const noexcept = 0;

    /// @brief Returns the total SHM quota negotiated at session setup time.
    /// @threadsafe Safe to call concurrently with any other method.
    virtual std::size_t GetQuota() const noexcept = 0;

  protected:
    IShmRegionRegistry() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_DATA_PLANE_I_SHM_REGION_REGISTRY_HPP
