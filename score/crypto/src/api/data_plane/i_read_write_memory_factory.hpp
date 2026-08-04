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

#ifndef SCORE_CRYPTO_API_DATA_PLANE_I_READ_WRITE_MEMORY_FACTORY_HPP
#define SCORE_CRYPTO_API_DATA_PLANE_I_READ_WRITE_MEMORY_FACTORY_HPP

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/i_memory.hpp"
#include "score/crypto/src/common/types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace score::crypto::api::control_plane
{
class IConnection;
}

namespace score
{

namespace crypto
{

/// @brief Core SHM region parameters (used by data plane to map and register a region).
struct ShmRegionParams
{
    std::uint64_t node_id;         ///< Daemon-assigned DataNodeId.
    std::uint64_t size;            ///< Usable region size in bytes.
    std::string token;             ///< SHM object name (POSIX name or handle).
    std::uint64_t transport_type;  ///< ShmTransportType enum value.
};

/// @brief Pool-specific geometry parameters (used by control plane to configure pool allocator).
struct PoolGeometry
{
    std::uint64_t slot_size;    ///< Pool slot size in bytes.
    std::uint64_t total_quota;  ///< Total quota in bytes.
};

/// @brief Complete SHM_SETUP response (control plane uses both, data plane uses only region).
struct ShmSetupResponse
{
    ShmRegionParams region;            ///< Core region parameters (always present).
    std::optional<PoolGeometry> pool;  ///< Pool geometry (present when is_pool=1).
};

/// @brief Internal result of IReadWriteMemoryFactory::Create().
struct ShmCreateResult
{
    std::uint64_t node_id;          ///< Daemon-assigned DataNodeId.
    IReadWriteMemory::Uptr memory;  ///< RAII lifetime owner.
};

/// @brief Data plane client side Factory that decodes a SHM_SETUP response, maps the region, registers it,
///        and returns a ShmCreateResult
class IReadWriteMemoryFactory
{
  public:
    using Sptr = std::shared_ptr<IReadWriteMemoryFactory>;

    virtual ~IReadWriteMemoryFactory() = default;

    IReadWriteMemoryFactory(const IReadWriteMemoryFactory&) = delete;
    IReadWriteMemoryFactory& operator=(const IReadWriteMemoryFactory&) = delete;
    IReadWriteMemoryFactory(IReadWriteMemoryFactory&&) = delete;
    IReadWriteMemoryFactory& operator=(IReadWriteMemoryFactory&&) = delete;

    /// @brief Open the SHM region described by @p region_params, register it, and return a ShmCreateResult.
    ///
    /// @param region_params  Core SHM region parameters (node_id, size, token, transport_type).
    /// @param is_pool        Forwarded to IShmRegionRegistry::Register(). True for pool regions,
    ///                       false (default) for bulk regions.
    ///
    /// Note: The returned IReadWriteMemory (ShmRwMemory) holds a weak_ptr to the registry and
    /// unregisters itself automatically in its destructor.
    virtual score::crypto::Expected<ShmCreateResult, CryptoErrorCode> Create(const ShmRegionParams& region_params,
                                                                             bool is_pool = false) = 0;

  protected:
    IReadWriteMemoryFactory() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_DATA_PLANE_I_READ_WRITE_MEMORY_FACTORY_HPP
