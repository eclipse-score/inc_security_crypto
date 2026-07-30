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

#ifndef SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_I_SHM_REGISTRY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_I_SHM_REGISTRY_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/data_plane/i_shm_factory.hpp"

#include <cstddef>
#include <memory>

namespace score::crypto::daemon::data_plane
{

class IShmFactory;

/// @brief Registry for per-UID SHM quota tracking.
///
/// Tracks quota allocation per OS user ID (uid).
class IShmRegistry
{
  public:
    using Sptr = std::shared_ptr<IShmRegistry>;

    virtual ~IShmRegistry() = default;

    IShmRegistry(const IShmRegistry&) = delete;
    IShmRegistry& operator=(const IShmRegistry&) = delete;
    IShmRegistry(IShmRegistry&&) = delete;
    IShmRegistry& operator=(IShmRegistry&&) = delete;

    /// @brief Combined SHM configuration: pool geometry + per-UID quota.
    struct ShmClientConfig
    {
        std::size_t pool_size;           ///< Total bytes of shm pool.
        std::size_t pool_slot_size;      ///< Bytes per individual fixed slot.
        std::size_t total_quota;         ///< Maximum bytes this uid may allocate.
        std::size_t current_usage;       ///< Bytes currently allocated by this uid.
        IShmFactory::Sptr pool_factory;  ///< Factory for pool SHM allocation (per-app configurable).
    };

    /// @brief Returns pool geometry constants and per-UID quota info.
    virtual Expected<ShmClientConfig, common::DaemonErrorCode> GetConfig(std::uint32_t uid) = 0;

    // =========================================================================
    // Quota tracking
    // =========================================================================

    /// @brief Reserve quota for a uid.
    /// If quota is exceeded, returns an error and no quota is reserved.
    ///
    /// @param uid   OS user ID that owns the allocation.
    /// @param size  Number of bytes to reserve.
    /// @return Success if quota available, kQuotaExceeded otherwise.
    virtual Expected<void, common::DaemonErrorCode> Register(std::uint32_t uid, std::size_t size) = 0;

    /// @brief Release quota for a uid.
    ///
    /// Called by ShmDataNode destructor to return allocated quota.
    ///
    /// @param uid   OS user ID that owns the allocation.
    /// @param size  Number of bytes to release.
    virtual void Unregister(std::uint32_t uid, std::size_t size) = 0;

  protected:
    IShmRegistry() = default;
};

}  // namespace score::crypto::daemon::data_plane

#endif  // SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_I_SHM_REGISTRY_HPP
