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

#ifndef SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_SHM_REGISTRY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_SHM_REGISTRY_HPP

#include "score/crypto/src/daemon/data_plane/i_shm_registry.hpp"

#include <mutex>
#include <string_view>
#include <unordered_map>

namespace score::crypto::daemon::data_plane
{

/// @brief Concrete IShmRegistry. Tracks SHM quota per OS user ID (uid).
///
/// Thread-safe.
class ShmRegistry : public IShmRegistry, public std::enable_shared_from_this<ShmRegistry>
{
  public:
    ShmRegistry() = default;
    // TODO : Move all these hardcoded constants to configs
    static constexpr std::size_t kPoolRegionSize = 4UL * 1024UL * 1024UL;     ///< 4 MiB
    static constexpr std::size_t kPoolSlotSize = 1024UL;                      ///< 1 KiB
    static constexpr std::size_t kMaxBytesPerClient = 8UL * 1024UL * 1024UL;  ///< 8 MiB per-uid quota

    Expected<ShmClientConfig, common::DaemonErrorCode> GetConfig(std::uint32_t uid) override;

    Expected<void, common::DaemonErrorCode> Register(std::uint32_t uid, std::size_t size) override;

    void Unregister(std::uint32_t uid, std::size_t size) override;

  private:
    mutable std::mutex m_mutex;
    std::unordered_map<std::uint32_t, std::size_t> m_usage_per_uid;

    static constexpr std::string_view LOG_PREFIX = "[SHM_REGISTRY] ";
};

}  // namespace score::crypto::daemon::data_plane

#endif  // SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_SHM_REGISTRY_HPP
