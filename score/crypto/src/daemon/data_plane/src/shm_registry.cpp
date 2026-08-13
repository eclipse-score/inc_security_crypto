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

#include "score/crypto/src/daemon/data_plane/src/shm_registry.hpp"

#include "score/crypto/src/daemon/data_plane/src/base_shm_factory.hpp"

#include <memory>

namespace score::crypto::daemon::data_plane
{
Expected<void, common::DaemonErrorCode> ShmRegistry::Register(std::uint32_t uid, std::size_t size)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it = m_usage_per_uid.find(uid);
    const std::size_t current = (it != m_usage_per_uid.end()) ? it->second : 0U;
    if (current + size > kMaxBytesPerClient)
    {
        return make_unexpected(common::DaemonErrorCode::kQuotaExceeded);
    }
    m_usage_per_uid[uid] += size;
    return {};
}

void ShmRegistry::Unregister(std::uint32_t uid, std::size_t size)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_usage_per_uid.find(uid);
    if (it != m_usage_per_uid.end())
    {
        it->second = (it->second >= size) ? it->second - size : 0U;
    }
}

Expected<IShmRegistry::ShmClientConfig, common::DaemonErrorCode> ShmRegistry::GetConfig(std::uint32_t uid)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it = m_usage_per_uid.find(uid);
    const std::size_t current = (it != m_usage_per_uid.end()) ? it->second : 0U;

    // Hardcode to kPosixNamed for now (per-app config will be added later)
    auto pool_factory = std::make_shared<BaseShmFactory>();

    return ShmClientConfig{kPoolRegionSize, kPoolSlotSize, kMaxBytesPerClient, current, pool_factory};
}

}  // namespace score::crypto::daemon::data_plane
