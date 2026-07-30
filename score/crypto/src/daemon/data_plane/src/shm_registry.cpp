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
#include "score/mw/log/logging.h"

#include <memory>

namespace score::crypto::daemon::data_plane
{
Expected<void, common::DaemonErrorCode> ShmRegistry::Register(std::uint32_t uid, std::size_t size)
{
    score::mw::log::LogVerbose() << LOG_PREFIX << "[REGISTER] uid=" << uid << " size=" << size << " bytes";
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it = m_usage_per_uid.find(uid);
    const std::size_t current = (it != m_usage_per_uid.end()) ? it->second : 0U;
    if (current + size > kMaxBytesPerClient)
    {
        score::mw::log::LogVerbose() << LOG_PREFIX << "[REGISTER_FAILED] uid=" << uid << " (current=" << current
                                     << ", requested=" << size << ", max=" << kMaxBytesPerClient << ")";
        return make_unexpected(common::DaemonErrorCode::kQuotaExceeded);
    }
    m_usage_per_uid[uid] += size;
    score::mw::log::LogVerbose() << LOG_PREFIX << "[REGISTER_SUCCESS] uid=" << uid
                                 << " usage_after=" << m_usage_per_uid[uid] << " bytes";
    return {};
}

void ShmRegistry::Unregister(std::uint32_t uid, std::size_t size)
{
    score::mw::log::LogVerbose() << LOG_PREFIX << "[UNREGISTER] uid=" << uid << " size=" << size << " bytes";
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_usage_per_uid.find(uid);
    if (it != m_usage_per_uid.end())
    {
        const std::size_t before = it->second;
        it->second = (it->second >= size) ? it->second - size : 0U;
        score::mw::log::LogVerbose() << LOG_PREFIX << "[UNREGISTER_SUCCESS] uid=" << uid << " usage_before=" << before
                                     << " usage_after=" << it->second << " bytes";
    }
    else
    {
        score::mw::log::LogVerbose() << LOG_PREFIX << "[UNREGISTER_WARNING] uid=" << uid
                                     << " not found in tracking map";
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
