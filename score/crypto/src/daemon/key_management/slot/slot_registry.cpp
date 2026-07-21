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

#include "score/crypto/daemon/key_management/slot/slot_registry.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"
#include "score/crypto/daemon/key_management/slot/access_policy_enforcer.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"

#include "score/mw/log/logging.h"
#include <algorithm>

namespace score::crypto::daemon::key_management
{

SlotHandle SlotRegistry::RegisterSlot(KeySlotConfig config)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const std::string name = config.slot_name;

    if (m_name_index.find(name) != m_name_index.end())
    {
        score::mw::log::LogError() << LOG_PREFIX << "Duplicate slot name ignored: '" << name << "'";
        return SlotHandle{};
    }

    const auto index = static_cast<uint32_t>(m_registry.size());

    SlotRegistryEntry entry{};
    entry.config = std::move(config);

    m_name_index[name] = index;
    m_registry.push_back(std::move(entry));
    return SlotHandle{index};
}

score::crypto::Expected<SlotHandle, score::crypto::daemon::common::DaemonErrorCode> SlotRegistry::ResolveSlot(
    const std::string& slot_name,
    data_manager::ClientId client_id) const
{
    auto it = m_name_index.find(slot_name);
    if (it == m_name_index.end())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }

    const auto index = it->second;
    const auto& entry = m_registry[index];

    auto access_result = AccessPolicyEnforcer::CheckSlotAccess(entry.config, client_id);
    if (!access_result.has_value())
    {
        return score::crypto::make_unexpected(access_result.error());
    }

    return SlotHandle{index};
}

score::crypto::Expected<const KeySlotConfig*, score::crypto::daemon::common::DaemonErrorCode> SlotRegistry::GetConfig(
    SlotHandle handle) const
{
    if (!IsValidHandle(handle))
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }
    return &m_registry[handle.index].config;
}

std::size_t SlotRegistry::GetSlotCount() const noexcept
{
    return m_registry.size();
}

void SlotRegistry::RegisterAppResource(uint32_t uid, const std::string& app_resource_id, const std::string& slot_name)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto& uid_map = m_app_resource_map[uid];
    if (uid_map.find(app_resource_id) != uid_map.end())
    {
        score::mw::log::LogError() << LOG_PREFIX << "Duplicate app resource mapping ignored: uid=" << uid
                                   << " resource='" << app_resource_id << "'";
        return;
    }
    uid_map[app_resource_id] = slot_name;
}

score::crypto::Expected<SlotHandle, score::crypto::daemon::common::DaemonErrorCode> SlotRegistry::ResolveAppResource(
    const std::string& app_resource_id,
    data_manager::ClientId client_id) const
{
    const uint32_t uid = control_plane::protocol::GetUidFromClientId(client_id);

    std::string slot_name;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto uid_it = m_app_resource_map.find(uid);
        if (uid_it == m_app_resource_map.end())
        {
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
        }
        auto res_it = uid_it->second.find(app_resource_id);
        if (res_it == uid_it->second.end())
        {
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
        }
        slot_name = res_it->second;
    }

    return ResolveSlot(slot_name, client_id);
}

void SlotRegistry::ResolveProviderIds(const provider::ProviderManager& provider_manager)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& entry : m_registry)
    {
        entry.config.provider_ids.clear();
        for (const auto& name : entry.config.provider_names)
        {
            auto provider = provider_manager.GetProvider(name);
            if (provider)
            {
                entry.config.provider_ids.push_back(provider->GetProviderId());
            }
            else
            {
                score::mw::log::LogError() << LOG_PREFIX << "Warning: provider '" << name << "' not found for slot '"
                                           << entry.config.slot_name << "'";
            }
        }
    }
}

bool SlotRegistry::IsValidHandle(SlotHandle handle) const noexcept
{
    return handle.IsValid() && handle.index < static_cast<uint32_t>(m_registry.size());
}

score::crypto::Expected<common::ProviderId, score::crypto::daemon::common::DaemonErrorCode>
SlotRegistry::GetPrimaryProviderId(SlotHandle handle) const
{
    if (!IsValidHandle(handle))
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }
    const auto& ids = m_registry[handle.index].config.provider_ids;
    if (ids.empty())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    return ids.front();
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
SlotRegistry::IsProviderAllowedForSlot(SlotHandle handle, const common::ProviderId& provider_id) const
{
    if (!IsValidHandle(handle))
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }
    if (m_registry[handle.index].config.IsProviderAllowed(provider_id))
    {
        return std::monostate{};
    }
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAccessDenied);
}

}  // namespace score::crypto::daemon::key_management
