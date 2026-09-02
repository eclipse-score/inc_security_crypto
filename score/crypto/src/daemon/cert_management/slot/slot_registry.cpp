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

#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/cert_management/policy/access_policy_enforcer.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::cert_management
{

CertSlotHandle CertSlotRegistry::RegisterSlot(CertSlotConfig config)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const std::string name = config.slot_name;

    if (m_name_index.find(name) != m_name_index.end())
    {
        score::mw::log::LogError() << kLogPrefix << "Duplicate slot name ignored: '" << name << "'";
        return CertSlotHandle{};
    }

    const auto index = static_cast<uint32_t>(m_registry.size());

    CertSlotRegistryEntry entry{};
    entry.config = std::move(config);

    m_name_index[name] = index;
    m_registry.push_back(std::move(entry));
    return CertSlotHandle{index};
}

score::crypto::Expected<CertSlotHandle, score::crypto::daemon::common::DaemonErrorCode> CertSlotRegistry::ResolveSlot(
    const std::string& slot_name,
    data_manager::ClientId client_id) const
{
    // RegisterSlot is called only at startup (ConfigDrivenSlotCatalog::Populate),
    // before any concurrent executor threads start. m_name_index and m_registry are
    // read-only at runtime, so no lock is needed here.
    auto it = m_name_index.find(slot_name);
    if (it == m_name_index.end())
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    auto access_result = AccessPolicyEnforcer::CheckSlotAccess(m_registry[it->second].config, client_id);
    if (!access_result.has_value())
        return score::crypto::make_unexpected(access_result.error());
    return CertSlotHandle{it->second};
}

score::crypto::Expected<CertSlotHandle, score::crypto::daemon::common::DaemonErrorCode>
CertSlotRegistry::ResolveSlotInternal(const std::string& slot_name) const
{
    // See ResolveSlot: m_name_index is read-only after startup.
    auto it = m_name_index.find(slot_name);
    if (it == m_name_index.end())
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    return CertSlotHandle{it->second};
}

score::crypto::Expected<const CertSlotConfig*, score::crypto::daemon::common::DaemonErrorCode>
CertSlotRegistry::GetConfig(CertSlotHandle handle) const
{
    // See ResolveSlot: m_registry is read-only after startup. IsValidHandle reads
    // m_registry.size() without a lock — consistent with GetSlotCount() and IsValidHandle().
    if (!IsValidHandle(handle))
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    return &m_registry[handle.index].config;
}

std::size_t CertSlotRegistry::GetSlotCount() const noexcept
{
    return m_registry.size();
}

std::vector<CertSlotHandle> CertSlotRegistry::GetAllHandles() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<CertSlotHandle> handles;
    handles.reserve(m_registry.size());
    for (uint32_t i = 0U; i < static_cast<uint32_t>(m_registry.size()); ++i)
    {
        handles.push_back(CertSlotHandle{i});
    }
    return handles;
}

bool CertSlotRegistry::IsValidHandle(CertSlotHandle handle) const noexcept
{
    return handle.IsValid() && handle.index < static_cast<uint32_t>(m_registry.size());
}

void CertSlotRegistry::RegisterAppResource(uint32_t uid,
                                           const std::string& app_resource_id,
                                           const std::string& slot_name)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto& uid_map = m_app_resource_map[uid];
    if (uid_map.find(app_resource_id) != uid_map.end())
    {
        score::mw::log::LogError() << kLogPrefix << "Duplicate app resource mapping ignored: uid=" << uid
                                   << " resource='" << app_resource_id << "'";
        return;
    }
    uid_map[app_resource_id] = slot_name;
}

score::crypto::Expected<CertSlotHandle, score::crypto::daemon::common::DaemonErrorCode>
CertSlotRegistry::ResolveAppResource(const std::string& app_resource_id, data_manager::ClientId client_id) const
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

}  // namespace score::crypto::daemon::cert_management
