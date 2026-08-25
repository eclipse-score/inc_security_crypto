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

#include "score/crypto/src/daemon/cert_management/core/cert_registry.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_entry.hpp"

#include "score/mw/log/logging.h"

#include <string_view>

namespace score::crypto::daemon::cert_management
{
namespace
{
constexpr std::string_view kLogPrefix = "[CERT_REGISTRY] ";
}  // namespace

CertRegistryId CertRegistry::RegisterSlotCert(CertSlotHandle slot_handle, std::shared_ptr<CertEntry> cert_entry)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    if (m_slot_to_id.count(slot_handle.index) != 0U)
    {
        score::mw::log::LogError() << kLogPrefix << "RegisterSlotCert: slot " << slot_handle.index
                                   << " already registered";
        return 0U;
    }

    const CertRegistryId id = m_next_id++;
    m_certs.emplace(id, std::move(cert_entry));
    m_slot_to_id.emplace(slot_handle.index, id);

    return id;
}

CertRegistryId CertRegistry::RegisterEphemeralCert(std::shared_ptr<CertEntry> cert_entry)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const CertRegistryId id = m_next_id++;
    m_certs.emplace(id, std::move(cert_entry));

    return id;
}

std::shared_ptr<CertEntry> CertRegistry::FindBySlot(CertSlotHandle slot_handle) const
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const auto slot_it = m_slot_to_id.find(slot_handle.index);
    if (slot_it == m_slot_to_id.end())
    {
        return nullptr;
    }

    const auto cert_it = m_certs.find(slot_it->second);
    if (cert_it == m_certs.end())
    {
        return nullptr;
    }

    return cert_it->second;
}

CertRegistryId CertRegistry::FindSlotRegistryId(CertSlotHandle slot_handle) const
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const auto slot_it = m_slot_to_id.find(slot_handle.index);
    if (slot_it == m_slot_to_id.end())
    {
        return 0U;
    }

    return slot_it->second;
}

std::shared_ptr<CertEntry> CertRegistry::FindById(CertRegistryId id) const
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const auto it = m_certs.find(id);
    if (it == m_certs.end())
    {
        return nullptr;
    }

    return it->second;
}

bool CertRegistry::Unregister(CertRegistryId id)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const auto it = m_certs.find(id);
    if (it == m_certs.end())
    {
        return false;
    }

    for (auto slot_it = m_slot_to_id.begin(); slot_it != m_slot_to_id.end(); ++slot_it)
    {
        if (slot_it->second == id)
        {
            m_slot_to_id.erase(slot_it);
            break;
        }
    }

    m_certs.erase(it);
    return true;
}

void CertRegistry::CleanupClient(data_manager::ClientId client_id)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<CertRegistryId> to_remove;

    for (auto& [id, cert_entry] : m_certs)
    {
        if (cert_entry->Release(client_id))
        {
            to_remove.push_back(id);
        }
    }

    for (const auto id : to_remove)
    {
        for (auto slot_it = m_slot_to_id.begin(); slot_it != m_slot_to_id.end(); ++slot_it)
        {
            if (slot_it->second == id)
            {
                m_slot_to_id.erase(slot_it);
                break;
            }
        }

        score::mw::log::LogDebug() << kLogPrefix << "CleanupClient: removing cert " << id
                                   << " (ref_count reached 0 after client " << client_id << " cleanup)";
        m_certs.erase(id);
    }
}

std::size_t CertRegistry::Size() const
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    return m_certs.size();
}

}  // namespace score::crypto::daemon::cert_management
