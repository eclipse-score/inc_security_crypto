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
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include "score/mw/log/logging.h"

#include <algorithm>
#include <string>
#include <unordered_set>

namespace score::crypto::daemon::cert_management
{
namespace
{
using Error = common::DaemonErrorCode;
}  // namespace

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

score::crypto::Expected<std::monostate, Error> TrustStoreManager::Load(const std::vector<TrustStoreConfig>& configs,
                                                                       CertSlotRegistry::Sptr registry,
                                                                       CertSlotManager::Sptr slot_manager)
{
    // Check the whole configuration before changing any state, so a rejected configuration
    // leaves the manager as it was.
    std::unordered_set<std::string> names;
    for (const auto& config : configs)
    {
        if (config.store_name.empty() || !names.insert(config.store_name).second)
        {
            score::mw::log::LogError() << kLogPrefix << "Trust store configuration has an empty or duplicate store name"
                                       << std::string{config.store_name.empty() ? "" : ": "} << config.store_name;
            return score::crypto::make_unexpected(Error::kInvalidArgument);
        }
    }

    m_stores.clear();
    m_name_index.clear();
    m_app_resource_map.clear();
    m_slot_memberships.clear();
    m_client_ref_counts.clear();
    for (const auto& config : configs)
    {
        const TrustStoreId id = static_cast<TrustStoreId>(m_stores.size());
        // The handler validates its members and reads its persisted member state here; no cert I/O
        // happens until the first AddRef().
        m_stores.push_back(std::make_shared<TrustStoreHandler>(TrustStoreHandle{id}, config, registry, slot_manager));
        m_name_index[config.store_name] = id;
        if (!registry)
        {
            continue;
        }
        // Build reverse membership index; no cert bytes loaded here.
        for (const auto& member : config.members)
        {
            const auto slot = registry->ResolveSlotInternal(member.slot_name);
            if (!slot.has_value())
            {
                // The store reports this member itself: its constructor marks the store invalid, so it
                // never needs change notifications. Returning an error here would stop every other store.
                continue;
            }
            auto& stores = m_slot_memberships[slot.value().index];
            if (std::find(stores.begin(), stores.end(), id) == stores.end())
            {
                stores.push_back(id);
            }
        }
    }
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Store access
// ---------------------------------------------------------------------------

std::shared_ptr<TrustStoreHandler> TrustStoreManager::FindStore(TrustStoreHandle handle) const
{
    if (!handle.IsValid() || handle.index >= m_stores.size())
    {
        return nullptr;
    }
    return m_stores[handle.index];
}

ITrustStoreHandler::Sptr TrustStoreManager::GetStore(TrustStoreHandle handle) const
{
    return FindStore(handle);
}

score::crypto::Expected<TrustStoreHandle, Error> TrustStoreManager::ResolveByName(const std::string& name) const
{
    const auto it = m_name_index.find(name);
    if (it == m_name_index.end())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    return TrustStoreHandle{it->second};
}

void TrustStoreManager::RegisterAppResource(uint32_t uid,
                                            const std::string& app_resource_id,
                                            const std::string& store_name)
{
    m_app_resource_map[uid][app_resource_id] = store_name;
}

score::crypto::Expected<TrustStoreHandle, Error> TrustStoreManager::ResolveAppResource(
    const std::string& app_resource_id,
    data_manager::ClientId client_id) const
{
    const uint32_t uid = control_plane::protocol::GetUidFromClientId(client_id);
    const auto resources = m_app_resource_map.find(uid);
    if (resources == m_app_resource_map.end())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    const auto resource = resources->second.find(app_resource_id);
    if (resource == resources->second.end())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    const auto store = m_name_index.find(resource->second);
    if (store == m_name_index.end())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    // A store that cannot be used is reported at resolution, so the client learns about it before
    // it creates a context on top of the store.
    if (!m_stores[store->second]->IsValid())
    {
        return score::crypto::make_unexpected(Error::kTrustStoreInvalid);
    }
    return TrustStoreHandle{store->second};
}

const TrustStoreConfig* TrustStoreManager::GetStoreConfig(TrustStoreHandle handle) const
{
    return handle.index < m_stores.size() ? &m_stores[handle.index]->GetConfig() : nullptr;
}

// ---------------------------------------------------------------------------
// Slot membership query
// ---------------------------------------------------------------------------

std::vector<TrustStoreHandle> TrustStoreManager::GetMembershipsForSlot(CertSlotHandle slot) const
{
    const auto it = m_slot_memberships.find(slot.index);
    if (it == m_slot_memberships.end())
    {
        return {};
    }
    std::vector<TrustStoreHandle> result;
    result.reserve(it->second.size());
    for (const auto id : it->second)
    {
        result.push_back(TrustStoreHandle{id});
    }
    return result;
}

// ---------------------------------------------------------------------------
// Ref counting — verification context lifecycle (per-client scoped)
// ---------------------------------------------------------------------------

void TrustStoreManager::MaybeEvictAnchorCache(TrustStoreHandle handle)
{
    // Must be called with m_mutex held.
    for (const auto& [cid, stores] : m_client_ref_counts)
    {
        if (stores.count(handle.index) != 0U)
        {
            return;  // at least one client still active for this store
        }
    }
    if (handle.index < m_stores.size())
    {
        m_stores[handle.index]->ClearCache();
    }
    score::mw::log::LogDebug() << kLogPrefix << "No active clients for store index " << handle.index
                               << " — anchor cache cleared";
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::AddRef(TrustStoreHandle handle,
                                                                         data_manager::ClientId client_id)
{
    const auto store = FindStore(handle);
    if (!store)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    {
        std::lock_guard lock(m_mutex);
        ++m_client_ref_counts[client_id][handle.index];
    }

    // The cache is built outside the registry mutex because it reads slots. LoadCache() does nothing
    // when the store is already warm, so a bind by a further client is cheap.
    const auto loaded = store->LoadCache();
    if (!loaded.has_value())
    {
        // A failed bind must not leave a reference behind. ReleaseRef() also clears the cache
        // when no other client holds the store.
        ReleaseRef(handle, client_id);
        return score::crypto::make_unexpected(loaded.error());
    }
    return std::monostate{};
}

void TrustStoreManager::ReleaseRef(TrustStoreHandle handle, data_manager::ClientId client_id)
{
    std::lock_guard lock(m_mutex);
    const auto client_it = m_client_ref_counts.find(client_id);
    if (client_it == m_client_ref_counts.end())
    {
        return;
    }
    auto& per_store = client_it->second;
    const auto store_it = per_store.find(handle.index);
    if (store_it == per_store.end() || store_it->second == 0U)
    {
        return;
    }
    if (--store_it->second == 0U)
    {
        per_store.erase(store_it);
        if (per_store.empty())
        {
            m_client_ref_counts.erase(client_it);
        }
        MaybeEvictAnchorCache(handle);
    }
}

void TrustStoreManager::CleanupClient(data_manager::ClientId client_id)
{
    std::lock_guard lock(m_mutex);
    const auto client_it = m_client_ref_counts.find(client_id);
    if (client_it == m_client_ref_counts.end())
    {
        return;
    }
    // Collect affected stores before erasing the client entry.
    std::vector<TrustStoreHandle> affected;
    affected.reserve(client_it->second.size());
    for (const auto& [store_id, count] : client_it->second)
    {
        affected.push_back(TrustStoreHandle{store_id});
    }
    m_client_ref_counts.erase(client_it);
    // Evict caches for stores that now have no remaining active clients.
    for (const auto& handle : affected)
    {
        MaybeEvictAnchorCache(handle);
    }
}

// ---------------------------------------------------------------------------
// Slot change notification
// ---------------------------------------------------------------------------

void TrustStoreManager::NotifySlotChanged(CertSlotHandle changed_slot)
{
    for (const auto handle : GetMembershipsForSlot(changed_slot))
    {
        if (const auto store = FindStore(handle))
        {
            store->OnSlotChanged(changed_slot);
        }
    }
}

void TrustStoreManager::NotifySlotCrlChanged(CertSlotHandle changed_slot)
{
    for (const auto handle : GetMembershipsForSlot(changed_slot))
    {
        if (const auto store = FindStore(handle))
        {
            store->OnSlotCrlChanged(changed_slot);
        }
    }
}

// ---------------------------------------------------------------------------
// Mutation operations — write access is checked here, the work is done by the handler
// ---------------------------------------------------------------------------

score::crypto::Expected<std::monostate, Error> TrustStoreManager::AddMember(TrustStoreHandle handle,
                                                                            CertObject::Sptr cert,
                                                                            data_manager::ClientId client_id,
                                                                            CrlData::Sptrc crl)
{
    const auto store = FindStore(handle);
    if (!store || !cert)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(store->GetConfig(), client_id).has_value())
    {
        return score::crypto::make_unexpected(Error::kAccessDenied);
    }
    return store->AddMember(cert, std::move(crl));
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::StoreCrlForMember(TrustStoreHandle handle,
                                                                                    CertSlotHandle slot,
                                                                                    const CrlData& crl,
                                                                                    data_manager::ClientId client_id)
{
    const auto store = FindStore(handle);
    if (!store || !slot.IsValid())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    if (crl.bytes.empty())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(store->GetConfig(), client_id).has_value())
    {
        return score::crypto::make_unexpected(Error::kAccessDenied);
    }
    return store->StoreCrlForMember(slot, crl);
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::ClearCrlForMember(TrustStoreHandle handle,
                                                                                    CertSlotHandle slot,
                                                                                    data_manager::ClientId client_id)
{
    const auto store = FindStore(handle);
    if (!store || !slot.IsValid())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(store->GetConfig(), client_id).has_value())
    {
        return score::crypto::make_unexpected(Error::kAccessDenied);
    }
    return store->ClearCrlForMember(slot);
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::RemoveMember(TrustStoreHandle handle,
                                                                               const std::vector<uint8_t>& fingerprint,
                                                                               data_manager::ClientId client_id)
{
    const auto store = FindStore(handle);
    if (!store)
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(store->GetConfig(), client_id).has_value())
    {
        return score::crypto::make_unexpected(Error::kAccessDenied);
    }
    return store->RemoveMember(fingerprint);
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::EnableMember(TrustStoreHandle handle,
                                                                               CertSlotHandle slot,
                                                                               data_manager::ClientId client_id)
{
    const auto store = FindStore(handle);
    if (!store || !slot.IsValid())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(store->GetConfig(), client_id).has_value())
    {
        return score::crypto::make_unexpected(Error::kAccessDenied);
    }
    return store->EnableMember(slot);
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::DisableMember(TrustStoreHandle handle,
                                                                                CertSlotHandle slot,
                                                                                data_manager::ClientId client_id)
{
    const auto store = FindStore(handle);
    if (!store || !slot.IsValid())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(store->GetConfig(), client_id).has_value())
    {
        return score::crypto::make_unexpected(Error::kAccessDenied);
    }
    return store->DisableMember(slot);
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::AcknowledgeMemberUpdate(
    TrustStoreHandle handle,
    CertSlotHandle slot,
    score::crypto::span<const uint8_t> expected_sha256_fingerprint,
    data_manager::ClientId client_id)
{
    const auto store = FindStore(handle);
    if (!store || !slot.IsValid())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(store->GetConfig(), client_id).has_value())
    {
        return score::crypto::make_unexpected(Error::kAccessDenied);
    }
    return store->AcknowledgeMemberUpdate(slot, expected_sha256_fingerprint);
}

// ---------------------------------------------------------------------------
// Member inspection (for ITrustStoreObject read-only view)
// ---------------------------------------------------------------------------

score::crypto::Expected<std::vector<CertSlotHandle>, common::DaemonErrorCode> TrustStoreManager::GetMemberSlotHandles(
    TrustStoreHandle handle)
{
    const auto store = FindStore(handle);
    if (!store)
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    return store->GetMemberSlotHandles();
}

score::crypto::Expected<TrustStoreManager::MemberSnapshot, common::DaemonErrorCode>
TrustStoreManager::GetMemberSnapshot(TrustStoreHandle handle, CertSlotHandle slot)
{
    const auto store = FindStore(handle);
    if (!store)
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    return store->GetMemberSnapshot(slot);
}

}  // namespace score::crypto::daemon::cert_management
