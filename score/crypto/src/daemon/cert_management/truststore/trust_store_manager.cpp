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
#include "score/crypto/src/daemon/cert_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_writer.hpp"
#include "score/crypto/src/daemon/common/hex.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include "score/mw/log/logging.h"

#include <algorithm>

namespace score::crypto::daemon::cert_management
{
namespace
{
using Error = common::DaemonErrorCode;

std::optional<std::array<uint8_t, 32U>> CopyFingerprint(score::crypto::span<const uint8_t> fingerprint)
{
    if (fingerprint.size() != 32U)
        return std::nullopt;

    std::array<uint8_t, 32U> copy{};
    std::copy(fingerprint.begin(), fingerprint.end(), copy.begin());
    return copy;
}

}  // namespace

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

void TrustStoreManager::Load(const std::vector<TrustStoreConfig>& configs,
                             CertSlotRegistry::Sptr registry,
                             CertSlotHandlerFactory slot_handler_factory)
{
    std::lock_guard lock(m_mutex);
    m_stores.clear();
    m_name_index.clear();
    m_app_resource_map.clear();
    m_slot_memberships.clear();
    m_member_states.clear();
    m_slot_cert_cache.clear();
    m_client_ref_counts.clear();
    m_slot_registry = std::move(registry);
    m_slot_handler_factory = std::move(slot_handler_factory);
    m_slot_handlers.clear();  // lazy cache — populated by GetOrCreateHandler() on first access
    for (const auto& config : configs)
    {
        const TrustStoreId id = static_cast<TrustStoreId>(m_stores.size());
        // Loader lambda is called by TrustStoreHandler::EnsureLoaded() on the first
        // GetAnchors() — never at startup. 'this' is safe: the handler is owned by
        // TrustStoreManager and never outlives it.
        auto handler = std::make_shared<TrustStoreHandler>(TrustStoreHandle{id}, [this, id](TrustStoreHandler& h) {
            this->LoadAnchorsIntoHandler(id, h);
        });
        TrustStoreEntry entry{config, handler, id};
        m_stores.push_back(std::move(entry));
        m_name_index[config.store_name] = id;
        LoadState(id);  // reads m_member_states from descriptor — no cert I/O
        if (!m_slot_registry)
            continue;
        // Build reverse membership index; no cert bytes loaded here.
        for (const auto& member : config.members)
        {
            const auto slot = m_slot_registry->ResolveSlotInternal(member.slot_name);
            if (slot)
                m_slot_memberships[slot->index].push_back(id);
        }
    }
}

// ---------------------------------------------------------------------------
// State helpers (unchanged logic, no cert loading)
// ---------------------------------------------------------------------------

void TrustStoreManager::LoadState(TrustStoreId id)
{
    if (!m_slot_registry)
        return;
    if (id >= m_stores.size() || m_stores[id].config.deployment_path.empty())
        return;
    const auto descriptor =
        DeploymentLoader::Load(m_stores[id].config.deployment_path, m_stores[id].config.deployment_format);
    if (!descriptor)
        return;
    const auto section = descriptor->sections.find(std::string{cert_section_names::kTrustStoreState});
    if (section == descriptor->sections.end())
        return;
    for (const auto& member : m_stores[id].config.members)
    {
        const auto slot = m_slot_registry->ResolveSlotInternal(member.slot_name);
        if (!slot)
            continue;
        MemberState state;
        const auto prefix = std::string{"slot."} + member.slot_name + ".";
        const auto enabled = section->second.find(prefix + "enabled");
        if (enabled != section->second.end())
            state.enabled = enabled->second == "true";
        const auto fingerprint = section->second.find(prefix + "accepted_fingerprint");
        if (fingerprint != section->second.end())
        {
            const auto decoded = common::DecodeHex(fingerprint->second);
            if (decoded && decoded->size() == 32U)
            {
                std::array<uint8_t, 32U> accepted{};
                std::copy(decoded->begin(), decoded->end(), accepted.begin());
                state.accepted_fingerprint = accepted;
            }
        }
        m_member_states[id][slot->index] = state;
    }
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::PersistState(TrustStoreId id) const
{
    if (!m_slot_registry)
        return std::monostate{};
    if (id >= m_stores.size() || m_stores[id].config.deployment_path.empty())
        return std::monostate{};
    common::storage::DeploymentDescriptor descriptor;
    const auto existing =
        DeploymentLoader::Load(m_stores[id].config.deployment_path, m_stores[id].config.deployment_format);
    if (existing)
        descriptor = *existing;
    const auto states = m_member_states.find(id);
    if (states != m_member_states.end())
    {
        for (const auto& member : m_stores[id].config.members)
        {
            const auto slot = m_slot_registry->ResolveSlotInternal(member.slot_name);
            if (!slot)
                continue;
            const auto state_it = states->second.find(slot->index);
            if (state_it == states->second.end())
                continue;
            const auto& state = state_it->second;
            const auto prefix = std::string{"slot."} + member.slot_name + ".";
            descriptor.Set(std::string{cert_section_names::kTrustStoreState},
                           prefix + "enabled",
                           state.enabled ? "true" : "false");
            if (state.accepted_fingerprint.has_value())
                descriptor.Set(std::string{cert_section_names::kTrustStoreState},
                               prefix + "accepted_fingerprint",
                               common::EncodeHex(score::crypto::span<const uint8_t>{
                                   state.accepted_fingerprint->data(), state.accepted_fingerprint->size()}));
        }
    }
    return DeploymentWriter::Write(
        m_stores[id].config.deployment_path, m_stores[id].config.deployment_format, descriptor);
}

// ---------------------------------------------------------------------------
// Lazy anchor loading — called by TrustStoreHandler::EnsureLoaded()
// ---------------------------------------------------------------------------

ICertSlotHandler* TrustStoreManager::GetOrCreateHandler(CertSlotHandle slot)
{
    // Must be called with m_mutex held.
    auto it = m_slot_handlers.find(slot.index);
    if (it != m_slot_handlers.end())
        return it->second.get();

    if (!m_slot_handler_factory || !m_slot_registry)
        return nullptr;
    const auto cfg = m_slot_registry->GetConfig(slot);
    if (!cfg)
        return nullptr;
    auto handler = m_slot_handler_factory(**cfg);
    if (!handler)
        return nullptr;
    return m_slot_handlers.emplace(slot.index, std::move(handler)).first->second.get();
}

CertObject::Sptr TrustStoreManager::LoadOrGetCached(CertSlotHandle slot)
{
    // Must be called with m_mutex held.
    auto& weak = m_slot_cert_cache[slot.index];
    if (auto cert = weak.lock())
        return cert;  // another active trust store handler already holds it

    auto* handler = GetOrCreateHandler(slot);
    const auto cfg = m_slot_registry ? m_slot_registry->GetConfig(slot) : nullptr;
    if (!handler || !cfg)
        return nullptr;

    auto loaded = handler->LoadCertificate(**cfg);
    if (!loaded)
        return nullptr;

    weak = *loaded;  // cache as weak_ptr; expires when all handler caches drop their strong ref
    return std::move(*loaded);
}

void TrustStoreManager::LoadAnchorsIntoHandler(TrustStoreId id, TrustStoreHandler& handler)
{
    std::lock_guard lock(m_mutex);
    if (id >= m_stores.size() || !m_slot_registry)
        return;

    const auto& store = m_stores[id];
    for (const auto& member : store.config.members)
    {
        const auto slot = m_slot_registry->ResolveSlotInternal(member.slot_name);
        if (!slot)
            continue;

        auto& state = m_member_states[id][slot->index];
        if (!state.enabled)
        {
            handler.NotifySlotUpdate(*slot, nullptr);
            continue;
        }

        auto cert = LoadOrGetCached(*slot);
        if (!cert)
        {
            handler.NotifySlotUpdate(*slot, nullptr);
            continue;
        }

        bool usable = true;
        if (member.kind == TrustStoreMemberKind::kConditionalExternal)
        {
            const auto fingerprint = cert->GetFingerprint();
            if (state.accepted_fingerprint.has_value())
            {
                const bool unchanged =
                    fingerprint.size() == state.accepted_fingerprint->size() &&
                    std::equal(fingerprint.begin(), fingerprint.end(), state.accepted_fingerprint->begin());
                if (!unchanged)
                {
                    // Content changed without acknowledgement — disable for this store only.
                    state.enabled = false;
                    usable = false;
                    score::mw::log::LogWarn()
                        << kLogPrefix << "Conditional slot '" << member.slot_name << "' fingerprint mismatch in store '"
                        << store.config.store_name << "' — disabled until acknowledged";
                }
            }
            else if (store.config.conditional_slot_initialization ==
                     ConditionalSlotInitialization::kEnableAndAcceptCurrent)
            {
                state.accepted_fingerprint = CopyFingerprint(fingerprint);
            }
            else
            {
                usable = false;
            }
        }

        handler.NotifySlotUpdate(*slot, usable ? cert : nullptr);
    }
}

// ---------------------------------------------------------------------------
// Store access
// ---------------------------------------------------------------------------

ITrustStoreHandler::Sptr TrustStoreManager::GetStore(TrustStoreId id) const
{
    std::lock_guard lock(m_mutex);
    return id < m_stores.size() ? m_stores[id].handler : nullptr;
}

TrustStoreId TrustStoreManager::ResolveByName(const std::string& name) const
{
    std::lock_guard lock(m_mutex);
    const auto it = m_name_index.find(name);
    return it == m_name_index.end() ? UINT32_MAX : it->second;
}

void TrustStoreManager::RegisterAppResource(uint32_t uid,
                                            const std::string& app_resource_id,
                                            const std::string& store_name)
{
    std::lock_guard lock(m_mutex);
    m_app_resource_map[uid][app_resource_id] = store_name;
}

score::crypto::Expected<TrustStoreHandle, Error> TrustStoreManager::ResolveAppResource(
    const std::string& app_resource_id,
    data_manager::ClientId client_id) const
{
    std::lock_guard lock(m_mutex);
    const uint32_t uid = control_plane::protocol::GetUidFromClientId(client_id);
    const auto resources = m_app_resource_map.find(uid);
    if (resources == m_app_resource_map.end())
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    const auto resource = resources->second.find(app_resource_id);
    if (resource == resources->second.end())
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    const auto store = m_name_index.find(resource->second);
    if (store == m_name_index.end())
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    return TrustStoreHandle{store->second};
}

// ---------------------------------------------------------------------------
// Slot membership query
// ---------------------------------------------------------------------------

std::vector<TrustStoreId> TrustStoreManager::GetMembershipsForSlot(CertSlotHandle slot) const
{
    std::lock_guard lock(m_mutex);
    const auto it = m_slot_memberships.find(slot.index);
    return it == m_slot_memberships.end() ? std::vector<TrustStoreId>{} : it->second;
}

// ---------------------------------------------------------------------------
// Ref counting — verification context lifecycle (per-client scoped)
// ---------------------------------------------------------------------------

void TrustStoreManager::MaybeEvictAnchorCache(TrustStoreHandle handle)
{
    // Must be called with m_mutex held.
    for (const auto& [cid, stores] : m_client_ref_counts)
    {
        if (stores.count(handle.index))
            return;  // at least one client still active for this store
    }
    if (handle.index < m_stores.size())
    {
        auto* h = static_cast<TrustStoreHandler*>(m_stores[handle.index].handler.get());
        if (h)
            h->ClearAnchorCache();
    }
    score::mw::log::LogDebug() << kLogPrefix << "No active clients for store index " << handle.index
                               << " — anchor cache cleared";
}

void TrustStoreManager::AddRef(TrustStoreHandle handle, data_manager::ClientId client_id)
{
    std::lock_guard lock(m_mutex);
    ++m_client_ref_counts[client_id][handle.index];
}

void TrustStoreManager::ReleaseRef(TrustStoreHandle handle, data_manager::ClientId client_id)
{
    std::lock_guard lock(m_mutex);
    const auto client_it = m_client_ref_counts.find(client_id);
    if (client_it == m_client_ref_counts.end())
        return;
    auto& per_store = client_it->second;
    const auto store_it = per_store.find(handle.index);
    if (store_it == per_store.end() || store_it->second == 0U)
        return;
    if (--store_it->second == 0U)
    {
        per_store.erase(store_it);
        if (per_store.empty())
            m_client_ref_counts.erase(client_it);
        MaybeEvictAnchorCache(handle);
    }
}

void TrustStoreManager::CleanupClient(data_manager::ClientId client_id)
{
    std::lock_guard lock(m_mutex);
    const auto client_it = m_client_ref_counts.find(client_id);
    if (client_it == m_client_ref_counts.end())
        return;
    // Collect affected stores before erasing the client entry.
    std::vector<TrustStoreHandle> affected;
    affected.reserve(client_it->second.size());
    for (const auto& [store_id, count] : client_it->second)
        affected.push_back(TrustStoreHandle{store_id});
    m_client_ref_counts.erase(client_it);
    // Evict caches for stores that now have no remaining active clients.
    for (const auto& handle : affected)
        MaybeEvictAnchorCache(handle);
}

// ---------------------------------------------------------------------------
// Slot change notification
// ---------------------------------------------------------------------------

void TrustStoreManager::NotifySlotChanged(TrustStoreId id, CertSlotHandle changed_slot)
{
    std::lock_guard lock(m_mutex);
    if (id >= m_stores.size())
        return;
    // Evict the changed slot from the shared cache so LoadOrGetCached does fresh I/O.
    m_slot_cert_cache.erase(changed_slot.index);
    // Tell the handler to drop just this slot and mark itself for reload.
    auto* h = static_cast<TrustStoreHandler*>(m_stores[id].handler.get());
    if (h)
        h->InvalidateSlot(changed_slot);
}

// ---------------------------------------------------------------------------
// Mutation operations
// ---------------------------------------------------------------------------

std::optional<TrustStoreManager::ResolvedMember> TrustStoreManager::ResolveMember(const TrustStoreMemberConfig& member)
{
    if (!m_slot_registry)
        return std::nullopt;
    const auto slot = m_slot_registry->ResolveSlotInternal(member.slot_name);
    if (!slot)
        return std::nullopt;
    const auto cfg = m_slot_registry->GetConfig(*slot);
    if (!cfg)
        return std::nullopt;
    auto* handler = GetOrCreateHandler(*slot);
    if (!handler)
        return std::nullopt;
    return ResolvedMember{*slot, handler, *cfg};
}

score::crypto::Expected<TrustStoreManager::ResolvedBackend, Error> TrustStoreManager::ResolveSlotBackend(
    CertSlotHandle slot)
{
    if (!m_slot_registry)
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    const auto cfg = m_slot_registry->GetConfig(slot);
    if (!cfg)
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    auto* handler = GetOrCreateHandler(slot);
    if (!handler)
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    return ResolvedBackend{*cfg, handler};
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::AddMember(TrustStoreId id,
                                                                            CertObject::Sptr cert,
                                                                            data_manager::ClientId client_id)
{
    std::lock_guard lock(m_mutex);
    if (id >= m_stores.size() || !cert)
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(m_stores[id].config, client_id).has_value())
        return score::crypto::make_unexpected(Error::kAccessDenied);
    for (const auto& member : m_stores[id].config.members)
    {
        if (member.kind != TrustStoreMemberKind::kExclusiveMutable)
            continue;
        const auto resolved = ResolveMember(member);
        if (!resolved)
            continue;
        const auto current = resolved->handler->LoadCertificate(*resolved->cfg);
        if (current)
        {
            const auto& current_fp = (*current)->GetFingerprint();
            const auto& cert_fp = cert->GetFingerprint();
            if (current_fp.size() != cert_fp.size() ||
                !std::equal(current_fp.begin(), current_fp.end(), cert_fp.begin()))
                continue;  // Slot occupied by a different cert — try the next exclusive slot.
            // Idempotent: cert already stored — re-enable and refresh cache.
            m_member_states[id][resolved->slot.index].enabled = true;
            m_slot_cert_cache[resolved->slot.index] = cert;
            static_cast<TrustStoreHandler*>(m_stores[id].handler.get())->NotifySlotUpdate(resolved->slot, cert);
            if (const auto persisted = PersistState(id); !persisted)
                return score::crypto::make_unexpected(persisted.error());
            return std::monostate{};
        }
        // Empty slot — store cert here.
        const auto stored = resolved->handler->StoreCertificate(*resolved->cfg, *cert);
        if (!stored)
            return score::crypto::make_unexpected(stored.error());
        m_member_states[id][resolved->slot.index].enabled = true;
        m_slot_cert_cache[resolved->slot.index] = cert;
        static_cast<TrustStoreHandler*>(m_stores[id].handler.get())->NotifySlotUpdate(resolved->slot, cert);
        if (const auto persisted = PersistState(id); !persisted)
            return score::crypto::make_unexpected(persisted.error());
        return std::monostate{};
    }
    return score::crypto::make_unexpected(Error::kTrustStoreCapacityExceeded);
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::RemoveMember(TrustStoreId id,
                                                                               const std::vector<uint8_t>& fingerprint,
                                                                               data_manager::ClientId client_id)
{
    std::lock_guard lock(m_mutex);
    if (id >= m_stores.size())
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(m_stores[id].config, client_id).has_value())
        return score::crypto::make_unexpected(Error::kAccessDenied);
    for (const auto& member : m_stores[id].config.members)
    {
        if (member.kind != TrustStoreMemberKind::kExclusiveMutable)
            continue;
        const auto resolved = ResolveMember(member);
        if (!resolved)
            continue;
        const auto current = resolved->handler->LoadCertificate(*resolved->cfg);
        if (!current)
            continue;
        const auto& current_fp = (*current)->GetFingerprint();
        if (current_fp.size() != fingerprint.size() ||
            !std::equal(current_fp.begin(), current_fp.end(), fingerprint.begin()))
            continue;
        if (const auto cleared = resolved->handler->ClearSlot(*resolved->cfg); !cleared)
            return score::crypto::make_unexpected(cleared.error());
        // Cert bytes gone — evict from shared cache and clear from handler.
        m_slot_cert_cache.erase(resolved->slot.index);
        m_member_states[id][resolved->slot.index].enabled = false;
        static_cast<TrustStoreHandler*>(m_stores[id].handler.get())->NotifySlotUpdate(resolved->slot, nullptr);
        if (const auto persisted = PersistState(id); !persisted)
            return score::crypto::make_unexpected(persisted.error());
        return std::monostate{};
    }
    return score::crypto::make_unexpected(Error::kInvalidArgument);
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::EnableMember(TrustStoreId id,
                                                                               CertSlotHandle slot,
                                                                               data_manager::ClientId client_id)
{
    std::lock_guard lock(m_mutex);
    if (id >= m_stores.size() || !slot.IsValid())
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(m_stores[id].config, client_id).has_value())
        return score::crypto::make_unexpected(Error::kAccessDenied);
    // Load via shared cache so other stores benefit from the strong ref.
    auto cert = LoadOrGetCached(slot);
    m_member_states[id][slot.index].enabled = true;
    static_cast<TrustStoreHandler*>(m_stores[id].handler.get())->NotifySlotUpdate(slot, std::move(cert));
    if (const auto persisted = PersistState(id); !persisted)
        return score::crypto::make_unexpected(persisted.error());
    return std::monostate{};
}

score::crypto::Expected<std::monostate, Error> TrustStoreManager::DisableMember(TrustStoreId id,
                                                                                CertSlotHandle slot,
                                                                                data_manager::ClientId client_id)
{
    std::lock_guard lock(m_mutex);
    if (id >= m_stores.size() || !slot.IsValid())
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(m_stores[id].config, client_id).has_value())
        return score::crypto::make_unexpected(Error::kAccessDenied);
    m_member_states[id][slot.index].enabled = false;
    static_cast<TrustStoreHandler*>(m_stores[id].handler.get())->NotifySlotUpdate(slot, nullptr);
    if (const auto persisted = PersistState(id); !persisted)
        return score::crypto::make_unexpected(persisted.error());
    return std::monostate{};
}

score::crypto::Expected<std::monostate, Error>
TrustStoreManager::AcknowledgeMemberUpdate(TrustStoreId id, CertSlotHandle slot, data_manager::ClientId client_id)
{
    std::lock_guard lock(m_mutex);
    if (id >= m_stores.size() || !slot.IsValid())
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    if (!AccessPolicyEnforcer::CheckTrustStoreWritePermission(m_stores[id].config, client_id).has_value())
        return score::crypto::make_unexpected(Error::kAccessDenied);
    // Fresh load to capture the new cert and update the shared cache.
    const auto resolved = ResolveSlotBackend(slot);
    if (!resolved)
        return score::crypto::make_unexpected(resolved.error());
    auto loaded = resolved->handler->LoadCertificate(*resolved->cfg);
    if (!loaded)
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    auto cert = std::move(*loaded);
    m_slot_cert_cache[slot.index] = cert;
    auto& state = m_member_states[id][slot.index];
    state.accepted_fingerprint = CopyFingerprint(cert->GetFingerprint());
    state.enabled = true;
    static_cast<TrustStoreHandler*>(m_stores[id].handler.get())->NotifySlotUpdate(slot, cert);
    if (const auto persisted = PersistState(id); !persisted)
        return score::crypto::make_unexpected(persisted.error());
    return std::monostate{};
}

const TrustStoreConfig* TrustStoreManager::GetStoreConfig(TrustStoreId id) const
{
    std::lock_guard lock(m_mutex);
    return id < m_stores.size() ? &m_stores[id].config : nullptr;
}

}  // namespace score::crypto::daemon::cert_management
