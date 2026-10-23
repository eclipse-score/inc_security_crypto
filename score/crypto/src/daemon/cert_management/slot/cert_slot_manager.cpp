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

#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/mw/log/logging.h"

namespace score::crypto::daemon::cert_management
{

using Error = common::DaemonErrorCode;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

CertSlotManager::CertSlotManager(CertSlotRegistry::Sptr registry, CertSlotHandlerFactory factory)
    : m_registry{std::move(registry)}, m_factory{std::move(factory)}
{
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

score::crypto::Expected<std::reference_wrapper<const CertSlotConfig>, Error> CertSlotManager::GetConfig(
    CertSlotHandle slot) const
{
    if (!m_registry)
        return score::crypto::make_unexpected(Error::kInternalError);
    const auto cfg = m_registry->GetConfig(slot);
    if (!cfg.has_value())
        return score::crypto::make_unexpected(cfg.error());
    return cfg.value();
}

score::crypto::Expected<std::monostate, Error> CertSlotManager::ApplyWriteChecks(const CertSlotConfig& cfg,
                                                                                 data_manager::ClientId client_id)
{
    auto write_check = AccessPolicyEnforcer::CheckWritePermission(cfg, client_id);
    if (!write_check.has_value())
        return write_check;

    // TODO(cert-slot-mgr): exclusive-slot guard — return kAccessDenied when the slot
    // is a kExclusiveMutable member of any trust store. Requires a membership query
    // callback to avoid a circular dependency with TrustStoreManager. Until this
    // lands, correctness relies on a configuration invariant documented on
    // AccessPolicy::allowed_write_uids (access_policy.hpp) and in design_decisions.rst.

    return std::monostate{};
}

ICertSlotHandler::Sptr CertSlotManager::GetOrCreate(CertSlotHandle slot)
{
    // Must be called with m_mutex held.
    const auto it = m_handlers.find(slot.index);
    if (it != m_handlers.end())
        return it->second;

    if (!m_factory || !m_registry)
        return nullptr;
    const auto cfg = m_registry->GetConfig(slot);
    if (!cfg.has_value())
        return nullptr;
    auto handler = m_factory(cfg.value().get());
    if (!handler)
        return nullptr;
    return m_handlers.emplace(slot.index, std::move(handler)).first->second;
}

// ---------------------------------------------------------------------------
// Tier 3 — trust-store backend (friend-gated, no auth check)
// ---------------------------------------------------------------------------

ICertSlotHandler::Sptr CertSlotManager::GetTrustStoreCertSlotHandler(CertSlotHandle slot)
{
    std::lock_guard lock(m_mutex);
    return GetOrCreate(slot);
}

// ---------------------------------------------------------------------------
// Tier 2 — provider extension escape hatch
// ---------------------------------------------------------------------------

score::crypto::Expected<ICertSlotHandler::Sptr, Error>
CertSlotManager::GetProviderCertSlotHandler(CertSlotHandle slot, data_manager::ClientId client_id, bool require_write)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = cfg_res.value().get();

    auto access_check = AccessPolicyEnforcer::CheckSlotAccess(cfg, client_id);
    if (!access_check.has_value())
        return score::crypto::make_unexpected(access_check.error());

    if (require_write)
    {
        auto write_res = ApplyWriteChecks(cfg, client_id);
        if (!write_res.has_value())
            return score::crypto::make_unexpected(write_res.error());
    }

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        handler = GetOrCreate(slot);
    }
    if (!handler)
    {
        score::mw::log::LogError() << kLogPrefix << "GetProviderCertSlotHandler: no handler for slot " << slot.index;
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    return handler;
}

// ---------------------------------------------------------------------------
// Tier 1 — reads
// ---------------------------------------------------------------------------

score::crypto::Expected<CertObject::Sptr, Error> CertSlotManager::LoadCertificate(CertSlotHandle slot,
                                                                                  data_manager::ClientId client_id)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = cfg_res.value().get();

    auto access_check = AccessPolicyEnforcer::CheckSlotAccess(cfg, client_id);
    if (!access_check.has_value())
        return score::crypto::make_unexpected(access_check.error());

    return LoadCertificateCached(slot, cfg);
}

score::crypto::Expected<CertObject::Sptr, Error> CertSlotManager::LoadCertificateForTrustStore(CertSlotHandle slot)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    return LoadCertificateCached(slot, cfg_res.value().get());
}

score::crypto::Expected<CertObject::Sptr, Error> CertSlotManager::LoadCertificateCached(CertSlotHandle slot,
                                                                                        const CertSlotConfig& cfg)
{
    ICertSlotHandler::Sptr handler;
    uint64_t generation{};
    {
        std::lock_guard lock(m_mutex);
        const auto& cache = m_slot_cache[slot.index];
        // Serve the parsed certificate while any holder keeps it alive, so concurrent clients
        // opening the same slot share one parse.
        if (auto cached = cache.certificate.lock())
            return cached;
        handler = GetOrCreate(slot);
        generation = cache.certificate_generation;
    }
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);

    auto cert_obj = handler->LoadCertificate(cfg);
    if (!cert_obj.has_value())
        return cert_obj;

    {
        std::lock_guard lock(m_mutex);
        auto& cache = m_slot_cache[slot.index];
        if (cache.certificate_generation == generation)
            cache.certificate = cert_obj.value();
    }
    return cert_obj;
}

score::crypto::Expected<score::crypto::CertificateSlotInfo, Error> CertSlotManager::GetSlotInfo(
    CertSlotHandle slot,
    data_manager::ClientId client_id)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = cfg_res.value().get();

    auto access_check = AccessPolicyEnforcer::CheckSlotAccess(cfg, client_id);
    if (!access_check.has_value())
        return score::crypto::make_unexpected(access_check.error());

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        handler = GetOrCreate(slot);
    }
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);
    return handler->GetSlotInfo(cfg);
}

score::crypto::Expected<bool, Error> CertSlotManager::HasCrl(CertSlotHandle slot, data_manager::ClientId client_id)
{
    const auto state = GetCrlStateChecked(slot, client_id);
    if (!state.has_value())
        return score::crypto::make_unexpected(state.error());
    return state->has_crl;
}

score::crypto::Expected<std::optional<score::crypto::CrlMetadata>, Error> CertSlotManager::GetCrlMetadata(
    CertSlotHandle slot,
    data_manager::ClientId client_id)
{
    const auto state = GetCrlStateChecked(slot, client_id);
    if (!state.has_value())
        return score::crypto::make_unexpected(state.error());
    return state->metadata;
}

score::crypto::Expected<CrlData::Sptrc, Error> CertSlotManager::LoadCrlData(CertSlotHandle slot,
                                                                            data_manager::ClientId client_id)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = cfg_res.value().get();

    auto access_check = AccessPolicyEnforcer::CheckSlotAccess(cfg, client_id);
    if (!access_check.has_value())
        return score::crypto::make_unexpected(access_check.error());

    return GetOrLoadCrlData(slot, cfg);
}

score::crypto::Expected<CrlData::Sptrc, Error> CertSlotManager::LoadCrlDataForTrustStore(CertSlotHandle slot)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    return GetOrLoadCrlData(slot, cfg_res.value().get());
}

score::crypto::Expected<CertSlotManager::CrlState, Error> CertSlotManager::GetCrlStateChecked(
    CertSlotHandle slot,
    data_manager::ClientId client_id)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());

    const CertSlotConfig& cfg = cfg_res.value().get();
    auto access_check = AccessPolicyEnforcer::CheckSlotAccess(cfg, client_id);
    if (!access_check.has_value())
        return score::crypto::make_unexpected(access_check.error());

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        handler = GetOrCreate(slot);
    }
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);
    return GetOrLoadCrlState(slot, handler, cfg);
}

score::crypto::Expected<int64_t, Error> CertSlotManager::GetCrlNextUpdate(CertSlotHandle slot,
                                                                          data_manager::ClientId client_id)
{
    const auto state = GetCrlStateChecked(slot, client_id);
    if (!state.has_value())
        return score::crypto::make_unexpected(state.error());
    // Collapses "no CRL" and "CRL present but no usable metadata" into one code:
    // neither case gives the caller a usable next-update value.
    if (!state->metadata.has_value())
        return score::crypto::make_unexpected(Error::kResourceNotAllocated);
    return state->metadata->next_update;
}

// ---------------------------------------------------------------------------
// Tier 1 — writes
// ---------------------------------------------------------------------------

score::crypto::Expected<std::monostate, Error> CertSlotManager::StoreCertificate(CertSlotHandle slot,
                                                                                 data_manager::ClientId client_id,
                                                                                 const CertObject& cert,
                                                                                 bool* content_may_have_changed)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = cfg_res.value().get();

    auto write_res = ApplyWriteChecks(cfg, client_id);
    if (!write_res.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "StoreCertificate: write access denied for slot " << slot.index;
        return write_res;
    }

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        handler = GetOrCreate(slot);
    }
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);

    if (content_may_have_changed != nullptr)
        *content_may_have_changed = true;
    auto result = handler->StoreCertificate(cfg, cert);
    // A failed write can still have changed what is stored, so the caches are dropped either way.
    InvalidateSlotCaches(slot);
    return result;
}

score::crypto::Expected<std::monostate, Error> CertSlotManager::ClearSlot(CertSlotHandle slot,
                                                                          data_manager::ClientId client_id,
                                                                          bool* content_may_have_changed)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = cfg_res.value().get();

    auto write_res = ApplyWriteChecks(cfg, client_id);
    if (!write_res.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "ClearSlot: write access denied for slot " << slot.index;
        return write_res;
    }

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        handler = GetOrCreate(slot);
    }
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);

    if (content_may_have_changed != nullptr)
        *content_may_have_changed = true;
    auto result = handler->ClearSlot(cfg);
    // A failed write can still have changed what is stored, so the caches are dropped either way.
    InvalidateSlotCaches(slot);
    return result;
}

void CertSlotManager::InvalidateSlotCaches(CertSlotHandle slot)
{
    std::lock_guard lock(m_mutex);
    auto& cache = m_slot_cache[slot.index];
    cache.ResetCertificate();
    cache.ResetCrl();
}

score::crypto::Expected<CertSlotManager::CrlState, Error> CertSlotManager::GetOrLoadCrlState(
    CertSlotHandle slot,
    const ICertSlotHandler::Sptr& handler,
    const CertSlotConfig& cfg)
{
    uint64_t generation{};
    {
        std::lock_guard lock(m_mutex);
        const auto& cache = m_slot_cache[slot.index];
        if (cache.crl_state.has_value())
            return *cache.crl_state;
        generation = cache.crl_generation;
    }

    CrlState state;
    const auto has_crl = handler->HasCrl(cfg);
    if (!has_crl.has_value())
        return score::crypto::make_unexpected(has_crl.error());
    state.has_crl = has_crl.value();
    if (state.has_crl)
    {
        auto metadata = handler->GetCrlMetadata(cfg);
        if (!metadata.has_value())
            return score::crypto::make_unexpected(metadata.error());
        state.metadata = std::move(metadata.value());
    }

    {
        std::lock_guard lock(m_mutex);
        auto& cache = m_slot_cache[slot.index];
        if (cache.crl_generation == generation)
            cache.crl_state = state;
    }
    return state;
}

score::crypto::Expected<CrlData::Sptrc, Error> CertSlotManager::GetOrLoadCrlData(CertSlotHandle slot,
                                                                                 const CertSlotConfig& cfg)
{
    ICertSlotHandler::Sptr handler;
    uint64_t generation{};
    {
        std::lock_guard lock(m_mutex);
        const auto& cache = m_slot_cache[slot.index];
        // A cached absence needs no read; a live snapshot is shared with its holders.
        if (cache.crl_state.has_value() && !cache.crl_state->has_crl)
            return CrlData::Sptrc{};
        if (auto cached = cache.crl_snapshot.lock())
            return cached;
        handler = GetOrCreate(slot);
        generation = cache.crl_generation;
    }
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);

    auto loaded = handler->LoadCrlData(cfg);
    if (!loaded.has_value())
        return score::crypto::make_unexpected(loaded.error());

    CrlData::Sptrc snapshot;
    CrlState state;
    if (loaded.value().has_value())
    {
        snapshot = std::make_shared<const CrlData>(std::move(*loaded.value()));
        state.has_crl = true;
        state.metadata = snapshot->metadata;
    }

    {
        std::lock_guard lock(m_mutex);
        auto& cache = m_slot_cache[slot.index];
        if (cache.crl_generation == generation)
        {
            cache.crl_state = state;
            cache.crl_snapshot = snapshot;
        }
    }
    return snapshot;
}

void CertSlotManager::InvalidateCrl(CertSlotHandle slot)
{
    std::lock_guard lock(m_mutex);
    m_slot_cache[slot.index].ResetCrl();
}

score::crypto::Expected<std::monostate, Error> CertSlotManager::StoreCrl(CertSlotHandle slot,
                                                                         data_manager::ClientId client_id,
                                                                         const CrlData& crl,
                                                                         bool* content_may_have_changed)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = cfg_res.value().get();

    auto write_res = ApplyWriteChecks(cfg, client_id);
    if (!write_res.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "StoreCrl: write access denied for slot " << slot.index;
        return write_res;
    }

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        handler = GetOrCreate(slot);
    }
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);
    if (content_may_have_changed != nullptr)
        *content_may_have_changed = true;
    auto result = handler->StoreCrl(cfg, crl);
    // A failed write can still have changed what is stored, so the caches are dropped either way.
    InvalidateCrl(slot);
    return result;
}

score::crypto::Expected<std::monostate, Error> CertSlotManager::ClearCrl(CertSlotHandle slot,
                                                                         data_manager::ClientId client_id,
                                                                         bool* content_may_have_changed)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = cfg_res.value().get();

    auto write_res = ApplyWriteChecks(cfg, client_id);
    if (!write_res.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "ClearCrl: write access denied for slot " << slot.index;
        return write_res;
    }

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        handler = GetOrCreate(slot);
    }
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);
    if (content_may_have_changed != nullptr)
        *content_may_have_changed = true;
    auto result = handler->ClearCrl(cfg);
    // A failed write can still have changed what is stored, so the caches are dropped either way.
    InvalidateCrl(slot);
    return result;
}

}  // namespace score::crypto::daemon::cert_management
