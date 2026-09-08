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

score::crypto::Expected<const CertSlotConfig*, Error> CertSlotManager::GetConfig(CertSlotHandle slot) const
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
    // callback to avoid a circular dependency with TrustStoreManager.

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
    auto handler = m_factory(*cfg.value());
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
    const CertSlotConfig& cfg = *cfg_res.value();

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
    const CertSlotConfig& cfg = *cfg_res.value();

    auto access_check = AccessPolicyEnforcer::CheckSlotAccess(cfg, client_id);
    if (!access_check.has_value())
        return score::crypto::make_unexpected(access_check.error());

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        // Return cached CertObject if a strong ref is still alive — avoids disk re-read
        // when multiple clients open the same slot cert concurrently.
        const auto cache_it = m_cert_object_cache.find(slot.index);
        if (cache_it != m_cert_object_cache.end())
        {
            auto cached = cache_it->second.lock();
            if (cached)
                return cached;
            m_cert_object_cache.erase(cache_it);
        }
        handler = GetOrCreate(slot);
    }
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);

    auto cert_obj = handler->LoadCertificate(cfg);
    if (!cert_obj.has_value())
        return cert_obj;

    {
        std::lock_guard lock(m_mutex);
        m_cert_object_cache[slot.index] = cert_obj.value();
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
    const CertSlotConfig& cfg = *cfg_res.value();

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

bool CertSlotManager::HasCrl(CertSlotHandle slot)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return false;

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        handler = GetOrCreate(slot);
    }
    if (!handler)
        return false;
    return handler->HasCrl(*cfg_res.value());
}

score::crypto::Expected<std::vector<uint8_t>, Error> CertSlotManager::LoadCrl(CertSlotHandle slot,
                                                                              data_manager::ClientId client_id)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = *cfg_res.value();

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
    return handler->LoadCrl(cfg);
}

score::crypto::FormatType CertSlotManager::GetCrlFormat(CertSlotHandle slot)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::FormatType::kDer;

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        handler = GetOrCreate(slot);
    }
    if (!handler)
        return score::crypto::FormatType::kDer;
    return handler->GetCrlFormat(*cfg_res.value());
}

score::crypto::Expected<int64_t, Error> CertSlotManager::GetCrlNextUpdate(CertSlotHandle slot,
                                                                          data_manager::ClientId client_id)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = *cfg_res.value();

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
    return handler->GetCrlNextUpdate(cfg);
}

// ---------------------------------------------------------------------------
// Tier 1 — writes
// ---------------------------------------------------------------------------

score::crypto::Expected<std::monostate, Error> CertSlotManager::StoreCertificate(CertSlotHandle slot,
                                                                                 data_manager::ClientId client_id,
                                                                                 const CertObject& cert)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = *cfg_res.value();

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

    auto result = handler->StoreCertificate(cfg, cert);
    if (result.has_value())
        InvalidateCertObjectCache(slot);
    return result;
}

score::crypto::Expected<std::monostate, Error> CertSlotManager::ClearSlot(CertSlotHandle slot,
                                                                          data_manager::ClientId client_id)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = *cfg_res.value();

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

    auto result = handler->ClearSlot(cfg);
    if (result.has_value())
        InvalidateCertObjectCache(slot);
    return result;
}

void CertSlotManager::InvalidateCertObjectCache(CertSlotHandle slot)
{
    std::lock_guard lock(m_mutex);
    m_cert_object_cache.erase(slot.index);
}

score::crypto::Expected<std::monostate, Error> CertSlotManager::ImportCrl(CertSlotHandle slot,
                                                                          data_manager::ClientId client_id,
                                                                          score::crypto::span<const uint8_t> crl_data,
                                                                          score::crypto::FormatType format,
                                                                          std::int64_t next_update_epoch_s)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = *cfg_res.value();

    auto write_res = ApplyWriteChecks(cfg, client_id);
    if (!write_res.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "ImportCrl: write access denied for slot " << slot.index;
        return write_res;
    }

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        handler = GetOrCreate(slot);
    }
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);
    return handler->StoreCrl(cfg, crl_data, format, next_update_epoch_s);
}

score::crypto::Expected<std::monostate, Error> CertSlotManager::DeleteCrl(CertSlotHandle slot,
                                                                          data_manager::ClientId client_id)
{
    const auto cfg_res = GetConfig(slot);
    if (!cfg_res.has_value())
        return score::crypto::make_unexpected(cfg_res.error());
    const CertSlotConfig& cfg = *cfg_res.value();

    auto write_res = ApplyWriteChecks(cfg, client_id);
    if (!write_res.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "DeleteCrl: write access denied for slot " << slot.index;
        return write_res;
    }

    ICertSlotHandler::Sptr handler;
    {
        std::lock_guard lock(m_mutex);
        handler = GetOrCreate(slot);
    }
    if (!handler)
        return score::crypto::make_unexpected(Error::kInternalError);
    return handler->ClearCrl(cfg);
}

}  // namespace score::crypto::daemon::cert_management
