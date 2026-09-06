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
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_handler.hpp"

#include <utility>

namespace score::crypto::daemon::cert_management
{
namespace
{
using Error = common::DaemonErrorCode;
}

TrustStoreHandler::TrustStoreHandler(TrustStoreHandle handle, AnchorLoader loader)
    : m_handle{handle}, m_loader{std::move(loader)}
{
}

TrustStoreHandle TrustStoreHandler::GetHandle() const noexcept
{
    return m_handle;
}

score::crypto::Expected<std::vector<CertObject::Sptr>, Error> TrustStoreHandler::GetAnchors()
{
    EnsureLoaded();
    return All();
}

void TrustStoreHandler::EnsureLoaded()
{
    if (!m_loaded)
    {
        if (m_loader)
            m_loader(*this);
        m_loaded = true;
    }
}

void TrustStoreHandler::NotifySlotUpdate(CertSlotHandle slot, CertObject::Sptr cert)
{
    // In-place update of one slot. Does not touch m_loaded — the caller
    // (TrustStoreManager) is responsible for deciding whether a reload is needed.
    m_slots[slot.index] = std::move(cert);
}

std::vector<CrlEntry> TrustStoreHandler::GetCrls()
{
    EnsureLoaded();
    std::vector<CrlEntry> result;
    result.reserve(m_crls.size());
    for (const auto& [slot_index, entry] : m_crls)
        result.push_back(entry);
    return result;
}

void TrustStoreHandler::NotifyCrlUpdate(CertSlotHandle slot, std::optional<CrlEntry> entry)
{
    if (entry.has_value())
        m_crls[slot.index] = std::move(*entry);
    else
        m_crls.erase(slot.index);
}

void TrustStoreHandler::InvalidateSlot(CertSlotHandle slot)
{
    m_slots.erase(slot.index);
    m_crls.erase(slot.index);
    m_loaded = false;
}

void TrustStoreHandler::ClearAnchorCache()
{
    m_slots.clear();
    m_crls.clear();
    m_loaded = false;
}

CertObject::Sptr TrustStoreHandler::FindBySubject(const std::string& subject) const
{
    for (const auto& cert : All())
    {
        if (cert && cert->GetSubject() == subject)
            return cert;
    }
    return nullptr;
}

CertObject::Sptr TrustStoreHandler::FindBySkid(score::crypto::span<const uint8_t> skid) const
{
    for (const auto& cert : All())
    {
        if (cert && cert->GetSkid().size() == skid.size() &&
            std::equal(skid.begin(), skid.end(), cert->GetSkid().begin()))
            return cert;
    }
    return nullptr;
}

std::vector<CertObject::Sptr> TrustStoreHandler::All() const
{
    std::vector<CertObject::Sptr> all;
    for (const auto& [slot, cert] : m_slots)
    {
        if (cert)
            all.push_back(cert);
    }
    return all;
}

}  // namespace score::crypto::daemon::cert_management
