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

#include "score/crypto/src/daemon/cert_management/core/cert_entry.hpp"

#include <utility>

namespace score::crypto::daemon::cert_management
{

CertEntry::CertEntry(data_manager::ClientId owner, CertObject::Sptr object, CertSlotHandle slot_handle)
    : m_object{std::move(object)}, m_slot_handle{slot_handle}, m_owner_client_id{owner}
{
}

CertEntry::~CertEntry() = default;

CertObject::Sptr CertEntry::GetCertObject() const noexcept
{
    return m_object;
}

CertSlotHandle CertEntry::GetSlotHandle() const noexcept
{
    return m_slot_handle;
}

void CertEntry::AttachSessionCrl(CrlData crl)
{
    auto snapshot = std::make_shared<const CrlData>(std::move(crl));
    const std::lock_guard<std::mutex> lock(m_ref_mutex);
    m_session_crl = std::move(snapshot);
}

bool CertEntry::HasSessionCrl() const
{
    const std::lock_guard<std::mutex> lock(m_ref_mutex);
    return m_session_crl != nullptr;
}

void CertEntry::ClearSessionCrl()
{
    const std::lock_guard<std::mutex> lock(m_ref_mutex);
    m_session_crl.reset();
}

CrlData::Sptrc CertEntry::GetSessionCrlSnapshot() const
{
    const std::lock_guard<std::mutex> lock(m_ref_mutex);
    return m_session_crl;
}

data_manager::ClientId CertEntry::GetOwner() const noexcept
{
    return m_owner_client_id;
}

bool CertEntry::IsOwnedBy(data_manager::ClientId client_id) const noexcept
{
    return m_owner_client_id == client_id;
}

}  // namespace score::crypto::daemon::cert_management
