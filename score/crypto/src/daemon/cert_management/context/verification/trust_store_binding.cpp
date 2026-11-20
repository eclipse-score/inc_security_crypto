/*******************************************************************************
 *
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
 *******************************************************************************
 */

#include "score/crypto/src/daemon/cert_management/context/verification/trust_store_binding.hpp"

#include <utility>

namespace score::crypto::daemon::cert_management
{

TrustStoreBinding::TrustStoreBinding(TrustStoreManager::Sptr trust_store_manager, data_manager::ClientId client_id)
    : m_trust_store_manager{std::move(trust_store_manager)}, m_client_id{client_id}
{
}

TrustStoreBinding::~TrustStoreBinding()
{
    Release();
}

score::crypto::Expected<std::monostate, common::DaemonErrorCode> TrustStoreBinding::Bind(TrustStoreHandle handle)
{
    if (!m_trust_store_manager)
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInternalError);
    }

    // Take the new reference first: a failure returns before the current binding is touched.
    auto added = m_trust_store_manager->AddRef(handle, m_client_id);
    if (!added.has_value())
    {
        return score::crypto::make_unexpected(added.error());
    }

    Release();
    m_handle = handle;
    return std::monostate{};
}

void TrustStoreBinding::Release()
{
    if (!m_handle.has_value())
    {
        return;
    }
    m_trust_store_manager->ReleaseRef(*m_handle, m_client_id);
    m_handle.reset();
}

std::optional<TrustStoreHandle> TrustStoreBinding::Handle() const noexcept
{
    return m_handle;
}

}  // namespace score::crypto::daemon::cert_management
