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

#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_handler.hpp"
#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_store.hpp"

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::provider::pkcs11
{

Pkcs11KeyHandler::Pkcs11KeyHandler(std::weak_ptr<Pkcs11KeyStore> key_store,
                                   key_management::ProviderKeyHandle key_handle) noexcept
    : m_key_store{std::move(key_store)}, m_key_handle{std::move(key_handle)}, m_released{false}
{
}

Pkcs11KeyHandler::~Pkcs11KeyHandler()
{
    score::mw::log::LogDebug() << "[PKCS11_KEY_HANDLER] Release Key";
    static_cast<void>(Release());
}

const key_management::ProviderKeyHandle& Pkcs11KeyHandler::GetHandle() const noexcept
{
    return m_key_handle;
}

common::ProviderId Pkcs11KeyHandler::GetProviderId() const noexcept
{
    return m_key_handle.provider_id;
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11KeyHandler::Release()
{
    if (m_released.exchange(true))
    {
        return std::monostate{};  // idempotent — already released by another thread
    }

    auto key_store = m_key_store.lock();
    if (key_store == nullptr)
    {
        // Key store was destroyed before the key — nothing to clean up.
        return std::monostate{};
    }
    return key_store->Release(m_key_handle.opaque_id, m_key_handle);
}

std::pair<CK_SESSION_HANDLE, CK_OBJECT_HANDLE> Pkcs11KeyHandler::GetSessionKey() const noexcept
{
    auto key_store = m_key_store.lock();
    if (key_store == nullptr)
    {
        return {CK_INVALID_HANDLE, CK_INVALID_HANDLE};
    }
    return key_store->Lookup(m_key_handle.opaque_id);
}

Pkcs11KeyStore::ResolvedKey Pkcs11KeyHandler::ResolveObject(CK_SESSION_HANDLE handler_session) const noexcept
{
    auto key_store = m_key_store.lock();
    if (key_store == nullptr)
    {
        return {};
    }
    return key_store->ResolveObject(m_key_handle.opaque_id, handler_session);
}

score::crypto::Expected<key_management::SecureKeyBytes, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeyHandler::Export() const
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kKeyOperationNotPermitted);
}

}  // namespace score::crypto::daemon::provider::pkcs11
