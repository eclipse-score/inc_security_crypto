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

#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_store.hpp"

#include "score/crypto/daemon/provider/pkcs11/pkcs11_provider.hpp"

#include "score/mw/log/logging.h"

#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

// ========== Private definition for LOG_PREFIX ==========
#ifndef LOG_PREFIX
#define LOG_PREFIX "[Pkcs11KeyStore] "
#endif

Pkcs11KeyStore::Pkcs11KeyStore(std::weak_ptr<Pkcs11Provider> provider, std::weak_ptr<Pkcs11Module> module)
    : m_provider{std::move(provider)}, m_module{std::move(module)}
{
}

key_management::ProviderKeyHandle Pkcs11KeyStore::Register(
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object,
    const std::string& algorithm,
    std::size_t key_size,
    score::mw::crypto::KeyOperationPermission permissions) noexcept
{
    std::lock_guard<std::mutex> lock(m_map_mutex);
    const uint64_t opaque_id = m_next_opaque_id++;
    SessionKey sk{};
    sk.session = session;
    sk.object = object;
    sk.is_token_object = false;
    sk.op_mutex = std::make_shared<std::mutex>();
    m_keys[opaque_id] = std::move(sk);
    return key_management::ProviderKeyHandle{
        .opaque_id = opaque_id,
        .provider_id = m_provider.lock() ? m_provider.lock()->GetProviderId() : common::kInvalidProviderId,
        .permissions = permissions,
        .algorithm = algorithm,
        .key_size = key_size,
    };
}

key_management::ProviderKeyHandle Pkcs11KeyStore::RegisterTokenObject(const SearchTemplate& search_template,
                                                                      const std::string& algorithm,
                                                                      std::size_t key_size) noexcept
{
    std::lock_guard<std::mutex> lock(m_map_mutex);
    const uint64_t opaque_id = m_next_opaque_id++;
    SessionKey sk{};
    sk.is_token_object = true;
    sk.token_search = search_template;
    m_keys[opaque_id] = std::move(sk);
    return key_management::ProviderKeyHandle{
        .opaque_id = opaque_id,
        .provider_id = m_provider.lock() ? m_provider.lock()->GetProviderId() : common::kInvalidProviderId,
        .permissions = score::mw::crypto::KeyOperationPermission::kNone,
        .algorithm = algorithm,
        .key_size = key_size,
    };
}

Pkcs11KeyStore::ResolvedKey Pkcs11KeyStore::ResolveObject(uint64_t opaque_id,
                                                          CK_SESSION_HANDLE handler_session) noexcept
{
    // For session objects: try to acquire the per-key mutex (non-blocking).
    // Returns a contended ResolvedKey if another handler already holds the lock;
    // the caller surfaces kResourceBusy immediately.\n    //
    // For token objects: run C_FindObjects on handler_session (outside m_map_mutex
    // to avoid holding it during a potentially blocking HSM call).
    std::shared_ptr<std::mutex> op_mtx;
    bool is_token = false;
    CK_SESSION_HANDLE creating_session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE stored_object = CK_INVALID_HANDLE;
    SearchTemplate tmpl;

    {
        std::lock_guard<std::mutex> lock(m_map_mutex);
        const auto it = m_keys.find(opaque_id);
        if (it == m_keys.end())
        {
            return {};
        }
        is_token = it->second.is_token_object;
        if (!is_token)
        {
            creating_session = it->second.session;
            stored_object = it->second.object;
            op_mtx = it->second.op_mutex;
        }
        else
        {
            tmpl = it->second.token_search;
        }
    }

    if (!is_token)
    {
        // Try to acquire the per-key mutex without blocking.  If another handler
        // is already using this session key, return a contended sentinel so the
        // caller can immediately surface kResourceBusy instead of deadlocking.
        std::unique_lock<std::mutex> key_lock{*op_mtx, std::try_to_lock};
        if (!key_lock.owns_lock())
        {
            ResolvedKey contended{};
            contended.contended = true;
            return contended;
        }
        ResolvedKey resolved{};
        resolved.session = creating_session;
        resolved.object = stored_object;
        resolved.lock = std::move(key_lock);
        return resolved;
    }

    // --- token object path ---
    if (handler_session == CK_INVALID_HANDLE)
    {
        return {};
    }
    auto module = m_module.lock();
    if (!module)
    {
        return {};
    }
    CK_FUNCTION_LIST* fns = module->GetFunctionList();
    if (fns == nullptr)
    {
        return {};
    }

    // Run C_FindObjects on the handler's session to obtain a session-local handle.
    CK_ATTRIBUTE attrs_storage[3];
    CK_ULONG attr_count = 0U;
    attrs_storage[attr_count++] = {CKA_CLASS, &tmpl.obj_class, sizeof(CK_OBJECT_CLASS)};
    if (!tmpl.label.empty())
    {
        // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API requires non-const pValue.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        attrs_storage[attr_count++] = {
            CKA_LABEL, const_cast<char*>(tmpl.label.data()), static_cast<CK_ULONG>(tmpl.label.size())};
    }
    if (!tmpl.id.empty())
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        attrs_storage[attr_count++] = {
            CKA_ID, const_cast<uint8_t*>(tmpl.id.data()), static_cast<CK_ULONG>(tmpl.id.size())};
    }

    const CK_RV rv_init = fns->C_FindObjectsInit(handler_session, attrs_storage, attr_count);
    if (rv_init != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "ResolveObject: C_FindObjectsInit failed: rv="
                                   << static_cast<unsigned long>(rv_init);
        return {};
    }

    CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
    CK_ULONG count = 0U;
    const CK_RV rv_find = fns->C_FindObjects(handler_session, &found, 1U, &count);
    static_cast<void>(fns->C_FindObjectsFinal(handler_session));

    if ((rv_find != CKR_OK) || (count == 0U) || (found == CK_INVALID_HANDLE))
    {
        score::mw::log::LogError() << LOG_PREFIX << "ResolveObject: token object not found on handler session";
        return {};
    }

    ResolvedKey resolved{};
    resolved.session = handler_session;
    resolved.object = found;
    return resolved;
}

std::pair<CK_SESSION_HANDLE, CK_OBJECT_HANDLE> Pkcs11KeyStore::Lookup(uint64_t opaque_id) const noexcept
{
    std::lock_guard<std::mutex> lock(m_map_mutex);
    const auto it = m_keys.find(opaque_id);
    if (it == m_keys.end())
    {
        return {CK_INVALID_HANDLE, CK_INVALID_HANDLE};
    }
    return {it->second.session, it->second.object};
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11KeyStore::Release(
    uint64_t opaque_id,
    const key_management::ProviderKeyHandle& key) noexcept
{
    (void)key;  // Unused for now; kept for future extensibility

    std::lock_guard<std::mutex> lock(m_map_mutex);

    const auto it = m_keys.find(opaque_id);
    if (it == m_keys.end())
    {
        score::mw::log::LogError() << LOG_PREFIX << "Release: opaque_id=" << opaque_id << " not found";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }

    const SessionKey& sk = it->second;

    if (!sk.is_token_object)
    {
        // Session object (generated/imported key): destroy the PKCS#11 object
        // and return the ReadWrite session to the provider pool.
        auto module_sptr = m_module.lock();
        auto provider_sptr = m_provider.lock();
        if (module_sptr)
        {
            CK_FUNCTION_LIST* fns = module_sptr->GetFunctionList();
            if ((fns != nullptr) && (sk.session != CK_INVALID_HANDLE) && (sk.object != CK_INVALID_HANDLE))
            {
                const CK_RV rv = fns->C_DestroyObject(sk.session, sk.object);
                if (rv != CKR_OK)
                {
                    score::mw::log::LogError()
                        << LOG_PREFIX << "C_DestroyObject failed: rv=" << static_cast<unsigned long>(rv);
                }
            }
        }
        if ((sk.session != CK_INVALID_HANDLE) && provider_sptr)
        {
            const Pkcs11HandlerRequirements reqs{Pkcs11SessionType::ReadWrite, Pkcs11TokenAuthState::User};
            provider_sptr->ReleaseSession(sk.session, reqs);
        }
    }
    // Token objects: the HSM object persists on the token — nothing to destroy
    // and no session to release.

    m_keys.erase(it);
    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::pkcs11
