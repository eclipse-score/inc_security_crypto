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

#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_key_store.hpp"

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/key_management/resolved_key.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"

#include "score/mw/log/logging.h"

#include <pkcs11.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

constexpr std::string_view LOG_PREFIX = "[Pkcs11KeyStore] ";

Pkcs11KeyStore::Pkcs11KeyStore(std::weak_ptr<Pkcs11Provider> provider, std::weak_ptr<Pkcs11Module> module)
    : m_provider{std::move(provider)}, m_module{std::move(module)}
{
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
key_management::ProviderKeyHandle Pkcs11KeyStore::Register(CK_SESSION_HANDLE session,
                                                           CK_OBJECT_HANDLE object,
                                                           const std::string& algorithm,
                                                           std::size_t key_size,
                                                           score::crypto::KeyOperationPermission permissions) noexcept
{
    const std::lock_guard<std::mutex> lock(m_map_mutex);
    const uint64_t opaque_id = m_next_opaque_id++;
    SessionKey session_key{};
    session_key.session = session;
    session_key.object = object;
    session_key.is_token_object = false;
    session_key.op_in_use = std::make_shared<std::atomic_flag>();
    session_key.op_in_use
        ->clear();  // Default ctor sets flag to unspecified state till C++20, explicitly clear to ensure it's not set.
    m_keys[opaque_id] = std::move(session_key);
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
    const std::lock_guard<std::mutex> lock(m_map_mutex);
    const uint64_t opaque_id = m_next_opaque_id++;
    SessionKey session_key{};
    session_key.is_token_object = true;
    session_key.token_search = search_template;
    m_keys[opaque_id] = std::move(session_key);
    return key_management::ProviderKeyHandle{
        .opaque_id = opaque_id,
        .provider_id = m_provider.lock() ? m_provider.lock()->GetProviderId() : common::kInvalidProviderId,
        .permissions = score::crypto::KeyOperationPermission::kNone,
        .algorithm = algorithm,
        .key_size = key_size,
    };
}

score::crypto::Expected<ResolvedKey, score::crypto::daemon::common::DaemonErrorCode> Pkcs11KeyStore::ResolveObject(
    uint64_t opaque_id,  // NOLINT(bugprone-easily-swappable-parameters)
    CK_SESSION_HANDLE handler_session) noexcept
{
    // Hold m_map_mutex only to read the key entry, then release before any HSM call.
    std::shared_ptr<std::atomic_flag> op_flag;
    bool is_token = false;
    CK_SESSION_HANDLE creating_session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE stored_object = CK_INVALID_HANDLE;
    SearchTemplate tmpl;

    {
        const std::lock_guard<std::mutex> lock(m_map_mutex);
        const auto key_iter = m_keys.find(opaque_id);
        if (key_iter == m_keys.end())
        {
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
        }
        is_token = key_iter->second.is_token_object;
        if (!is_token)
        {
            creating_session = key_iter->second.session;
            stored_object = key_iter->second.object;
            op_flag = key_iter->second.op_in_use;
        }
        else
        {
            tmpl = key_iter->second.token_search;
        }
    }

    if (!is_token)
    {
        return ResolvedKey::Acquire(creating_session, stored_object, std::move(op_flag));
    }

    // --- token object path ---
    if (handler_session == CK_INVALID_HANDLE)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    auto module = m_module.lock();
    if (!module)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    CK_FUNCTION_LIST* fns = module->GetFunctionList();
    if (fns == nullptr)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    // Run C_FindObjects on the handler's session to obtain a session-local handle.
    std::array<CK_ATTRIBUTE, 3> attrs_storage{};
    std::array<CK_ATTRIBUTE, 3>::iterator attribute_iter = attrs_storage.begin();
    CK_ULONG attr_count = 0U;
    *attribute_iter++ = {CKA_CLASS, &tmpl.obj_class, sizeof(CK_OBJECT_CLASS)};
    ++attr_count;
    if (!tmpl.label.empty())
    {
        // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API requires non-const pValue.
        *attribute_iter++ = {CKA_LABEL, const_cast<char*>(tmpl.label.data()), static_cast<CK_ULONG>(tmpl.label.size())};
        ++attr_count;
    }
    if (!tmpl.id.empty())
    {
        *attribute_iter++ = {CKA_ID, const_cast<uint8_t*>(tmpl.id.data()), static_cast<CK_ULONG>(tmpl.id.size())};
        ++attr_count;
    }

    const CK_RV rv_init = fns->C_FindObjectsInit(handler_session, attrs_storage.data(), attr_count);
    if (rv_init != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "ResolveObject: C_FindObjectsInit failed: rv="
                                   << static_cast<unsigned long>(rv_init);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
    CK_ULONG count = 0U;
    const CK_RV rv_find = fns->C_FindObjects(handler_session, &found, 1U, &count);
    static_cast<void>(fns->C_FindObjectsFinal(handler_session));

    if ((rv_find != CKR_OK) || (count == 0U) || (found == CK_INVALID_HANDLE))
    {
        score::mw::log::LogError() << LOG_PREFIX << "ResolveObject: token object not found on handler session";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    return ResolvedKey::ForToken(handler_session, found);
}

std::pair<CK_SESSION_HANDLE, CK_OBJECT_HANDLE> Pkcs11KeyStore::Lookup(uint64_t opaque_id) const noexcept
{
    const std::lock_guard<std::mutex> lock(m_map_mutex);
    const auto key_iter = m_keys.find(opaque_id);
    if (key_iter == m_keys.end())
    {
        return {CK_INVALID_HANDLE, CK_INVALID_HANDLE};
    }
    return {key_iter->second.session, key_iter->second.object};
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11KeyStore::Release(
    uint64_t opaque_id,
    const key_management::ProviderKeyHandle& key) noexcept
{
    (void)key;  // Unused for now; kept for future extensibility

    const std::lock_guard<std::mutex> lock(m_map_mutex);

    const auto key_iter = m_keys.find(opaque_id);
    if (key_iter == m_keys.end())
    {
        score::mw::log::LogError() << LOG_PREFIX << "Release: opaque_id=" << opaque_id << " not found";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }

    const SessionKey& session_key = key_iter->second;

    if (!session_key.is_token_object)
    {
        // Session object (generated/imported key): destroy the PKCS#11 object
        // and return the ReadWrite session to the provider pool.
        auto module_sptr = m_module.lock();
        auto provider_sptr = m_provider.lock();
        if (module_sptr)
        {
            CK_FUNCTION_LIST* fns = module_sptr->GetFunctionList();
            if ((fns != nullptr) && (session_key.session != CK_INVALID_HANDLE) &&
                (session_key.object != CK_INVALID_HANDLE))
            {
                const CK_RV result = fns->C_DestroyObject(session_key.session, session_key.object);
                if (result != CKR_OK)
                {
                    score::mw::log::LogError()
                        << LOG_PREFIX << "C_DestroyObject failed: rv=" << static_cast<unsigned long>(result);
                }
            }
        }
        if ((session_key.session != CK_INVALID_HANDLE) && provider_sptr)
        {
            const Pkcs11HandlerRequirements reqs{Pkcs11SessionType::ReadWrite, Pkcs11TokenAuthState::User};
            provider_sptr->ReleaseSession(session_key.session, reqs);
        }
    }
    // Token objects: the HSM object persists on the token — nothing to destroy
    // and no session to release.

    m_keys.erase(key_iter);
    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::pkcs11
