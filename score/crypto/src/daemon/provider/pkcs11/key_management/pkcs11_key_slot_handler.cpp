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

#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_slot_handler.hpp"

#include "score/crypto/daemon/key_management/detail/slot_info_builder.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/daemon/key_management/slot/deployment_loader.hpp"
#include "score/crypto/daemon/provider/pkcs11/detail/pkcs11_algorithm_info.hpp"
#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_handler.hpp"
#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_store.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_provider.hpp"

#include "score/mw/log/logging.h"

#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

// =============================================================================
// Pkcs11KeySlotHandler
// =============================================================================

Pkcs11KeySlotHandler::Pkcs11KeySlotHandler(std::shared_ptr<Pkcs11Provider> provider,
                                           std::weak_ptr<Pkcs11Module> module,
                                           std::shared_ptr<Pkcs11KeyStore> key_store)
    : m_provider{std::move(provider)}, m_module{std::move(module)}, m_key_store{std::move(key_store)}
{
}

score::crypto::Expected<key_management::IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeySlotHandler::LoadKey(const key_management::KeySlotConfig& slot)
{
    using key_management::deployment_keys::kPkcs11Label;
    using key_management::deployment_keys::kPkcs11ObjectClass;
    using key_management::deployment_keys::kPkcs11ObjectId;

    if (!m_provider)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    // Load deployment info to get PKCS#11 object identifiers.
    auto deploy_result = key_management::DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        return score::crypto::make_unexpected(deploy_result.error());
    }
    const auto& key_props = deploy_result.value().key_properties;

    const auto label_it = key_props.find(std::string{kPkcs11Label});
    const auto id_it = key_props.find(std::string{kPkcs11ObjectId});
    const auto class_it = key_props.find(std::string{kPkcs11ObjectClass});

    if (label_it == key_props.end() && id_it == key_props.end())
    {
        score::mw::log::LogError() << LOG_PREFIX << "LoadKey: slot '" << slot.slot_name
                                   << "' has neither pkcs11.label nor pkcs11.object_id in deployment info";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    // Determine object class (default: CKO_SECRET_KEY).
    CK_OBJECT_CLASS obj_class = CKO_SECRET_KEY;
    if (class_it != key_props.end())
    {
        const auto& cls_str = class_it->second;
        if (cls_str == "private_key")
        {
            obj_class = CKO_PRIVATE_KEY;
        }
        else if (cls_str == "public_key")
        {
            obj_class = CKO_PUBLIC_KEY;
        }
        // else: default secret_key
    }

    // Build the search template.
    std::vector<CK_ATTRIBUTE> tmpl;
    tmpl.push_back({CKA_CLASS, &obj_class, sizeof(obj_class)});

    // Label attribute (must outlive the C_FindObjects call).
    std::string label_value;
    if (label_it != key_props.end())
    {
        label_value = label_it->second;
        // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API (CK_ATTRIBUTE) requires non-const pValue.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        tmpl.push_back({CKA_LABEL, const_cast<char*>(label_value.data()), static_cast<CK_ULONG>(label_value.size())});
    }

    // Object ID attribute (must outlive the C_FindObjects call).
    std::vector<uint8_t> id_bytes;
    if (id_it != key_props.end())
    {
        id_bytes = detail::HexDecode(id_it->second);
        if (!id_bytes.empty())
        {
            tmpl.push_back({CKA_ID, id_bytes.data(), static_cast<CK_ULONG>(id_bytes.size())});
        }
    }

    // Acquire RO session (User auth needed for secret key objects).
    const Pkcs11HandlerRequirements reqs{Pkcs11SessionType::ReadOnly, Pkcs11TokenAuthState::User};
    auto session_result = m_provider->AcquireSession(reqs);
    if (!session_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "LoadKey: failed to acquire RO session for slot '" << slot.slot_name
                                   << "'";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
    }
    const CK_SESSION_HANDLE session = session_result.value();

    auto module = m_module.lock();
    if (!module)
    {
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    CK_FUNCTION_LIST* fns = module->GetFunctionList();
    if (fns == nullptr)
    {
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    CK_RV rv = fns->C_FindObjectsInit(session, tmpl.data(), static_cast<CK_ULONG>(tmpl.size()));
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_FindObjectsInit failed: rv=" << static_cast<unsigned long>(rv);
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kKeySlotEmpty);
    }

    CK_OBJECT_HANDLE found_object = CK_INVALID_HANDLE;
    CK_ULONG found_count = 0U;
    rv = fns->C_FindObjects(session, &found_object, 1U, &found_count);
    static_cast<void>(fns->C_FindObjectsFinal(session));  // always finalise

    if (rv != CKR_OK || found_count == 0U || found_object == CK_INVALID_HANDLE)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_FindObjects: object not found for slot '" << slot.slot_name
                                   << "'";
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kKeySlotEmpty);
    }

    // Retrieve CKA_VALUE_LEN (key size in bytes).
    CK_ULONG value_len = 0U;
    CK_ATTRIBUTE value_len_attr{CKA_VALUE_LEN, &value_len, sizeof(value_len)};
    rv = fns->C_GetAttributeValue(session, found_object, &value_len_attr, 1U);
    // Some tokens don't support CKA_VALUE_LEN -- fall back to algorithm-derived size.
    if (rv != CKR_OK)
    {
        const auto algo_info = detail::LookupAlgorithm(slot.algorithm);
        value_len = algo_info.has_value() ? static_cast<CK_ULONG>(algo_info->value_len) : 0U;
    }

    // Store the search template so any handler can independently locate the key
    // via Pkcs11KeyStore::ResolveObject() on its own session.
    SearchTemplate search_tmpl;
    search_tmpl.label = (label_it != key_props.end()) ? label_it->second : std::string{};
    search_tmpl.id = id_bytes;
    search_tmpl.obj_class = obj_class;

    const auto handle =
        m_key_store->RegisterTokenObject(search_tmpl, slot.algorithm, static_cast<std::size_t>(value_len));

    m_provider->ReleaseSession(session, reqs);

    return std::make_shared<Pkcs11KeyHandler>(m_key_store, std::move(handle));
}

score::crypto::Expected<score::mw::crypto::KeySlotState, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeySlotHandler::GetSlotState(const key_management::KeySlotConfig& slot)
{
    using key_management::deployment_keys::kPkcs11Label;
    using key_management::deployment_keys::kPkcs11ObjectId;

    if (!m_provider)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    // Load deployment info to get PKCS#11 object identifiers.
    auto deploy_result = key_management::DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        return score::mw::crypto::KeySlotState::kEmpty;
    }
    const auto& key_props = deploy_result.value().key_properties;

    const auto label_it = key_props.find(std::string{kPkcs11Label});
    const auto id_it = key_props.find(std::string{kPkcs11ObjectId});

    if (label_it == key_props.end() && id_it == key_props.end())
    {
        return score::mw::crypto::KeySlotState::kEmpty;
    }

    const Pkcs11HandlerRequirements reqs{Pkcs11SessionType::ReadOnly, Pkcs11TokenAuthState::User};
    auto session_result = m_provider->AcquireSession(reqs);
    if (!session_result.has_value())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
    }
    const CK_SESSION_HANDLE session = session_result.value();

    auto module = m_module.lock();
    if (!module)
    {
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    CK_FUNCTION_LIST* fns = module->GetFunctionList();
    if (fns == nullptr)
    {
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    CK_OBJECT_CLASS obj_class = CKO_SECRET_KEY;
    std::vector<CK_ATTRIBUTE> tmpl;
    tmpl.push_back({CKA_CLASS, &obj_class, sizeof(obj_class)});

    std::string label_value;
    if (label_it != key_props.end())
    {
        label_value = label_it->second;
        // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API (CK_ATTRIBUTE) requires non-const pValue.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        tmpl.push_back({CKA_LABEL, const_cast<char*>(label_value.data()), static_cast<CK_ULONG>(label_value.size())});
    }

    std::vector<uint8_t> id_bytes;
    if (id_it != key_props.end())
    {
        id_bytes = detail::HexDecode(id_it->second);
        if (!id_bytes.empty())
        {
            tmpl.push_back({CKA_ID, id_bytes.data(), static_cast<CK_ULONG>(id_bytes.size())});
        }
    }

    const CK_RV rv_init = fns->C_FindObjectsInit(session, tmpl.data(), static_cast<CK_ULONG>(tmpl.size()));
    score::mw::crypto::KeySlotState state = score::mw::crypto::KeySlotState::kEmpty;
    if (rv_init == CKR_OK)
    {
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        CK_ULONG count = 0U;
        if (fns->C_FindObjects(session, &obj, 1U, &count) == CKR_OK && count > 0U)
        {
            state = score::mw::crypto::KeySlotState::kOccupied;
        }
        static_cast<void>(fns->C_FindObjectsFinal(session));
    }

    m_provider->ReleaseSession(session, reqs);
    return state;
}

score::crypto::Expected<score::mw::crypto::KeySlotInfo, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeySlotHandler::GetSlotInfo(const key_management::KeySlotConfig& slot)
{
    auto state = GetSlotState(slot);
    if (!state.has_value())
    {
        return score::crypto::make_unexpected(state.error());
    }
    return key_management::detail::BuildKeySlotInfo(slot, state.value());
}

}  // namespace score::crypto::daemon::provider::pkcs11
