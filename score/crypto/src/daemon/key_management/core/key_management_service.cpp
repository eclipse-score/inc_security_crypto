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

#include "score/crypto/daemon/key_management/core/key_management_service.hpp"

#include "score/crypto/daemon/data_manager/data_node_accessor.hpp"
#include "score/crypto/daemon/key_management/core/key_entry.hpp"
#include "score/crypto/daemon/key_management/nodes/key_data_node.hpp"
#include "score/crypto/daemon/key_management/nodes/key_slot_data_node.hpp"

#include "score/mw/log/logging.h"

#include <string_view>

namespace score::crypto::daemon::key_management
{
namespace
{
constexpr std::string_view LOG_PREFIX = "[KM_SERVICE] ";
}  // namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

KeyManagementService::KeyManagementService(data_manager::IDataManager::Sptr data_manager,
                                           provider::ProviderManager::Sptr provider_manager,
                                           SlotRegistry::Sptr slot_registry)
    : m_data_manager{std::move(data_manager)},
      m_provider_manager{std::move(provider_manager)},
      m_slot_registry{std::move(slot_registry)}
{
    if (!m_data_manager || !m_provider_manager || !m_slot_registry)
    {
        score::mw::log::LogError() << LOG_PREFIX << "constructor: null dependency injected";
    }
}

// ---------------------------------------------------------------------------
// RegisterKeyMaterial
// ---------------------------------------------------------------------------

Expected<KeyDataNodeResult, score::crypto::daemon::common::DaemonErrorCode> KeyManagementService::RegisterKeyMaterial(
    const KeyRegistrationParams& params,
    IKeyHandler::Sptr handler)
{
    if (!handler)
    {
        score::mw::log::LogError() << LOG_PREFIX << "RegisterKeyMaterial: null handler";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    auto key_node = std::make_shared<KeyEntry>(std::move(handler), params.provider_id, params.slot_handle);

    auto& registry = GetProviderRegistry(params.provider_id);

    KeyRegistryId reg_id{};
    if (params.slot_handle.IsValid())
    {
        reg_id = registry.RegisterSlotKey(params.slot_handle, key_node);
        if (reg_id == 0U)
        {
            // Race condition: another thread registered this slot between our LoadOrShare()
            // check and this registration attempt. Our loaded key_node will be destroyed
            // (and handler released) when we replace it below.
            reg_id = registry.FindSlotRegistryId(params.slot_handle);
            if (reg_id == 0U)
            {
                score::mw::log::LogError()
                    << LOG_PREFIX << "RegisterKeyMaterial: race condition - slot registered but ID not found";
                return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
            }

            // Look up the key node that won the race.
            key_node = registry.FindById(reg_id);
            if (!key_node)
            {
                score::mw::log::LogError()
                    << LOG_PREFIX << "RegisterKeyMaterial: existing key not found after race condition";
                return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
            }
        }
    }
    else
    {
        reg_id = registry.RegisterEphemeralKey(key_node);
    }

    return CreateKeyDataNode(params.client_id, params.parent_id, std::move(key_node), reg_id, params.provider_id);
}

// ---------------------------------------------------------------------------
// LoadOrShare
// ---------------------------------------------------------------------------

Expected<KeyDataNodeResult, score::crypto::daemon::common::DaemonErrorCode> KeyManagementService::LoadOrShare(
    const KeyRegistrationParams& params,
    IKeySlotHandler& slot_handler,
    const KeySlotConfig& slot_config)
{
    auto& registry = GetProviderRegistry(params.provider_id);

    // Check if this slot is already loaded in the registry.
    auto existing = registry.FindBySlot(params.slot_handle);
    if (existing != nullptr)
    {
        // Reuse the existing KeyDataNode — add a reference for this client.
        // We need the registry ID for the existing entry. Look it up via FindBySlot
        // indirectly: we know the entry exists, so retrieve its ID through the
        // slot_to_id mapping by calling FindSlotRegistryId.
        const auto reg_id = registry.FindSlotRegistryId(params.slot_handle);
        return CreateKeyDataNode(params.client_id, params.parent_id, std::move(existing), reg_id, params.provider_id);
    }

    // Not yet loaded — call the provider's slot handler.
    auto load_result = slot_handler.LoadKey(slot_config);
    if (!load_result.has_value())
    {
        // LoadKey failed. Could be due to another thread loading the slot simultaneously
        // (e.g., PKCS#11 rejects duplicate loads). Check if it was registered in the meantime.
        auto existing = registry.FindBySlot(params.slot_handle);
        if (existing != nullptr)
        {
            const auto reg_id = registry.FindSlotRegistryId(params.slot_handle);
            return CreateKeyDataNode(
                params.client_id, params.parent_id, std::move(existing), reg_id, params.provider_id);
        }

        score::mw::log::LogError() << LOG_PREFIX << "LoadOrShare: LoadKey failed and slot not in registry";
        return score::crypto::make_unexpected(load_result.error());
    }

    return RegisterKeyMaterial(params, std::move(load_result.value()));
}

// ---------------------------------------------------------------------------
// ReleaseKeyMaterial
// ---------------------------------------------------------------------------

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> KeyManagementService::ReleaseKeyMaterial(
    data_manager::ClientId client_id,
    data_manager::DataNodeId ref_node_id)
{
    // Deleting the node from the DataManager triggers ~KeyDataNode which
    // calls Release() on the shared KeyDataNode and, if it was the last
    // reference, invokes the unregister callback to remove the key from the
    // KeyRegistry.
    auto del_result = m_data_manager->deleteNode(client_id, ref_node_id);
    if (!del_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "ReleaseKeyMaterial: deleteNode failed";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }

    return std::monostate{};
}

// ---------------------------------------------------------------------------
// CleanupClient
// ---------------------------------------------------------------------------

void KeyManagementService::CleanupClient(data_manager::ClientId client_id)
{
    m_slot_node_cache.erase(client_id);
    for (auto& [provider_id, registry] : m_registries)
    {
        static_cast<void>(provider_id);
        registry.CleanupClient(client_id);
    }
}

// ---------------------------------------------------------------------------
// GetProviderRegistry
// ---------------------------------------------------------------------------

KeyRegistry& KeyManagementService::GetProviderRegistry(const common::ProviderId& provider_id)
{
    return m_registries[provider_id];
}

// ---------------------------------------------------------------------------
// CreateKeyDataNode
// ---------------------------------------------------------------------------

Expected<KeyDataNodeResult, score::crypto::daemon::common::DaemonErrorCode> KeyManagementService::CreateKeyDataNode(
    data_manager::ClientId client_id,
    data_manager::DataNodeId parent_id,
    std::shared_ptr<KeyEntry> key_node,
    KeyRegistryId registry_id,
    const common::ProviderId& provider_id)
{
    auto& registry = GetProviderRegistry(provider_id);

    auto captured_key_node = key_node;  // keep a copy before move

    auto ref_node =
        std::make_shared<KeyDataNode>(std::move(key_node), registry_id, client_id, [&registry](KeyRegistryId id) {
            registry.Unregister(id);
        });

    auto node_id_result = m_data_manager->addChildNode(client_id, parent_id, ref_node);
    if (!node_id_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "CreateKeyDataNode: addChildNode failed";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    return KeyDataNodeResult{node_id_result.value(), std::move(captured_key_node)};
}

// ---------------------------------------------------------------------------
// ResolveKeySlot
// ---------------------------------------------------------------------------

Expected<data_manager::DataNodeId, score::crypto::daemon::common::DaemonErrorCode> KeyManagementService::ResolveKeySlot(
    const std::string& resource_name,
    data_manager::ClientId client_id)
{
    // Dedup: return cached DataNodeId when the same client resolves the same resource twice.
    auto& client_cache = m_slot_node_cache[client_id];
    const auto cache_it = client_cache.find(resource_name);
    if (cache_it != client_cache.end())
    {
        return cache_it->second;
    }

    // Resolve via SlotRegistry (performs access-policy check).
    auto handle_result = m_slot_registry->ResolveAppResource(resource_name, client_id);
    if (!handle_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "ResolveKeySlot: SlotRegistry::ResolveAppResource failed for '"
                                   << resource_name << "'";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }

    // Create a lightweight KeySlotDataNode and register it in the DataManager.
    auto slot_node = std::make_shared<KeySlotDataNode>(handle_result.value(), m_slot_registry);
    auto node_id_result = m_data_manager->addNode(client_id, std::move(slot_node));
    if (!node_id_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "ResolveKeySlot: addNode failed";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    client_cache[resource_name] = node_id_result.value();
    return node_id_result.value();
}

// ---------------------------------------------------------------------------
// ResolveSlotForOperation
// ---------------------------------------------------------------------------

Expected<SlotResolution, score::crypto::daemon::common::DaemonErrorCode> KeyManagementService::ResolveSlotForOperation(
    data_manager::ClientId client_id,
    data_manager::DataNodeId slot_node_id)
{
    auto accessor_res = m_data_manager->getNodeAccessor(client_id, slot_node_id);
    if (!accessor_res.has_value())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }

    auto slot_acc = std::move(accessor_res.value()).downCast<KeySlotDataNode>();
    if (!slot_acc.has_value())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }

    const auto& slot_node = *slot_acc.value();
    const auto slot_handle = slot_node.GetSlotHandle();
    auto slot_cfg_res = slot_node.GetConfig();
    if (!slot_cfg_res.has_value())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }

    return SlotResolution{slot_cfg_res.value(), slot_handle};
}

// ---------------------------------------------------------------------------
// ResolveKeyForOperation
// ---------------------------------------------------------------------------

Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
KeyManagementService::ResolveKeyForOperation(data_manager::ClientId client_id,
                                             data_manager::DataNodeId key_node_id) const
{
    auto accessor_res = m_data_manager->getNodeAccessor(client_id, key_node_id);
    if (!accessor_res.has_value())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }

    auto ref_acc = std::move(accessor_res.value()).downCast<KeyDataNode>();
    if (!ref_acc.has_value())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidResourceId);
    }

    auto key_node = ref_acc.value()->GetKeyEntry();
    if (!key_node)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    auto handler = key_node->GetKeyHandler();
    if (!handler)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    return handler;
}

// ---------------------------------------------------------------------------
// BindKeyToContext
// ---------------------------------------------------------------------------

Expected<KeyBindingResult, score::crypto::daemon::common::DaemonErrorCode> KeyManagementService::BindKeyToContext(
    data_manager::ClientId client_id,
    data_manager::DataNodeId context_node_id,
    data_manager::DataNodeId key_node_id,
    const common::ProviderId& target_provider_id)
{
    // ------------------------------------------------------------------
    // Single accessor lookup + GetNodeType() dispatch.
    //
    // Follows the same pattern as ResolveTargetProvider: read the node
    // type tag first, then downCast inside the matching branch. This
    // avoids the previous double-getNodeAccessor + trial-downcast pattern.
    // ------------------------------------------------------------------
    auto node_accessor = m_data_manager->getNodeAccessor(client_id, key_node_id);
    if (!node_accessor.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX
                                   << "BindKeyToContext: node lookup failed for key_node_id=" << key_node_id;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    const auto node_type = node_accessor.value()->GetNodeType();

    // ------------------------------------------------------------------
    // Slot-direct path (KeySlotDataNode).
    //
    // Resolve the slot's primary provider, obtain its IKeySlotHandler,
    // and delegate to LoadOrShare which handles HW deduplication.
    // The resulting KeyDataNode is parented under context_node_id so
    // it is cascade-deleted when the context is closed.
    // ------------------------------------------------------------------
    if (node_type == data_manager::DataNodeType::kKeySlot)
    {
        auto slot_acc = std::move(node_accessor.value()).downCast<KeySlotDataNode>();
        if (!slot_acc.has_value())
        {
            score::mw::log::LogError() << LOG_PREFIX << "BindKeyToContext: kKeySlot downCast failed (internal)";
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
        }

        auto* slot_node = &(*slot_acc.value());
        auto slot_config_res = slot_node->GetConfig();
        if (!slot_config_res.has_value())
        {
            score::mw::log::LogError() << LOG_PREFIX
                                       << "BindKeyToContext: KeySlotDataNode has no config "
                                          "(key_node_id="
                                       << key_node_id << ")";
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }
        const auto* slot_config = slot_config_res.value();
        const auto slot_handle = slot_node->GetSlotHandle();

        // Determine the primary provider for this slot.
        auto primary_prov_res = m_slot_registry->GetPrimaryProviderId(slot_handle);
        if (!primary_prov_res.has_value())
        {
            score::mw::log::LogError() << LOG_PREFIX << "BindKeyToContext: no primary provider for slot "
                                       << key_node_id;
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }
        const common::ProviderId& slot_provider_id = primary_prov_res.value();

        // Cross-provider guard: key's provider must match the target context provider.
        if (target_provider_id != common::kInvalidProviderId && slot_provider_id != target_provider_id)
        {
            score::mw::log::LogError() << LOG_PREFIX << "BindKeyToContext: cross-provider binding not supported "
                                       << "(key provider=" << slot_provider_id
                                       << ", target provider=" << target_provider_id << ")";
            return score::crypto::make_unexpected(
                score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
        }

        auto slot_provider = m_provider_manager->GetProvider(slot_provider_id);
        if (!slot_provider)
        {
            score::mw::log::LogError() << LOG_PREFIX << "BindKeyToContext: provider '" << slot_provider_id
                                       << "' not found";
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }

        auto slot_handler = slot_provider->GetKeySlotHandler(*slot_config);
        if (!slot_handler)
        {
            score::mw::log::LogError() << LOG_PREFIX << "BindKeyToContext: provider '" << slot_provider_id
                                       << "' does not support slot operations";
            return score::crypto::make_unexpected(
                score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
        }

        // Load (or reuse) key material; ref node parented under context.
        auto ref_result =
            LoadOrShare({client_id, context_node_id, slot_provider_id, slot_handle}, *slot_handler, *slot_config);
        if (!ref_result.has_value())
        {
            score::mw::log::LogError() << LOG_PREFIX << "BindKeyToContext: LoadOrShare failed for" << key_node_id;
            return score::crypto::make_unexpected(ref_result.error());
        }

        // KeyDataNodeResult carries the KeyEntry — no re-lookup needed.
        return KeyBindingResult{
            ref_result.value().key_node->GetKeyHandler(),
            ref_result.value().node_id,
        };
    }

    // ------------------------------------------------------------------
    // Loaded-key path (KeyDataNode).
    //
    // Create a NEW KeyDataNode child under context_node_id so the
    // context owns its own reference.  The user's original ref stays
    // independent — releasing it will not affect the context's binding.
    // ------------------------------------------------------------------
    if (node_type == data_manager::DataNodeType::kKeyData)
    {
        auto ref_acc = std::move(node_accessor.value()).downCast<KeyDataNode>();
        if (!ref_acc.has_value())
        {
            score::mw::log::LogError() << LOG_PREFIX << "BindKeyToContext: kKeyData downCast failed (internal)";
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
        }

        auto key_data_node = ref_acc.value()->GetKeyEntry();
        if (!key_data_node)
        {
            score::mw::log::LogError() << LOG_PREFIX
                                       << "BindKeyToContext: KeyDataNode has no backing "
                                          "KeyDataNode";
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }

        // Cross-provider guard: key's provider must match the target context provider.
        const auto& key_provider_id = key_data_node->GetProviderId();
        if (target_provider_id != common::kInvalidProviderId && key_provider_id != target_provider_id)
        {
            score::mw::log::LogError() << LOG_PREFIX << "BindKeyToContext: cross-provider binding not supported "
                                       << "(key provider=" << key_provider_id
                                       << ", target provider=" << target_provider_id << ")";
            return score::crypto::make_unexpected(
                score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
        }

        const auto registry_id = ref_acc.value()->GetRegistryId();

        auto new_ref_result =
            CreateKeyDataNode(client_id, context_node_id, key_data_node, registry_id, key_provider_id);
        if (!new_ref_result.has_value())
        {
            score::mw::log::LogError() << LOG_PREFIX
                                       << "BindKeyToContext: failed to create context-owned "
                                          "KeyDataNode for loaded key";
            return score::crypto::make_unexpected(new_ref_result.error());
        }

        return KeyBindingResult{
            key_data_node->GetKeyHandler(),
            new_ref_result.value().node_id,
        };
    }

    // Neither kKeySlot nor kKeyData invalid argument.
    score::mw::log::LogError() << LOG_PREFIX << "BindKeyToContext: key_node_id=" << key_node_id
                               << " is neither a KeySlotDataNode nor a KeyDataNode"
                               << " (node_type=" << static_cast<int>(node_type) << ")";
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// Provider resolution for keyed contexts
// ---------------------------------------------------------------------------

Expected<common::ProviderId, score::crypto::daemon::common::DaemonErrorCode>
KeyManagementService::ResolveTargetProvider(data_manager::ClientId client_id,
                                            common::CryptoProviderType requested_type,
                                            std::optional<data_manager::DataNodeId> key_node_id)
{
    // No key binding ? resolve purely from provider type.
    if (!key_node_id.has_value())
    {
        auto provider = m_provider_manager->GetProvider(requested_type);
        if (!provider)
        {
            score::mw::log::LogError() << LOG_PREFIX << "ResolveTargetProvider: no provider for type "
                                       << static_cast<int>(requested_type);
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }
        return provider->GetProviderId();
    }

    // Key supplied — resolve node type and extract provider affinity.
    auto node_accessor = m_data_manager->getNodeAccessor(client_id, key_node_id.value());
    if (!node_accessor.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "ResolveTargetProvider: node lookup failed for key_node_id="
                                   << key_node_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    const auto node_type = node_accessor.value()->GetNodeType();

    // ------- KeySlotDataNode (slot-direct path) -------
    if (node_type == data_manager::DataNodeType::kKeySlot)
    {
        auto slot_acc = std::move(node_accessor.value()).downCast<KeySlotDataNode>();
        if (!slot_acc.has_value())
        {
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
        }
        auto config_res = slot_acc.value()->GetConfig();
        if (!config_res.has_value() || config_res.value()->provider_ids.empty())
        {
            score::mw::log::LogError() << LOG_PREFIX << "ResolveTargetProvider: slot has no config or providers";
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }
        const auto* config = config_res.value();

        if (requested_type == common::CryptoProviderType::DEFAULT)
        {
            return config->GetPrimaryProviderId();
        }

        // Filter slot's provider list by type compatibility (primary first).
        for (const auto& pid : config->provider_ids)
        {
            if (m_provider_manager->IsProviderCompatibleWithType(pid, requested_type))
            {
                return pid;
            }
        }

        score::mw::log::LogError() << LOG_PREFIX << "ResolveTargetProvider: no compatible provider for slot '"
                                   << config->slot_name << "' with type" << static_cast<int>(requested_type);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    // ------- KeyDataNode (loaded-key path) -------
    if (node_type == data_manager::DataNodeType::kKeyData)
    {
        auto ref_acc = std::move(node_accessor.value()).downCast<KeyDataNode>();
        if (!ref_acc.has_value())
        {
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
        }
        auto key_data_node = ref_acc.value()->GetKeyEntry();
        if (!key_data_node)
        {
            score::mw::log::LogError() << LOG_PREFIX
                                       << "ResolveTargetProvider: KeyDataNode has no "
                                          "backing KeyDataNode";
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }

        const auto& key_provider_id = key_data_node->GetProviderId();

        if (requested_type == common::CryptoProviderType::DEFAULT)
        {
            return key_provider_id;
        }

        if (m_provider_manager->IsProviderCompatibleWithType(key_provider_id, requested_type))
        {
            return key_provider_id;
        }

        score::mw::log::LogError() << LOG_PREFIX << "ResolveTargetProvider: key's provider '" << key_provider_id
                                   << "' incompatible with type" << static_cast<int>(requested_type);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    score::mw::log::LogError() << LOG_PREFIX << "ResolveTargetProvider: key_node_id=" << key_node_id.value()
                               << " is neither a KeySlotDataNode nor a KeyDataNode";
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
}

}  // namespace score::crypto::daemon::key_management
