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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_CORE_KEY_MANAGEMENT_SERVICE_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_CORE_KEY_MANAGEMENT_SERVICE_HPP

#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/daemon/key_management/core/key_registry.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_slot_handler.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/daemon/key_management/slot/slot_registry.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>

namespace score::crypto::daemon::key_management
{

/// Outcome of a successful slot resolution.
struct SlotResolution
{
    const KeySlotConfig* config;  ///< Points to config in SlotRegistry (valid for operation duration).
    SlotHandle handle;            ///< Lightweight token for the resolved slot.
};

/// Outcome of a key-to-context binding.
///
/// Returned by BindKeyToContext so the mediator can pass the IKeyHandler
/// to the crypto handler via InitializationParams.bound_key_handler.
struct KeyBindingResult
{
    IKeyHandler::Sptr key_handler;              ///< Bound key handler for the provider.
    data_manager::DataNodeId resolved_node_id;  ///< KeyDataNode id (may differ from
                                                ///< input when slot-direct path was used).
};

/// Internal result of CreateKeyDataNode / RegisterKeyMaterial / LoadOrShare.
///
/// Carries both the new DataNodeId and the backing KeyEntry so that
/// callers avoid a redundant DataManager re-lookup (see BindKeyToContext).
struct KeyDataNodeResult
{
    data_manager::DataNodeId node_id;
    std::shared_ptr<KeyEntry> key_node;
};

/// Core orchestration service for key management operations.
///
/// Provides primitives consumed by provider executors for DataNode lifecycle
/// management, slot resolution, and context-level key binding (single-provider only).
///
/// Provider-specific crypto operations (GenerateKey, DeriveKey, LoadKey, etc.)
/// are NOT part of this service. Executors call IKeyFactory and IKeySlotHandler
/// directly for those, then use the service for bookkeeping integration.
///
/// Thread safety: methods are serialized by the underlying DataManager and
/// SlotRegistry mutexes. The service itself holds no mutable state beyond
/// the injected shared pointers.
class KeyManagementService final
{
  public:
    using Sptr = std::shared_ptr<KeyManagementService>;

    KeyManagementService(data_manager::IDataManager::Sptr data_manager,
                         provider::ProviderManager::Sptr provider_manager,
                         SlotRegistry::Sptr slot_registry);

    ~KeyManagementService() = default;

    KeyManagementService(const KeyManagementService&) = delete;
    KeyManagementService& operator=(const KeyManagementService&) = delete;
    KeyManagementService(KeyManagementService&&) = delete;
    KeyManagementService& operator=(KeyManagementService&&) = delete;

    // ------------------------------------------------------------------
    // DataNode lifecycle
    // ------------------------------------------------------------------

    /// Register a newly created key in the provider's KeyRegistry and place
    /// a KeyDataNode in the client's tree under parent_id.
    ///
    /// Ownership of the IKeyHandler is transferred to the KeyDataNode which
    /// lives in the registry.  The returned DataNodeId identifies the
    /// KeyDataNode (the guard) in the client's DataManager tree.
    ///
    /// @param params   Client, parent, provider, and optional slot identity.
    /// @param handler  Key handler produced by IKeyFactory or IKeySlotHandler.
    /// @return DataNodeId of the KeyDataNode on success.
    [[nodiscard]] Expected<KeyDataNodeResult, score::crypto::daemon::common::DaemonErrorCode> RegisterKeyMaterial(
        const KeyRegistrationParams& params,
        IKeyHandler::Sptr handler);

    /// Load a key from a slot, reusing an existing registry entry when the
    /// provider already holds the key (HW deduplication).
    ///
    /// If the slot is already loaded in the provider's registry, a new
    /// KeyDataNode is created referencing the existing KeyDataNode.
    /// Otherwise, slot_handler.LoadKey() is called to produce a fresh
    /// IKeyHandler which is then registered.
    ///
    /// @param params        Client, parent, provider, and slot identity.
    /// @param slot_handler  Provider slot handler for LoadKey().
    /// @param slot_config   Resolved slot configuration.
    /// @return DataNodeId of the KeyDataNode on success.
    [[nodiscard]] Expected<KeyDataNodeResult, score::crypto::daemon::common::DaemonErrorCode>
    LoadOrShare(const KeyRegistrationParams& params, IKeySlotHandler& slot_handler, const KeySlotConfig& slot_config);

    /// Release a client's reference to a key.
    ///
    /// Looks up the KeyDataNode by ref_node_id, removes it from the
    /// DataManager tree, and decrements the KeyDataNode's reference count.
    /// When the last reference is dropped, the key is unregistered from
    /// the KeyRegistry and its destructor securely zeroizes key material.
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ReleaseKeyMaterial(
        data_manager::ClientId client_id,
        data_manager::DataNodeId ref_node_id);

    /// Remove all key references for a disconnected or crashed client.
    ///
    /// Called as a safety net after DataManager::deleteClientNodes().
    void CleanupClient(data_manager::ClientId client_id);

    // ------------------------------------------------------------------
    // Context-level key binding
    // ------------------------------------------------------------------

    /// Bind a key (loaded or slot) to a context at creation time.
    ///
    /// Accepts either a KeySlotDataNode ID (slot-direct path) or a
    /// KeyDataNode ID (loaded-key path).  For the slot-direct path the
    /// service internally loads the key via LoadOrShare and parents the
    /// resulting KeyDataNode under @p context_node_id so it is released
    /// automatically when the context is closed.
    ///
    /// @param client_id         Owning client.
    /// @param context_node_id   Context the key is bound to.
    /// @param key_node_id       DataNodeId of a KeySlotDataNode or KeyDataNode.
    /// @param target_provider_id Provider that owns the context; cross-provider
    ///                          binding returns kNotSupported.
    /// @return KeyBindingResult on success; DaemonErrorCode on failure.
    [[nodiscard]] Expected<KeyBindingResult, score::crypto::daemon::common::DaemonErrorCode> BindKeyToContext(
        data_manager::ClientId client_id,
        data_manager::DataNodeId context_node_id,
        data_manager::DataNodeId key_node_id,
        const common::ProviderId& target_provider_id);

    // ------------------------------------------------------------------
    // Provider resolution for keyed contexts
    // ------------------------------------------------------------------

    /// Resolve the target provider for a keyed context creation.
    ///
    /// Considers the key/slot's provider affinity and the caller's requested
    /// provider type to determine which provider should create the handler.
    ///
    /// Resolution precedence:
    ///   - No key ? GetProvider(requested_type)
    ///   - Key + DEFAULT type ? primary provider of key/slot
    ///   - Key + specific type ? first compatible provider from key/slot's
    ///     provider list; hard fail if none match.
    ///
    /// @param client_id        Client requesting the context.
    /// @param requested_type   Provider type preference (DEFAULT = any).
    /// @param key_node_id      DataNodeId of a KeySlotDataNode or KeyDataNode,
    ///                         or std::nullopt when no key is involved.
    /// @return ProviderId on success; DaemonErrorCode on failure.
    [[nodiscard]] Expected<common::ProviderId, score::crypto::daemon::common::DaemonErrorCode> ResolveTargetProvider(
        data_manager::ClientId client_id,
        common::CryptoProviderType requested_type,
        std::optional<data_manager::DataNodeId> key_node_id = std::nullopt);

    // ------------------------------------------------------------------
    // Slot orchestration
    // ------------------------------------------------------------------

    /// Resolve an application resource name to a session-scoped KeySlotDataNode.
    ///
    /// Performs SlotRegistry::ResolveAppResource(), creates a KeySlotDataNode if
    /// no node for this (client, resource) pair exists yet, and returns the
    /// DataNodeId to the caller. Repeated calls with the same arguments return
    /// the same DataNodeId (deduplication — fixes Point 5).
    [[nodiscard]] Expected<data_manager::DataNodeId, score::crypto::daemon::common::DaemonErrorCode> ResolveKeySlot(
        const std::string& resource_name,
        data_manager::ClientId client_id);

    /// Resolve a slot DataNode ID to its configuration and handle.
    [[nodiscard]] Expected<SlotResolution, score::crypto::daemon::common::DaemonErrorCode> ResolveSlotForOperation(
        data_manager::ClientId client_id,
        data_manager::DataNodeId slot_node_id);

    /// Resolve a key DataNode ID (a KeyDataNode) back to its IKeyHandler.
    ///
    /// Used by executor handlers that need a ProviderKeyHandle or the raw
    /// IKeyHandler to build provider-level request structs (WrapKey, ExportKey, ...).
    [[nodiscard]] Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode> ResolveKeyForOperation(
        data_manager::ClientId client_id,
        data_manager::DataNodeId key_node_id) const;

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    [[nodiscard]] data_manager::IDataManager::Sptr GetDataManager() const noexcept
    {
        return m_data_manager;
    }

    [[nodiscard]] SlotRegistry::Sptr GetSlotRegistry() const noexcept
    {
        return m_slot_registry;
    }

    [[nodiscard]] provider::ProviderManager::Sptr GetProviderManager() const noexcept
    {
        return m_provider_manager;
    }

    /// Retrieve (or create) the KeyRegistry for a given provider.
    [[nodiscard]] KeyRegistry& GetProviderRegistry(const common::ProviderId& provider_id);

  private:
    /// Create a KeyDataNode in the client tree pointing at the given
    /// KeyDataNode from the registry.
    [[nodiscard]] Expected<KeyDataNodeResult, score::crypto::daemon::common::DaemonErrorCode> CreateKeyDataNode(
        data_manager::ClientId client_id,
        data_manager::DataNodeId parent_id,
        std::shared_ptr<KeyEntry> key_node,
        KeyRegistryId registry_id,
        const common::ProviderId& provider_id);

    data_manager::IDataManager::Sptr m_data_manager;
    provider::ProviderManager::Sptr m_provider_manager;
    SlotRegistry::Sptr m_slot_registry;
    std::unordered_map<common::ProviderId, KeyRegistry> m_registries;

    /// Per-client cache of resolved resource names → DataNodeId.
    /// Cleared in CleanupClient(). Prevents duplicate KeySlotDataNodes.
    std::unordered_map<data_manager::ClientId, std::unordered_map<std::string, data_manager::DataNodeId>>
        m_slot_node_cache;
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_CORE_KEY_MANAGEMENT_SERVICE_HPP
