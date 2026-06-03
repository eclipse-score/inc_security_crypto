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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_REGISTRY_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_REGISTRY_HPP

#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace score::crypto::daemon::provider
{
class ProviderManager;  // Forward declaration
}  // namespace score::crypto::daemon::provider

namespace score::crypto::daemon::key_management
{

/// @brief Lightweight token referencing a slot entry in SlotRegistry.
///
/// Cheap to copy (≈8 bytes). Used by KeySlotDataNode instead of copying
/// KeySlotConfig. The index refers to SlotRegistry's internal registry
/// vector. UINT32_MAX indicates an invalid/uninitialized handle.
struct SlotHandle
{
    uint32_t index{UINT32_MAX};

    bool IsValid() const noexcept
    {
        return index != UINT32_MAX;
    }

    bool operator==(const SlotHandle& other) const noexcept
    {
        return index == other.index;
    }

    bool operator!=(const SlotHandle& other) const noexcept
    {
        return !(*this == other);
    }
};

/// @brief Internal registry entry for a key slot. Owned by SlotRegistry.
///
/// Not exposed to data nodes — accessed only through SlotRegistry's API.
struct SlotRegistryEntry
{
    KeySlotConfig config;  ///< The full config — exists ONCE, shared across all contexts
};

// ---------------------------------------------------------------------------
// KeyRegistrationParams — common parameters for key registration operations
// ---------------------------------------------------------------------------

/// Groups the stable identity/location parameters shared by
/// RegisterKeyMaterial and LoadOrShare, reducing their argument counts.
struct KeyRegistrationParams
{
    data_manager::ClientId client_id{0U};
    data_manager::DataNodeId parent_id{0U};
    common::ProviderId provider_id{common::kInvalidProviderId};
    SlotHandle slot_handle{};  ///< Non-default only when loading from a slot.
};

/// @brief Central registry for all key slot configurations.
///
/// Single source of truth for slot configs, slot handlers, and per-slot state.
/// Per-connection KeySlotDataNodes hold only a lightweight SlotHandle (≈8 bytes)
/// referencing entries in this registry — they do NOT copy KeySlotConfig.
///
/// Thread safety: The registry is protected by a mutex for state mutations.
/// Config reads are safe without locking after initialization (configs are
/// immutable after setup).
class SlotRegistry : public std::enable_shared_from_this<SlotRegistry>
{
  public:
    using Sptr = std::shared_ptr<SlotRegistry>;

    SlotRegistry() = default;
    ~SlotRegistry() = default;

    // Non-copyable, non-movable (shared via Sptr)
    SlotRegistry(const SlotRegistry&) = delete;
    SlotRegistry& operator=(const SlotRegistry&) = delete;
    SlotRegistry(SlotRegistry&&) = delete;
    SlotRegistry& operator=(SlotRegistry&&) = delete;

    /// @brief Register a key slot with the registry.
    ///
    /// Called by IKeySlotCatalog::Load() at startup, or dynamically when a new
    /// hardware slot is provisioned at runtime. Thread-safe.
    ///
    /// @param config  Fully-populated slot configuration.
    /// @return        A lightweight handle to the registered slot.
    SlotHandle RegisterSlot(KeySlotConfig config);

    // Implementation note: this manager exposes slot availability only via
    // `SlotAvailability` (`kActive`, `kDisabled`, `kUnavailable`).
    // `kUnavailable` indicates the slot cannot be used (for example, the
    // provider or hardware is unreachable); it blocks new usages while
    // allowing existing in-flight usages to complete.
    //
    // Persistent configuration changes (adding/removing slots) are performed
    // through the configuration/catalog management path and are the source of
    // truth across restarts. If operators require an in-memory admin API for
    // hot-reload or controlled removals in the future, introduce a dedicated
    // admin endpoint that: emits audit events, documents orphaning semantics,
    // and coordinates persistence with the configuration service.

    /// @brief Resolve slot name + client_id → SlotHandle.
    ///
    /// This is a **passive** operation — it grants the connection a lightweight
    /// reference to the slot but does NOT constitute active key usage.
    /// No counter increment, no side effects. ~KeySlotDataNode is a no-op.
    ///
    /// Resolution steps:
    ///   1. Look up slot_name in m_name_index.
    ///   2. Extract UID from client_id.
    ///   3. Check access_policy.allowed_uids contains UID.
    ///   4. Return SlotHandle on success.
    ///
    /// @param slot_name  Human-readable slot name (e.g., "test/hmac-sha256")
    /// @param client_id  Composite PID|UID of the requesting connection
    /// @return SlotHandle on success, or DaemonErrorCode on failure.
    score::crypto::Expected<SlotHandle, score::crypto::daemon::common::DaemonErrorCode> ResolveSlot(
        const std::string& slot_name,
        data_manager::ClientId client_id) const;

    /// @brief Atomically check slot availability and acquire usage.
    ///
    /// @deprecated Will be removed. Usage counting is not wired into production.

    /// @brief Read-only access to config via handle.
    ///
    /// Returns a pointer to the central entry config.
    ///
    /// @param handle  Slot handle obtained from RegisterSlot or ResolveSlot.
    /// @return config pointer (valid for duration of operation), or kInvalidResourceId.
    score::crypto::Expected<const KeySlotConfig*, score::crypto::daemon::common::DaemonErrorCode> GetConfig(
        SlotHandle handle) const;

    /// @brief Register an application-local resource ID mapping.
    ///
    /// Called at startup by the catalog for each per-app mapping entry.
    /// Maps (uid, app_resource_id) → actual slot name in the registry.
    ///
    /// @param uid             UID of the application.
    /// @param app_resource_id Application-local name (e.g., "signing_key").
    /// @param slot_name       Actual slot name registered in this manager.
    void RegisterAppResource(uint32_t uid, const std::string& app_resource_id, const std::string& slot_name);

    /// @brief Resolve an application resource ID to a SlotHandle.
    ///
    /// Looks up (uid, app_resource_id) in the per-UID resource map, then
    /// resolves the resulting slot name with access-policy checks.
    ///
    /// @param app_resource_id  Application-local resource name.
    /// @param client_id        Composite PID|UID of the requesting connection.
    /// @return SlotHandle on success, or kInvalidResourceId if no mapping exists.
    score::crypto::Expected<SlotHandle, score::crypto::daemon::common::DaemonErrorCode> ResolveAppResource(
        const std::string& app_resource_id,
        data_manager::ClientId client_id) const;

    /// @brief Get the total number of registered slots. Useful for testing.
    std::size_t GetSlotCount() const noexcept;

    /// @brief Return the primary provider ID for a slot.
    ///
    /// The primary provider is `config.provider_ids[0]` — the sole writer.
    ///
    /// @return The primary ProviderId, or DaemonErrorCode on failure (invalid
    ///         handle, empty provider list).
    score::crypto::Expected<common::ProviderId, score::crypto::daemon::common::DaemonErrorCode> GetPrimaryProviderId(
        SlotHandle handle) const;

    /// @brief Check whether `provider_id` is permitted to access a slot.
    ///
    /// Returns std::monostate if `provider_id` appears anywhere in `config.provider_ids`.
    /// Returns kAccessDenied if it is not listed or the handle is invalid.
    ///
    /// @param handle       Slot to check.
    /// @param provider_id  Provider to validate.
    /// @return std::monostate if access is permitted, or DaemonErrorCode on failure.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> IsProviderAllowedForSlot(
        SlotHandle handle,
        const common::ProviderId& provider_id) const;

    /// @brief Resolve provider names to numeric IDs in all slots.
    ///
    /// Called once after ProviderManager::Initialize() to convert human-readable
    /// provider names (from config) to numeric IDs (assigned by ProviderManager).
    /// This ensures all runtime lookups use fast numeric comparisons.
    ///
    /// For each slot:
    ///   1. Iterate over provider_names
    ///   2. Call provider_manager.GetProvider(name) to get the instance
    ///   3. Call instance->GetProviderId() to get the numeric ID
    ///   4. Append numeric ID to provider_ids
    ///   5. Log warning if a name is not found
    ///
    /// After this call, provider_ids is populated and ready for runtime.
    /// provider_names may be cleared after this to save memory (future).
    ///
    /// @param provider_manager  The ProviderManager instance (post-Initialize).
    void ResolveProviderIds(const provider::ProviderManager& provider_manager);

  private:
    /// @brief Validate a SlotHandle before use.
    bool IsValidHandle(SlotHandle handle) const noexcept;

    std::vector<SlotRegistryEntry> m_registry;               ///< Central slot storage
    std::unordered_map<std::string, uint32_t> m_name_index;  ///< name → registry index
    /// Per-UID app resource map: uid → { app_resource_id → slot_name }.
    /// Populated at startup by RegisterAppResource(); read-only after that.
    std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>> m_app_resource_map;
    mutable std::mutex m_mutex;  ///< Protects state changes

    static constexpr std::string_view LOG_PREFIX = "[SLOT_REGISTRY]";
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_SLOT_REGISTRY_HPP
