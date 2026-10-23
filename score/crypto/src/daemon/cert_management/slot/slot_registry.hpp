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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_SLOT_REGISTRY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_SLOT_REGISTRY_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// @brief Internal registry entry for a certificate slot. Owned by CertSlotRegistry.
struct CertSlotRegistryEntry
{
    /// Immutable slot configuration registered at daemon startup.
    CertSlotConfig config;
};

/// @brief Groups the stable identity/location parameters for cert registration operations.
struct CertRegistrationParams
{
    /// Client that owns the certificate data node being registered.
    data_manager::ClientId client_id{0U};
    /// Parent data node under which the certificate node is created.
    data_manager::DataNodeId parent_id{0U};
    /// Source slot handle, or a default invalid handle for an ephemeral certificate.
    CertSlotHandle slot_handle{};
};

/// @brief Central registry for all certificate slot configurations.
///
/// Single source of truth for slot configs and per-slot state.
/// Per-connection CertSlotDataNodes hold only a lightweight CertSlotHandle
/// referencing entries in this registry.
///
/// Thread safety: register slots and application resource mappings before
/// concurrent request handling begins. The slot table and both indexes are
/// immutable afterward, so lock-free lookups may run concurrently. Do not call
/// RegisterSlot concurrently with ResolveSlot, ResolveSlotInternal, GetConfig,
/// or GetSlotCount, or RegisterAppResource concurrently with ResolveAppResource.
/// The internal mutex serializes registration updates and GetAllHandles snapshots.
class CertSlotRegistry : public std::enable_shared_from_this<CertSlotRegistry>
{
  public:
    using Sptr = std::shared_ptr<CertSlotRegistry>;

    CertSlotRegistry() = default;
    ~CertSlotRegistry() = default;

    CertSlotRegistry(const CertSlotRegistry&) = delete;
    CertSlotRegistry& operator=(const CertSlotRegistry&) = delete;
    CertSlotRegistry(CertSlotRegistry&&) = delete;
    CertSlotRegistry& operator=(CertSlotRegistry&&) = delete;

    /// @brief Register a certificate slot with the registry.
    ///
    /// Slot registration is a startup operation and must complete before
    /// concurrent slot lookups begin. Duplicate names are ignored.
    ///
    /// @param config Fully populated slot configuration.
    /// @return A lightweight handle to the registered slot, or an invalid
    ///         default handle if a slot with this name is already registered.
    /// @note Serialized with other slot registrations and GetAllHandles(). Must
    ///       not overlap lock-free slot lookups.
    CertSlotHandle RegisterSlot(CertSlotConfig config);

    /// @brief Resolve slot name + client_id → CertSlotHandle.
    ///
    /// Checks access policy before returning the handle.
    /// @param slot_name Name of the configured slot.
    /// @param client_id Client requesting access to the slot.
    /// @return The slot handle, or an error if the name is unknown or access is denied.
    /// @note Lock-free read; call only after slot registration is complete.
    score::crypto::Expected<CertSlotHandle, score::crypto::daemon::common::DaemonErrorCode> ResolveSlot(
        const std::string& slot_name,
        data_manager::ClientId client_id) const;

    /// @brief Resolve slot name → CertSlotHandle without access-policy checks.
    ///
    /// For daemon-internal callers (e.g. TrustStoreManager) that operate on
    /// integrator-configured slot names and are not subject to client access
    /// control. Must not be called from client-request code paths.
    /// @param slot_name Name of the configured slot.
    /// @return The slot handle, or kInvalidResourceId if the name is unknown.
    /// @note Lock-free read; call only after slot registration is complete.
    score::crypto::Expected<CertSlotHandle, score::crypto::daemon::common::DaemonErrorCode> ResolveSlotInternal(
        const std::string& slot_name) const;

    /// @brief Read-only access to a slot's configuration via handle.
    /// @param handle Handle of the slot to inspect.
    /// @return A non-owning reference to the registry-owned configuration, or
    ///         kInvalidResourceId if the handle is invalid. The reference is
    ///         valid only while this registry remains alive and its slot table is
    ///         not modified; slot registration is therefore restricted to startup.
    /// @note Lock-free read; call only after slot registration is complete.
    score::crypto::Expected<std::reference_wrapper<const CertSlotConfig>,
                            score::crypto::daemon::common::DaemonErrorCode>
    GetConfig(CertSlotHandle handle) const;

    /// @brief Get the total number of registered slots.
    /// @return The number of registered slots.
    /// @note Lock-free read; call only after slot registration is complete.
    std::size_t GetSlotCount() const noexcept;

    /// @brief Return a snapshot of handles for all registered slots.
    ///
    /// Intended for daemon-internal enumeration. The returned handles are not
    /// filtered by client access policy; client request paths should resolve
    /// resources through ResolveSlot() or ResolveAppResource().
    /// @return Handles for all slots registered when the snapshot is taken.
    /// @note Acquires the internal mutex and may run concurrently with slot registration.
    std::vector<CertSlotHandle> GetAllHandles() const;

    /// @brief Register an application-local resource ID mapping.
    ///
    /// Called at startup by ConfigDrivenSlotCatalog for each AppCertSlotEntry.
    /// Maps (uid, app_resource_id) → actual cert slot name in this registry.
    ///
    /// @param uid             UID of the application.
    /// @param app_resource_id Application-local name (e.g., "vehicle_tls_cert").
    /// @param slot_name       Actual slot name registered in this registry.
    /// @note Duplicate (UID, resource ID) mappings are ignored.
    /// @note Serialized with registration updates; complete before resource lookups begin.
    void RegisterAppResource(uint32_t uid, const std::string& app_resource_id, const std::string& slot_name);

    /// @brief Resolve an application resource ID to a CertSlotHandle.
    ///
    /// Looks up (uid, app_resource_id) in the per-UID resource map, then
    /// resolves the resulting slot name with access-policy checks.
    ///
    /// @param app_resource_id  Application-local resource name.
    /// @param client_id        Composite PID|UID of the requesting connection.
    /// @return The slot handle on success, or an error if the mapping is absent,
    ///         the slot is unknown, or client access is denied.
    /// @note Lock-free read; call only after application resource registration is complete.
    score::crypto::Expected<CertSlotHandle, score::crypto::daemon::common::DaemonErrorCode> ResolveAppResource(
        const std::string& app_resource_id,
        data_manager::ClientId client_id) const;

  private:
    /// Check whether @p handle refers to an entry in the registered slot table.
    /// @param handle Handle to validate.
    /// @return true if the handle is valid; false otherwise.
    bool IsValidHandle(CertSlotHandle handle) const noexcept;

    std::vector<CertSlotRegistryEntry> m_registry;
    std::unordered_map<std::string, uint32_t> m_name_index;
    /// Per-UID app resource map: uid → { app_resource_id → slot_name }.
    /// Populated at startup by RegisterAppResource(); read-only after that.
    std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>> m_app_resource_map;
    mutable std::mutex m_mutex;

    static constexpr std::string_view kLogPrefix = "[CERT_SLOT_REGISTRY] ";
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_SLOT_REGISTRY_HPP
