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
    CertSlotConfig config;
};

/// @brief Groups the stable identity/location parameters for cert registration operations.
struct CertRegistrationParams
{
    data_manager::ClientId client_id{0U};
    data_manager::DataNodeId parent_id{0U};
    CertSlotHandle slot_handle{};  ///< Non-default only when loading from a slot.
};

/// @brief Central registry for all certificate slot configurations.
///
/// Single source of truth for slot configs and per-slot state.
/// Per-connection CertSlotDataNodes hold only a lightweight CertSlotHandle
/// referencing entries in this registry.
///
/// Thread safety: all public methods serialise on an internal mutex.
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
    /// @param config  Fully-populated slot configuration.
    /// @return        A lightweight handle to the registered slot.
    CertSlotHandle RegisterSlot(CertSlotConfig config);

    /// @brief Resolve slot name + client_id → CertSlotHandle.
    ///
    /// Checks access policy before returning the handle.
    score::crypto::Expected<CertSlotHandle, score::crypto::daemon::common::DaemonErrorCode> ResolveSlot(
        const std::string& slot_name,
        data_manager::ClientId client_id) const;

    /// @brief Resolve slot name → CertSlotHandle without access-policy checks.
    ///
    /// For daemon-internal callers (e.g. TrustStoreManager) that operate on
    /// integrator-configured slot names and are not subject to client access
    /// control. Must not be called from client-request code paths.
    score::crypto::Expected<CertSlotHandle, score::crypto::daemon::common::DaemonErrorCode> ResolveSlotInternal(
        const std::string& slot_name) const;

    /// @brief Read-only access to config via handle.
    score::crypto::Expected<const CertSlotConfig*, score::crypto::daemon::common::DaemonErrorCode> GetConfig(
        CertSlotHandle handle) const;

    /// @brief Get the total number of registered slots.
    std::size_t GetSlotCount() const noexcept;

    /// @brief Return a snapshot of all registered slot configs.
    ///
    /// Used by services that need to iterate all slots (e.g., DeleteExpiredCrls).
    std::vector<CertSlotHandle> GetAllHandles() const;

    /// @brief Register an application-local resource ID mapping.
    ///
    /// Called at startup by ConfigDrivenSlotCatalog for each AppCertSlotEntry.
    /// Maps (uid, app_resource_id) → actual cert slot name in this registry.
    ///
    /// @param uid             UID of the application.
    /// @param app_resource_id Application-local name (e.g., "vehicle_tls_cert").
    /// @param slot_name       Actual slot name registered in this registry.
    void RegisterAppResource(uint32_t uid, const std::string& app_resource_id, const std::string& slot_name);

    /// @brief Resolve an application resource ID to a CertSlotHandle.
    ///
    /// Looks up (uid, app_resource_id) in the per-UID resource map, then
    /// resolves the resulting slot name with access-policy checks.
    ///
    /// @param app_resource_id  Application-local resource name.
    /// @param client_id        Composite PID|UID of the requesting connection.
    /// @return CertSlotHandle on success, or kInvalidResourceId if no mapping exists.
    score::crypto::Expected<CertSlotHandle, score::crypto::daemon::common::DaemonErrorCode> ResolveAppResource(
        const std::string& app_resource_id,
        data_manager::ClientId client_id) const;

  private:
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
