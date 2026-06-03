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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_MANAGEMENT_MODULE_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_MANAGEMENT_MODULE_HPP

#include "score/crypto/daemon/config/inc/config.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/daemon/key_management/slot/slot_registry.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"

#include <memory>
#include <string_view>

namespace score::crypto::daemon::key_management
{

/// @brief Composition root for the key management subsystem.
///
/// Wires together the slot registry and provider manager in dependency order:
///   1. Instantiates a slot catalog (ConfigDrivenSlotCatalog) and calls `Load(*slot_registry)`
///      to populate `SlotRegistry` with slot definitions.
///   2. Exposes `GetSlotRegistry()` and `GetProviderManager()` for the mediator
///      to create `KeyManagementContextDataNode` instances per client session.
///
/// The executor pattern is replaced by per-session context DataNodes created in
/// the mediator on `CTX_CREATE` operations. This module is created once at
/// daemon startup and its pointers are shared across all sessions.
class KeyManagementModule
{
  public:
    using Sptr = std::shared_ptr<KeyManagementModule>;

    /// @brief Initialize with parsed configuration (production path).
    ///
    /// Uses ConfigDrivenSlotCatalog to load slot definitions from the daemon's
    /// parsed KeyConfig section. Supports OpenSSL file-backed, PKCS#11, TEE,
    /// and any future provider — slot entries carry a deployment_path that each
    /// handler loads at runtime.
    ///
    /// @param data_manager      Thread-safe data store for session nodes.
    /// @param provider_manager  Provider registry for per-session handler dispatch.
    /// @param key_config        Parsed key configuration section.
    /// @return A fully initialized KeyManagementModule, or nullptr on failure.
    static Sptr Create(data_manager::IDataManager::Sptr data_manager,
                       provider::ProviderManager::Sptr provider_manager,
                       const config::KeyConfig& key_config);

    ~KeyManagementModule() = default;

    // Non-copyable, non-movable (shared via Sptr)
    KeyManagementModule(const KeyManagementModule&) = delete;
    KeyManagementModule& operator=(const KeyManagementModule&) = delete;
    KeyManagementModule(KeyManagementModule&&) = delete;
    KeyManagementModule& operator=(KeyManagementModule&&) = delete;

    /// @brief Get the key config manager (central slot registry).
    SlotRegistry::Sptr GetSlotRegistry() const;

    /// @brief Get the core key management service.
    KeyManagementService::Sptr GetService() const;

    /// @brief Get the provider manager (for context node creation in mediator).
    provider::ProviderManager::Sptr GetProviderManager() const;

  private:
    KeyManagementModule() = default;

    SlotRegistry::Sptr m_slot_registry;
    KeyManagementService::Sptr m_service;
    provider::ProviderManager::Sptr m_provider_manager;

    static constexpr std::string_view LOG_PREFIX = "[KEY_MGMT_MODULE] ";
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_MANAGEMENT_MODULE_HPP
