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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_SLOT_DATA_NODE_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_SLOT_DATA_NODE_HPP

#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/key_management/slot/slot_registry.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include <memory>

namespace score::crypto::daemon::key_management
{

/// @brief DataNode for a resolved persistent key slot.
///
/// Created on ResolveResource(), lives for the connection lifetime.
/// exclusiveAccess = false (concurrent reads OK).
///
/// This is a **minimal-footprint reference** (≈24 bytes). It holds only a SlotHandle
/// (token into SlotRegistry's central registry) and the resolved CryptoResourceId.
/// It does NOT copy the KeySlotConfig, hold a slot handler reference, or store key
/// material. All config/handler access goes through SlotRegistry via the handle.
///
/// Two consumption models:
///   1. Slot-direct: context calls LoadOrShare at operation time, which checks
///      the KeyRegistry and reuses an existing KeyDataNode when possible.
///   2. Explicit LoadKey: user calls KEY_LOAD, producing a KeyDataNode in
///      the client tree referencing a KeyDataNode in the per-provider registry.
class KeySlotDataNode : public data_manager::DataNode
{
  public:
    /// @param slot_handle     Lightweight reference into SlotRegistry.
    /// @param slot_registry   Shared pointer to the central SlotRegistry.
    KeySlotDataNode(SlotHandle slot_handle, SlotRegistry::Sptr slot_registry)
        : DataNode(false),  // exclusiveAccess = false → concurrent reads OK
          m_slot_handle{slot_handle},
          m_slot_registry{std::move(slot_registry)}
    {
    }

    /// @brief Destructor — no-op with respect to SlotRegistry.
    ///
    /// Resolution left no footprint to clean up.
    ~KeySlotDataNode() override = default;

    [[nodiscard]] data_manager::DataNodeType GetNodeType() const noexcept override
    {
        return data_manager::DataNodeType::kKeySlot;
    }

    SlotHandle GetSlotHandle() const noexcept
    {
        return m_slot_handle;
    }

    /// @brief Access config from central registry.
    ///
    /// Returns a pointer to the slot config stored in the registry.
    /// The pointer is valid for the duration of the current operation.
    [[nodiscard]] score::crypto::Expected<const KeySlotConfig*, score::crypto::daemon::common::DaemonErrorCode>
    GetConfig() const
    {
        return m_slot_registry->GetConfig(m_slot_handle);
    }

    /// @brief Access the SlotRegistry (for config reads).
    SlotRegistry::Sptr GetSlotRegistry() const
    {
        return m_slot_registry;
    }

    /// @brief Check whether a provider is allowed to access this slot.
    ///
    /// Delegates to `KeySlotConfig::IsProviderAllowed()`.  Returns false if the
    /// config is unavailable (fail-closed).
    bool IsProviderAllowed(const common::ProviderId& provider_id) const
    {
        auto cfg_res = GetConfig();
        return cfg_res.has_value() && cfg_res.value()->IsProviderAllowed(provider_id);
    }

  private:
    SlotHandle m_slot_handle;            ///< ~4 bytes: index into central registry
    SlotRegistry::Sptr m_slot_registry;  ///< shared_ptr to central registry
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_SLOT_DATA_NODE_HPP
