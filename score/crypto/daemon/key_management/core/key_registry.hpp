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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_CORE_KEY_REGISTRY_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_CORE_KEY_REGISTRY_HPP

#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/key_management/slot/slot_registry.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace score::crypto::daemon::key_management
{

// Forward declaration — full definition in key_data_node.hpp.
class KeyEntry;

/// Unique identifier for a key within a KeyRegistry.
using KeyRegistryId = std::uint64_t;

/// Per-provider registry of live keys.
///
/// Holds shared ownership of every KeyEntry produced by a single
/// provider (both slot-loaded and ephemeral).  KeyDataNode instances
/// in the client tree hold an additional shared_ptr to the same
/// KeyEntry, keeping it alive as long as any client references it.
///
/// Thread safety: all public methods serialise on an internal mutex that
/// is independent of the DataManager lock.  The lock hierarchy is:
///   DataManager::m_mutex  →  (release)  →  KeyRegistry::m_mutex
/// Callers must NOT hold the DataManager lock when calling into this class.
class KeyRegistry final
{
  public:
    using Sptr = std::shared_ptr<KeyRegistry>;

    KeyRegistry() = default;
    ~KeyRegistry() = default;

    KeyRegistry(const KeyRegistry&) = delete;
    KeyRegistry& operator=(const KeyRegistry&) = delete;
    KeyRegistry(KeyRegistry&&) = delete;
    KeyRegistry& operator=(KeyRegistry&&) = delete;

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    /// Register a key that was loaded from a persistent slot.
    ///
    /// The slot_handle is used as a deduplication key: if a KeyEntry
    /// for the same slot is already registered, this call fails with
    /// kAlreadyExists (caller should use FindBySlot() first).
    ///
    /// @return Assigned KeyRegistryId on success.
    [[nodiscard]] KeyRegistryId RegisterSlotKey(SlotHandle slot_handle, std::shared_ptr<KeyEntry> key_node);

    /// Register an ephemeral (non-slot) key.
    ///
    /// @return Assigned KeyRegistryId.
    [[nodiscard]] KeyRegistryId RegisterEphemeralKey(std::shared_ptr<KeyEntry> key_node);

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    /// Find a previously registered slot-loaded key.
    ///
    /// @return shared_ptr to the KeyEntry, or nullptr if not found.
    [[nodiscard]] std::shared_ptr<KeyEntry> FindBySlot(SlotHandle slot_handle) const;

    /// Find the registry ID for a slot-loaded key.
    ///
    /// @return KeyRegistryId, or 0 if not found.
    [[nodiscard]] KeyRegistryId FindSlotRegistryId(SlotHandle slot_handle) const;

    /// Find a key by its registry-assigned ID.
    ///
    /// @return shared_ptr to the KeyEntry, or nullptr if not found.
    [[nodiscard]] std::shared_ptr<KeyEntry> FindById(KeyRegistryId id) const;

    // ------------------------------------------------------------------
    // Removal
    // ------------------------------------------------------------------

    /// Remove a key from the registry.
    ///
    /// After this call, the registry no longer holds a shared_ptr to the
    /// KeyEntry.  If no other shared_ptrs exist (i.e. all KeyDataNodes
    /// were already destroyed) the KeyEntry destructor runs immediately.
    ///
    /// @return true if the key was found and removed, false otherwise.
    bool Unregister(KeyRegistryId id);

    // ------------------------------------------------------------------
    // Crash cleanup
    // ------------------------------------------------------------------

    /// Remove all references for a given client from every key in the
    /// registry.  Keys whose reference count drops to zero are unregistered.
    ///
    /// Called as a safety net after DataManager::deleteClientNodes().
    void CleanupClient(data_manager::ClientId client_id);

    // ------------------------------------------------------------------
    // Query
    // ------------------------------------------------------------------

    /// Number of keys currently held in the registry.
    [[nodiscard]] std::size_t Size() const;

  private:
    mutable std::mutex m_mutex;

    /// Master table: registry-assigned ID → KeyDataNode.
    std::unordered_map<KeyRegistryId, std::shared_ptr<KeyEntry>> m_keys;

    /// Reverse map: slot handle index → registry ID (for slot-loaded dedup).
    std::unordered_map<std::uint32_t, KeyRegistryId> m_slot_to_id;

    /// Monotonically increasing ID counter.
    KeyRegistryId m_next_id{1U};
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_CORE_KEY_REGISTRY_HPP
