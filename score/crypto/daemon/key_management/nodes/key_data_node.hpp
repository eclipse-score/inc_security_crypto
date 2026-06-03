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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_DATA_NODE_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_DATA_NODE_HPP

#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/key_management/core/key_entry.hpp"
#include "score/crypto/daemon/key_management/core/key_registry.hpp"

#include <cstdint>
#include <functional>
#include <memory>

namespace score::crypto::daemon::key_management
{

/// DataNode placed in the client's tree that references a shared
/// KeyEntry living in the per-provider KeyRegistry.
///
/// On construction, increments the KeyEntry's reference count.
/// On destruction, decrements it.  When the count reaches zero, the
/// provided cleanup callback unregisters the key from the registry and
/// triggers secure zeroization of key material.
///
/// This node is the daemon-side equivalent of a client's CryptoResourceGuard:
/// each guard ↔ one KeyDataNode ↔ one AddRef/Release pair on the shared
/// KeyEntry.
///
/// exclusiveAccess = false: multiple threads may read concurrently.
class KeyDataNode final : public data_manager::DataNode
{
  public:
    /// Callback invoked when the reference count reaches zero.
    /// The registry uses this to unregister the key.
    using UnregisterCallback = std::function<void(KeyRegistryId)>;

    /// @param key_entry      Shared KeyEntry from the registry.
    /// @param registry_id    ID assigned by KeyRegistry.
    /// @param client_id      Client that owns this reference.
    /// @param on_last_release Called when Release() drops ref_count to zero.
    [[nodiscard]] data_manager::DataNodeType GetNodeType() const noexcept override
    {
        return data_manager::DataNodeType::kKeyData;
    }

    KeyDataNode(std::shared_ptr<KeyEntry> key_entry,
                KeyRegistryId registry_id,
                data_manager::ClientId client_id,
                UnregisterCallback on_last_release)
        : DataNode(false),
          m_key_entry{std::move(key_entry)},
          m_registry_id{registry_id},
          m_client_id{client_id},
          m_on_last_release{std::move(on_last_release)}
    {
        m_key_entry->AddRef(m_client_id);
    }

    /// Decrements the shared KeyEntry's reference count.
    /// If the count reaches zero, invokes the unregister callback so the
    /// registry can remove the key and allow its destructor to run.
    ~KeyDataNode() override
    {
        if (m_key_entry != nullptr)
        {
            const bool last = m_key_entry->Release(m_client_id);
            if (last && m_on_last_release)
            {
                m_on_last_release(m_registry_id);
            }
        }
    }

    KeyDataNode(const KeyDataNode&) = delete;
    KeyDataNode& operator=(const KeyDataNode&) = delete;
    KeyDataNode(KeyDataNode&&) = delete;
    KeyDataNode& operator=(KeyDataNode&&) = delete;

    /// Access the underlying KeyEntry (e.g., for key resolution in BindKeyToContext).
    [[nodiscard]] std::shared_ptr<KeyEntry> GetKeyEntry() const noexcept
    {
        return m_key_entry;
    }

    /// Registry-assigned identifier for the shared key.
    [[nodiscard]] KeyRegistryId GetRegistryId() const noexcept
    {
        return m_registry_id;
    }

  private:
    std::shared_ptr<KeyEntry> m_key_entry;
    KeyRegistryId m_registry_id;
    data_manager::ClientId m_client_id;
    UnregisterCallback m_on_last_release;
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_KEY_DATA_NODE_HPP
