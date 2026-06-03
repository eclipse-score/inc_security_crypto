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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_CORE_KEY_ENTRY_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_CORE_KEY_ENTRY_HPP

#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/daemon/key_management/slot/slot_registry.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace score::crypto::daemon::key_management
{

/// Registry entry for a single live key (ephemeral or slot-loaded).
///
/// Takes exclusive ownership of an IKeyHandler. The destructor calls
/// IKeyHandler::Release() to securely zeroize and free key material.
///
/// Client-visible references are KeyDataNode instances (formerly KeyDataNode)
/// in the DataManager client tree.
///
/// Inherits enable_shared_from_this for ContextDataNode co-ownership: a
/// ContextDataNode may hold a shared_ptr<KeyEntry> to prevent a dangling
/// ProviderKeyHandle reference if the user releases their context early.
class KeyEntry final : public std::enable_shared_from_this<KeyEntry>
{
  public:
    /// @param handler        Owning key handler (must not be nullptr).
    /// @param provider_id    Numeric provider ID (uint16_t) that created this key.
    /// @param slot_handle    Non-default only when key was loaded from a slot.
    KeyEntry(IKeyHandler::Sptr handler, common::ProviderId provider_id, SlotHandle slot_handle = SlotHandle{})
        : m_handler{std::move(handler)}, m_provider_id{provider_id}, m_slot_handle{slot_handle}
    {
    }

    /// Releases key material.
    ~KeyEntry()
    {
        if (m_handler)
        {
            static_cast<void>(m_handler->Release());
        }
    }

    KeyEntry(const KeyEntry&) = delete;
    KeyEntry& operator=(const KeyEntry&) = delete;
    KeyEntry(KeyEntry&&) = delete;
    KeyEntry& operator=(KeyEntry&&) = delete;

    /// Read the opaque provider key handle metadata.
    [[nodiscard]] const ProviderKeyHandle& GetHandle() const noexcept
    {
        return m_handler->GetHandle();
    }

    /// Access the key handler (e.g., for crypto operations that need raw bytes).
    [[nodiscard]] IKeyHandler::Sptr GetKeyHandler() const noexcept
    {
        return m_handler;
    }

    [[nodiscard]] const common::ProviderId GetProviderId() const noexcept
    {
        return m_provider_id;
    }

    // -----------------------------------------------------------------------
    // Reference counting for shared key access across clients
    // -----------------------------------------------------------------------

    /// Record an additional client holding a reference to this key.
    void AddRef(data_manager::ClientId client_id)
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        m_ref_count.fetch_add(1U, std::memory_order_relaxed);
        m_referencing_clients.push_back(client_id);
    }

    /// Remove a client reference.
    ///
    /// @return true when the reference count has reached zero.
    ///         The caller must then unregister this key from the KeyRegistry.
    bool Release(data_manager::ClientId client_id)
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        m_referencing_clients.erase(std::remove(m_referencing_clients.begin(), m_referencing_clients.end(), client_id),
                                    m_referencing_clients.end());
        const std::uint32_t prev = m_ref_count.fetch_sub(1U, std::memory_order_acq_rel);
        return prev == 1U;
    }

    /// Current number of live references.
    [[nodiscard]] std::uint32_t GetRefCount() const noexcept
    {
        return m_ref_count.load(std::memory_order_acquire);
    }

  private:
    IKeyHandler::Sptr m_handler;
    common::ProviderId m_provider_id;
    SlotHandle m_slot_handle;

    mutable std::mutex m_ref_mutex;  ///< Protects m_referencing_clients.
    std::atomic<std::uint32_t> m_ref_count{0U};
    std::vector<data_manager::ClientId> m_referencing_clients;
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_CORE_KEY_ENTRY_HPP
