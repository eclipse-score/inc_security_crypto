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

#include "score/crypto/daemon/key_management/core/key_registry.hpp"

#include "score/crypto/daemon/key_management/core/key_entry.hpp"

#include "score/mw/log/logging.h"
#include <algorithm>

#include <string_view>

namespace score::crypto::daemon::key_management
{
namespace
{
constexpr std::string_view LOG_PREFIX = "[KEY_REGISTRY] ";
}  // namespace

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

KeyRegistryId KeyRegistry::RegisterSlotKey(SlotHandle slot_handle, std::shared_ptr<KeyEntry> key_node)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    // Dedup check — caller should have called FindBySlot() first, but guard
    // against concurrent races.
    if (m_slot_to_id.count(slot_handle.index) != 0U)
    {
        score::mw::log::LogError() << LOG_PREFIX << "RegisterSlotKey: slot" << slot_handle.index
                                   << " already registered";
        return 0U;
    }

    const KeyRegistryId id = m_next_id++;
    m_keys.emplace(id, std::move(key_node));
    m_slot_to_id.emplace(slot_handle.index, id);

    return id;
}

KeyRegistryId KeyRegistry::RegisterEphemeralKey(std::shared_ptr<KeyEntry> key_node)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const KeyRegistryId id = m_next_id++;
    m_keys.emplace(id, std::move(key_node));

    return id;
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

std::shared_ptr<KeyEntry> KeyRegistry::FindBySlot(SlotHandle slot_handle) const
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const auto slot_it = m_slot_to_id.find(slot_handle.index);
    if (slot_it == m_slot_to_id.end())
    {
        return nullptr;
    }

    const auto key_it = m_keys.find(slot_it->second);
    if (key_it == m_keys.end())
    {
        return nullptr;
    }

    return key_it->second;
}

KeyRegistryId KeyRegistry::FindSlotRegistryId(SlotHandle slot_handle) const
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const auto slot_it = m_slot_to_id.find(slot_handle.index);
    if (slot_it == m_slot_to_id.end())
    {
        return 0U;
    }

    return slot_it->second;
}

std::shared_ptr<KeyEntry> KeyRegistry::FindById(KeyRegistryId id) const
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const auto it = m_keys.find(id);
    if (it == m_keys.end())
    {
        return nullptr;
    }

    return it->second;
}

// ---------------------------------------------------------------------------
// Removal
// ---------------------------------------------------------------------------

bool KeyRegistry::Unregister(KeyRegistryId id)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    const auto it = m_keys.find(id);
    if (it == m_keys.end())
    {
        return false;
    }

    // Remove reverse mapping if this was a slot-loaded key.
    for (auto slot_it = m_slot_to_id.begin(); slot_it != m_slot_to_id.end(); ++slot_it)
    {
        if (slot_it->second == id)
        {
            m_slot_to_id.erase(slot_it);
            break;
        }
    }

    m_keys.erase(it);
    return true;
}

// ---------------------------------------------------------------------------
// Crash cleanup
// ---------------------------------------------------------------------------

void KeyRegistry::CleanupClient(data_manager::ClientId client_id)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    // Collect IDs of keys to remove (cannot mutate m_keys while iterating).
    std::vector<KeyRegistryId> to_remove;

    for (auto& [id, key_node] : m_keys)
    {
        if (key_node->Release(client_id))
        {
            // ref_count reached zero — mark for removal.
            to_remove.push_back(id);
        }
    }

    for (const auto id : to_remove)
    {
        // Remove reverse slot mapping.
        for (auto slot_it = m_slot_to_id.begin(); slot_it != m_slot_to_id.end(); ++slot_it)
        {
            if (slot_it->second == id)
            {
                m_slot_to_id.erase(slot_it);
                break;
            }
        }

        score::mw::log::LogDebug() << LOG_PREFIX << "CleanupClient: removing key" << id
                                   << " (ref_count reached 0 after client" << client_id << " cleanup)";
        m_keys.erase(id);
    }
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

std::size_t KeyRegistry::Size() const
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    return m_keys.size();
}

}  // namespace score::crypto::daemon::key_management
