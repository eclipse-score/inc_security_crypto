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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_KEYED_REGISTRY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_KEYED_REGISTRY_HPP

#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <utility>

namespace score::crypto::daemon::common
{

/// @brief Keyed collection of shared entries, filled at startup and read afterwards.
///
/// Registration is the only mutation. A registry is populated before it is handed to the
/// mediator as a `const` pointer; from then on only `Find` is called, and `Find` is safe to call
/// from several threads at once. Lookup accepts any key type comparable with `Key`, so a
/// `std::string` registry can be searched with a `std::string_view`.
///
/// @tparam Key Key type; must be ordered.
/// @tparam Interface Interface of the entries, stored by shared pointer.
template <typename Key, typename Interface>
class KeyedRegistry final
{
  public:
    /// @brief Shared pointer to a registered entry.
    using EntryPtr = std::shared_ptr<Interface>;

    /// @brief Add an entry under a key.
    /// @param key Key the entry is registered under.
    /// @param entry Entry to register; must not be null.
    /// @return True if the entry was added. False if @p entry is null or @p key is already
    ///         registered; the registry is unchanged in both cases.
    [[nodiscard]] bool Register(Key key, EntryPtr entry)
    {
        if (!entry)
        {
            return false;
        }
        return m_entries.emplace(std::move(key), std::move(entry)).second;
    }

    /// @brief Look up the entry registered under a key.
    /// @tparam Lookup Any type comparable with `Key`.
    /// @param key Key to look up.
    /// @return The registered entry, or null if the key is not registered.
    template <typename Lookup>
    [[nodiscard]] EntryPtr Find(const Lookup& key) const
    {
        const auto it = m_entries.find(key);
        return it == m_entries.end() ? EntryPtr{} : it->second;
    }

    /// @return Number of registered entries.
    [[nodiscard]] std::size_t Size() const noexcept
    {
        return m_entries.size();
    }

  private:
    std::map<Key, EntryPtr, std::less<>> m_entries;
};

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_KEYED_REGISTRY_HPP
