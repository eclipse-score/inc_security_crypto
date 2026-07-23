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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_DEPLOYMENT_DESCRIPTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_DEPLOYMENT_DESCRIPTOR_HPP

#include <string>
#include <unordered_map>

namespace score::crypto::daemon::common::storage
{

/// @brief Generic section-based key-value deployment descriptor.
///
/// Represents the parsed content of a deployment descriptor file as a nested map:
///   section name -> { key -> value }
///
/// This is the generic in-memory representation. Specific components
/// (cert_management, future components) interpret section names and keys
/// according to their own schema.
struct DeploymentDescriptor
{
    /// @brief Section name -> (key -> value) map.
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> sections;

    /// @brief Get a value from a section, returning default_val if absent.
    [[nodiscard]] const std::string& Get(const std::string& section,
                                         const std::string& key,
                                         const std::string& default_val = kEmptyString) const noexcept
    {
        const auto sit = sections.find(section);
        if (sit == sections.end())
        {
            return default_val;
        }
        const auto kit = sit->second.find(key);
        return (kit != sit->second.end()) ? kit->second : default_val;
    }

    /// @brief True if the named section is present (even if empty).
    [[nodiscard]] bool HasSection(const std::string& section) const noexcept
    {
        return sections.count(section) > 0U;
    }

    /// @brief Set a key in a section (creates section if absent).
    void Set(const std::string& section, const std::string& key, const std::string& value)
    {
        sections[section][key] = value;
    }

    /// @brief Remove the named section entirely.
    void RemoveSection(const std::string& section)
    {
        sections.erase(section);
    }

  private:
    static const std::string kEmptyString;
};

}  // namespace score::crypto::daemon::common::storage

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_DEPLOYMENT_DESCRIPTOR_HPP
