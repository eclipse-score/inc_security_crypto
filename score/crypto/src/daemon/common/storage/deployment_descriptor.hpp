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
#include <string_view>
#include <unordered_map>

namespace score::crypto::daemon::common::storage
{

/// @brief Generic section-based deployment descriptor.
///
/// Represents the parsed content of a deployment descriptor file as a nested map:
///   section name -> { key -> value }
///
/// Format-specific validation is performed by the corresponding loader or writer.
struct DeploymentDescriptor
{
    using Section = std::unordered_map<std::string, std::string>;
    using Sections = std::unordered_map<std::string, Section>;

    /// @brief Get a value from a section, returning an empty string if absent.
    [[nodiscard]] const std::string& Get(const std::string& section, const std::string& key) const noexcept;

    /// @brief Get a value from a section, returning an owning default if absent.
    [[nodiscard]] std::string Get(const std::string& section,
                                  const std::string& key,
                                  std::string_view default_val) const;

    /// @brief True if the named section is present (even if empty).
    [[nodiscard]] bool HasSection(const std::string& section) const noexcept;

    /// @brief True if the named key is present in the section.
    [[nodiscard]] bool HasKey(const std::string& section, const std::string& key) const noexcept;

    /// @brief Get all entries in a section, or an empty section if absent.
    [[nodiscard]] const Section& GetSection(const std::string& section) const noexcept;

    /// @brief Read-only view of all sections.
    [[nodiscard]] const Sections& GetSections() const noexcept;

    /// @brief Add an empty section.
    void AddSection(const std::string& section);

    /// @brief Set an entry, creating its section if absent.
    void Set(const std::string& section, const std::string& key, const std::string& value);

    /// @brief Remove the named section entirely.
    void RemoveSection(const std::string& section);

  private:
    static const std::string kEmptyString;
    static const Section kEmptySection;

    Sections m_sections;
};

}  // namespace score::crypto::daemon::common::storage

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_DEPLOYMENT_DESCRIPTOR_HPP
