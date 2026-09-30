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

#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_validator.hpp"

namespace score::crypto::daemon::common::storage
{

namespace
{

[[nodiscard]] bool IsWhitespace(char value) noexcept
{
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

[[nodiscard]] bool HasBoundaryWhitespace(std::string_view value) noexcept
{
    return !value.empty() && (IsWhitespace(value.front()) || IsWhitespace(value.back()));
}

[[nodiscard]] bool IsSingleLine(std::string_view value) noexcept
{
    return value.find_first_of("\r\n") == std::string_view::npos;
}

[[nodiscard]] bool IsValidKvKey(std::string_view key) noexcept
{
    return !key.empty() && key.front() != '#' && key.find('=') == std::string_view::npos &&
           !HasBoundaryWhitespace(key) && IsSingleLine(key);
}

[[nodiscard]] bool IsValidKvValue(std::string_view value) noexcept
{
    return !HasBoundaryWhitespace(value) && IsSingleLine(value);
}

}  // namespace

bool KvDeploymentValidator::IsValidSection(std::string_view section) const noexcept
{
    return !section.empty() && !HasBoundaryWhitespace(section) && IsSingleLine(section);
}

bool KvDeploymentValidator::IsValidEntry(std::string_view section,
                                         std::string_view key,
                                         std::string_view value) const noexcept
{
    return IsValidSection(section) && IsValidKvKey(key) && IsValidKvValue(value);
}

bool KvDeploymentValidator::Validate(const DeploymentDescriptor::Sections& sections) const noexcept
{
    for (const auto& [section, entries] : sections)
    {
        if (!IsValidSection(section))
        {
            return false;
        }
        for (const auto& [key, value] : entries)
        {
            if (!IsValidEntry(section, key, value))
            {
                return false;
            }
        }
    }
    return true;
}

}  // namespace score::crypto::daemon::common::storage
