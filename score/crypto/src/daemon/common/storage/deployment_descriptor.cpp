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

#include "score/crypto/src/daemon/common/storage/deployment_descriptor.hpp"

namespace score::crypto::daemon::common::storage
{

const std::string DeploymentDescriptor::kEmptyString{};
const DeploymentDescriptor::Section DeploymentDescriptor::kEmptySection{};

const std::string& DeploymentDescriptor::Get(const std::string& section, const std::string& key) const noexcept
{
    const auto sit = m_sections.find(section);
    if (sit == m_sections.end())
    {
        return kEmptyString;
    }
    const auto kit = sit->second.find(key);
    return (kit != sit->second.end()) ? kit->second : kEmptyString;
}

std::string DeploymentDescriptor::Get(const std::string& section,
                                      const std::string& key,
                                      std::string_view default_val) const
{
    const auto sit = m_sections.find(section);
    if (sit == m_sections.end())
    {
        return std::string{default_val};
    }
    const auto kit = sit->second.find(key);
    return (kit != sit->second.end()) ? kit->second : std::string{default_val};
}

bool DeploymentDescriptor::HasSection(const std::string& section) const noexcept
{
    return m_sections.count(section) > 0U;
}

bool DeploymentDescriptor::HasKey(const std::string& section, const std::string& key) const noexcept
{
    const auto sit = m_sections.find(section);
    return sit != m_sections.end() && sit->second.count(key) > 0U;
}

const DeploymentDescriptor::Section& DeploymentDescriptor::GetSection(const std::string& section) const noexcept
{
    const auto sit = m_sections.find(section);
    return (sit != m_sections.end()) ? sit->second : kEmptySection;
}

const DeploymentDescriptor::Sections& DeploymentDescriptor::GetSections() const noexcept
{
    return m_sections;
}

void DeploymentDescriptor::AddSection(const std::string& section)
{
    m_sections.try_emplace(section);
}

void DeploymentDescriptor::Set(const std::string& section, const std::string& key, const std::string& value)
{
    m_sections[section][key] = value;
}

void DeploymentDescriptor::RemoveSection(const std::string& section)
{
    m_sections.erase(section);
}

}  // namespace score::crypto::daemon::common::storage
