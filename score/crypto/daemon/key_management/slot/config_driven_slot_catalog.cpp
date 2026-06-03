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

#include "score/crypto/daemon/key_management/slot/config_driven_slot_catalog.hpp"

#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/daemon/key_management/slot/slot_registry.hpp"

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::key_management
{

namespace
{

/// @brief Convert the string representation of allowed_operations to the bitmask.
///
/// Supports: "MAC", "ENCRYPT", "DECRYPT", "SIGN", "VERIFY", "ALL", "NONE".
/// Pipe-separated combinations: "ENCRYPT|DECRYPT".
score::mw::crypto::KeyOperationPermission ParseOperationPermission(const std::string& ops_str)
{
    if (ops_str.empty() || ops_str == "NONE")
    {
        return score::mw::crypto::KeyOperationPermission::kNone;
    }
    if (ops_str == "ALL")
    {
        return score::mw::crypto::KeyOperationPermission::kAll;
    }

    auto result = score::mw::crypto::KeyOperationPermission::kNone;

    // Simple pipe-separated token parsing
    std::string token;
    for (std::size_t i = 0U; i <= ops_str.size(); ++i)
    {
        if (i == ops_str.size() || ops_str[i] == '|')
        {
            if (token == "MAC")
            {
                result = static_cast<score::mw::crypto::KeyOperationPermission>(
                    static_cast<uint32_t>(result) |
                    static_cast<uint32_t>(score::mw::crypto::KeyOperationPermission::kMac));
            }
            else if (token == "ENCRYPT")
            {
                result = static_cast<score::mw::crypto::KeyOperationPermission>(
                    static_cast<uint32_t>(result) |
                    static_cast<uint32_t>(score::mw::crypto::KeyOperationPermission::kEncrypt));
            }
            else if (token == "DECRYPT")
            {
                result = static_cast<score::mw::crypto::KeyOperationPermission>(
                    static_cast<uint32_t>(result) |
                    static_cast<uint32_t>(score::mw::crypto::KeyOperationPermission::kDecrypt));
            }
            else if (token == "SIGN")
            {
                result = static_cast<score::mw::crypto::KeyOperationPermission>(
                    static_cast<uint32_t>(result) |
                    static_cast<uint32_t>(score::mw::crypto::KeyOperationPermission::kSign));
            }
            else if (token == "VERIFY")
            {
                result = static_cast<score::mw::crypto::KeyOperationPermission>(
                    static_cast<uint32_t>(result) |
                    static_cast<uint32_t>(score::mw::crypto::KeyOperationPermission::kVerify));
            }
            token.clear();
        }
        else
        {
            token += ops_str[i];
        }
    }

    return result;
}

}  // namespace

ConfigDrivenSlotCatalog::ConfigDrivenSlotCatalog(const config::KeyConfig& key_config) : m_key_config{key_config} {}

void ConfigDrivenSlotCatalog::Load(SlotRegistry& registry)
{
    const auto& entries = m_key_config.GetSlotEntries();

    for (const auto& entry : entries)
    {
        KeySlotConfig config{};
        config.slot_name = entry.slot_name;
        config.algorithm = entry.algorithm;
        // Store provider names as-is from config (strings); numeric IDs will be resolved later
        config.provider_names = entry.provider_names;
        config.allowed_operations = ParseOperationPermission(entry.allowed_operations);

        // Access policy
        config.access_policy.allowed_uids = entry.allowed_uids;
        config.access_policy.allowed_write_uids = entry.allowed_write_uids;

        // Deployment descriptor — each IKeySlotHandler loads provider-specific
        // key properties from this file at runtime.
        config.deployment_path = entry.deployment_path;
        config.deployment_format = entry.deployment_format;

        registry.RegisterSlot(std::move(config));

        score::mw::log::LogDebug() << LOG_PREFIX << "Registered slot '" << entry.slot_name << "' (primary_provider="
                                   << (entry.provider_names.empty() ? "<none>" : entry.provider_names[0])
                                   << ", algorithm=" << entry.algorithm << ")";
    }

    score::mw::log::LogDebug() << LOG_PREFIX << "Loaded" << entries.size() << " slot(s) from configuration.";

    // Register per-application resource ID mappings.
    for (const auto& mapping : m_key_config.GetAppResourceEntries())
    {
        registry.RegisterAppResource(mapping.uid, mapping.app_resource_id, mapping.slot_name);
    }
}

}  // namespace score::crypto::daemon::key_management
