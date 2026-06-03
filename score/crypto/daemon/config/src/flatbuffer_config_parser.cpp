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

#include "score/mw/log/logging.h"
#include <fstream>

#include <limits>
#include <variant>
#include <vector>

#include "score/crypto/daemon/config/src/flatbuffer_config_parser.hpp"

// Include FlatBuffers generated file
#include "score/crypto/daemon/config/crypto_config_generated.h"

using namespace score::crypto::daemon::config::keyslot;

namespace score::crypto::daemon::config
{

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ValidateBuffer(const uint8_t* data,
                                                                                         size_t size)
{
    if (!data || size < kMinBufferSize)
    {
        score::mw::log::LogError() << LOG_PREFIX
                                   << "Buffer too small or null pointer. Required: >=4 bytes, Got:" << size;
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    if (!CryptoConfigBufferHasIdentifier(data))
    {
        score::mw::log::LogError() << LOG_PREFIX << "Buffer does not have expected file identifier";
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    }

    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseKeySlotConfig(const CryptoConfig* root,
                                                                                             KeyConfig& out_config)
{
    if (!root)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Failed to get FlatBuffers root object";
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    // Get key slot config from root
    const auto* key_slot_config = root->key_slot_config();
    if (!key_slot_config)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Failed to get key_slot_config from root object";
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    // Parse slot entries
    auto slot_entries_result = ParseSlotEntries(key_slot_config, out_config);
    if (!slot_entries_result.has_value())
    {
        return make_unexpected(slot_entries_result.error());
    }

    // Parse app resource entries
    auto app_resource_result = ParseAppResourceEntries(key_slot_config, out_config);
    if (!app_resource_result.has_value())
    {
        return make_unexpected(app_resource_result.error());
    }

    score::mw::log::LogDebug() << LOG_PREFIX << "Successfully parsed configuration. Loaded "
                               << out_config.GetSlotEntries().size() << " slot(s) and "
                               << out_config.GetAppResourceEntries().size() << " app resource mapping(s).";

    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseSlotEntries(
    const KeySlotConfig* key_slot_config,
    KeyConfig& out_config)
{
    const auto* slot_entries = key_slot_config->slot_entries();
    if (!slot_entries)
    {
        return std::monostate{};  // No slot entries is not an error
    }

    for (const auto* entry : *slot_entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null slot entry encountered - invalid configuration";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }

        KeyConfig::KeySlotEntry slot_entry;

        if (!entry->slot_name())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing required field 'slot_name'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        slot_entry.slot_name = entry->slot_name()->str();

        if (!entry->algorithm())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing required field 'algorithm'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        slot_entry.algorithm = entry->algorithm()->str();

        if (!entry->provider_names())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing required field 'provider_names'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        for (const auto* provider : *entry->provider_names())
        {
            if (provider)
            {
                slot_entry.provider_names.push_back(provider->str());
            }
        }

        if (!entry->allowed_operations())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing required field 'allowed_operations'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        slot_entry.allowed_operations = entry->allowed_operations()->str();

        if (!entry->allowed_uids())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing required field 'allowed_uids'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        for (auto uid : *entry->allowed_uids())
        {
            slot_entry.allowed_uids.push_back(uid);
        }

        if (!entry->allowed_write_uids())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing required field 'allowed_write_uids'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        for (auto uid : *entry->allowed_write_uids())
        {
            slot_entry.allowed_write_uids.push_back(uid);
        }

        if (!entry->deployment_path())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing required field 'deployment_path'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        slot_entry.deployment_path = entry->deployment_path()->str();

        if (!entry->deployment_format())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing required field 'deployment_format'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        slot_entry.deployment_format = entry->deployment_format()->str();

        out_config.AddSlotEntry(std::move(slot_entry));

        score::mw::log::LogDebug() << LOG_PREFIX << "Loaded slot: '" << out_config.GetSlotEntries().back().slot_name
                                   << "'";
    }

    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseFromFile(std::string_view filepath,
                                                                                        KeyConfig& out_config)
{
    std::ifstream file(std::string(filepath), std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        score::mw::log::LogError() << LOG_PREFIX << "Failed to open file:" << filepath;
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    // Get file size
    std::streamsize size = file.tellg();
    if (size <= 0)
    {
        score::mw::log::LogError() << LOG_PREFIX << "File is empty:" << filepath;
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    file.seekg(0, std::ios::beg);

    // Read entire file into buffer
    if (size > std::numeric_limits<size_t>::max())
    {
        score::mw::log::LogError() << LOG_PREFIX << "File size exceeds maximum allowed size:" << filepath;
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
    {
        score::mw::log::LogError() << LOG_PREFIX << "Failed to read file:" << filepath;
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    return ParseFromBuffer(buffer.data(), buffer.size(), out_config);
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseAppResourceEntries(
    const KeySlotConfig* key_slot_config,
    KeyConfig& out_config)
{
    const auto* app_resource_entries = key_slot_config->app_resource_entries();
    if (!app_resource_entries)
    {
        return std::monostate{};  // No app resource entries is not an error
    }

    for (const auto* entry : *app_resource_entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null app resource entry encountered - invalid configuration";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }

        KeyConfig::AppResourceEntry resource_entry;
        resource_entry.uid = entry->uid();

        // All fields below are required per schema - add defensive checks
        if (!entry->app_resource_id())
        {
            score::mw::log::LogError() << LOG_PREFIX << "App resource entry missing required field 'app_resource_id'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        resource_entry.app_resource_id = entry->app_resource_id()->str();

        if (!entry->slot_name())
        {
            score::mw::log::LogError() << LOG_PREFIX << "App resource entry missing required field 'slot_name'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        resource_entry.slot_name = entry->slot_name()->str();

        out_config.AddAppResourceEntry(std::move(resource_entry));
    }

    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseFromBuffer(const uint8_t* data,
                                                                                          size_t size,
                                                                                          KeyConfig& out_config)
{
    if (!data || size == 0)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Invalid buffer: null pointer or zero size";
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    auto validateRes = ValidateBuffer(data, size);
    if (!validateRes.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "Buffer validation failed";
        return make_unexpected(validateRes.error());
    }

    // Get root FlatBuffers object (CryptoConfig is the root_type)
    const auto* root = flatbuffers::GetRoot<CryptoConfig>(data);
    if (!root)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Failed to get FlatBuffers root object from buffer";
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    }

    return ParseKeySlotConfig(root, out_config);
}

}  // namespace score::crypto::daemon::config
