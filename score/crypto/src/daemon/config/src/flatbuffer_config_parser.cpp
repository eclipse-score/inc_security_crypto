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

#include "score/crypto/src/daemon/config/src/flatbuffer_config_parser.hpp"

#include "score/mw/log/logging.h"

#include <fstream>
#include <limits>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

// FlatBuffers-generated header (from crypto_config.fbs via genrule)
#include "score/crypto/src/daemon/config/crypto_config_generated.h"

using namespace score::crypto::daemon::config::keyslot;

namespace score::crypto::daemon::config
{

// ---------------------------------------------------------------------------
// Binary FlatBuffers configuration parsing
// ---------------------------------------------------------------------------

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

    const auto* key_slot_config = root->key_slot_config();
    if (!key_slot_config)
    {
        // key_slot_config is optional — cert-only or empty deployment is valid.
        score::mw::log::LogDebug() << LOG_PREFIX << "No key_slot_config present — key management starts empty.";
        return std::monostate{};
    }

    auto slot_entries_result = ParseSlotEntries(key_slot_config, out_config);
    if (!slot_entries_result.has_value())
        return make_unexpected(slot_entries_result.error());

    auto app_resource_result = ParseAppKeySlotEntries(key_slot_config, out_config);
    if (!app_resource_result.has_value())
        return make_unexpected(app_resource_result.error());

    score::mw::log::LogDebug() << LOG_PREFIX << "Successfully parsed key config. Loaded "
                               << out_config.GetSlotEntries().size() << " slot(s) and "
                               << out_config.GetAppKeySlotEntries().size() << " app key slot mapping(s).";
    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseSlotEntries(
    const KeySlotConfig* key_slot_config,
    KeyConfig& out_config)
{
    const auto* slot_entries = key_slot_config->slot_entries();
    if (!slot_entries)
        return std::monostate{};

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
                slot_entry.provider_names.push_back(provider->str());
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
            slot_entry.allowed_uids.push_back(uid);

        if (!entry->allowed_write_uids())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing required field 'allowed_write_uids'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        for (auto uid : *entry->allowed_write_uids())
            slot_entry.allowed_write_uids.push_back(uid);

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
        score::mw::log::LogDebug() << LOG_PREFIX << "Loaded key slot: '" << out_config.GetSlotEntries().back().slot_name
                                   << "'";
    }

    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseAppKeySlotEntries(
    const KeySlotConfig* key_slot_config,
    KeyConfig& out_config)
{
    const auto* app_key_slot_entries = key_slot_config->app_key_slot_entries();
    if (!app_key_slot_entries)
        return std::monostate{};

    for (const auto* entry : *app_key_slot_entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null app key slot entry encountered";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }

        KeyConfig::AppKeySlotEntry key_slot_entry;
        key_slot_entry.uid = entry->uid();

        if (!entry->app_resource_id())
        {
            score::mw::log::LogError() << LOG_PREFIX << "App key slot entry missing 'app_resource_id'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        key_slot_entry.app_resource_id = entry->app_resource_id()->str();

        if (!entry->slot_name())
        {
            score::mw::log::LogError() << LOG_PREFIX << "App key slot entry missing 'slot_name'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        key_slot_entry.slot_name = entry->slot_name()->str();

        out_config.AddAppKeySlotEntry(std::move(key_slot_entry));
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

    std::streamsize size = file.tellg();
    if (size <= 0)
    {
        score::mw::log::LogError() << LOG_PREFIX << "File is empty:" << filepath;
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    file.seekg(0, std::ios::beg);

    if (static_cast<std::make_unsigned_t<std::streamsize>>(size) > std::numeric_limits<size_t>::max())
    {
        score::mw::log::LogError() << LOG_PREFIX << "File size exceeds maximum:" << filepath;
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

    const auto* root = flatbuffers::GetRoot<CryptoConfig>(data);
    if (!root)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Failed to get FlatBuffers root object from buffer";
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    }

    return ParseKeySlotConfig(root, out_config);
}

// ---------------------------------------------------------------------------
// Per-component entry points
// ---------------------------------------------------------------------------

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseKeyManagementConfig(
    std::string_view filepath,
    KeyConfig& out_config)
{
    CertificateConfig unused_cert;
    return ParseAll(filepath, out_config, unused_cert);
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseCertManagementConfig(
    std::string_view filepath,
    CertificateConfig& out_config)
{
    KeyConfig unused_key;
    return ParseAll(filepath, unused_key, out_config);
}

// ---------------------------------------------------------------------------
// Unified entry point — ParseAll
// ---------------------------------------------------------------------------

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseAllFromBinary(
    const uint8_t* data,
    size_t size,
    KeyConfig& key_config,
    CertificateConfig& cert_config)
{
    if (!data || size == 0U)
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);

    auto val = ValidateBuffer(data, size);
    if (!val.has_value())
        return val;

    const auto* root = flatbuffers::GetRoot<CryptoConfig>(data);
    if (!root)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Failed to get CryptoConfig root";
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    }

    // Key config (required).
    auto key_res = ParseKeySlotConfig(root, key_config);
    if (!key_res.has_value())
        return key_res;

    // Cert config (optional - old binaries without the cert tables are fine).
    if (root->cert_slot_config())
    {
        auto cert_res = ParseCertSlotConfig(root->cert_slot_config(), cert_config);
        if (!cert_res.has_value())
            return cert_res;
    }
    else
    {
        score::mw::log::LogDebug() << LOG_PREFIX << "No cert_slot_config in binary - cert management starts empty.";
    }

    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseAll(std::string_view filepath,
                                                                                   KeyConfig& key_config,
                                                                                   CertificateConfig& cert_config)
{
    // Read the generated binary FlatBuffers file into memory.
    std::ifstream file(std::string(filepath), std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        score::mw::log::LogError() << LOG_PREFIX << "Cannot open config file: " << filepath;
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    const std::streamsize sz = file.tellg();
    if (sz <= 0)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Config file is empty: " << filepath;
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(sz));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), sz))
    {
        score::mw::log::LogError() << LOG_PREFIX << "Failed to read config file: " << filepath;
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    score::mw::log::LogDebug() << LOG_PREFIX << "Parsing binary FlatBuffers config: " << filepath;
    return ParseAllFromBinary(buffer.data(), buffer.size(), key_config, cert_config);
}

// ---------------------------------------------------------------------------
// Cert config - binary FlatBuffers parsing
// ---------------------------------------------------------------------------

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseCertConfigFromFile(
    std::string_view filepath,
    CertificateConfig& out_config)
{
    KeyConfig unused_key;
    return ParseAll(filepath, unused_key, out_config);
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseCertSlotConfig(
    const CertSlotConfig* cert_slot_config,
    CertificateConfig& out_config)
{
    auto res = ParseCertSlotEntries(cert_slot_config, out_config);
    if (!res.has_value())
        return res;

    res = ParseTrustStoreEntries(cert_slot_config, out_config);
    if (!res.has_value())
        return res;

    res = ParseAppCertSlotEntries(cert_slot_config, out_config);
    if (!res.has_value())
        return res;

    res = ParseAppTrustStoreEntries(cert_slot_config, out_config);
    if (!res.has_value())
        return res;

    score::mw::log::LogDebug() << LOG_PREFIX << "Cert config loaded: " << out_config.GetSlotEntries().size()
                               << " cert slot(s), " << out_config.GetTrustStoreEntries().size() << " trust store(s), "
                               << out_config.GetAppCertSlotEntries().size() << " app cert mapping(s), "
                               << out_config.GetAppTrustStoreEntries().size() << " app trust store mapping(s).";
    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseCertSlotEntries(
    const CertSlotConfig* cert_slot_config,
    CertificateConfig& out_config)
{
    const auto* entries = cert_slot_config->slot_entries();
    if (!entries)
        return std::monostate{};

    for (const auto* entry : *entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null cert slot entry encountered";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        if (!entry->slot_name())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Cert slot entry missing 'slot_name'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        if (!entry->deployment_path())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Cert slot entry missing 'deployment_path'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }

        CertificateConfig::CertSlotEntry slot;
        slot.slot_name = entry->slot_name()->str();
        slot.storage_backend = entry->storage_backend() ? entry->storage_backend()->str() : "DEFAULT";
        slot.deployment_path = entry->deployment_path()->str();
        slot.deployment_format = entry->deployment_format() ? entry->deployment_format()->str() : "kv";
        slot.integrity_policy = entry->integrity_policy() ? entry->integrity_policy()->str() : "disabled";

        if (entry->allowed_uids())
        {
            for (auto uid : *entry->allowed_uids())
                slot.allowed_uids.push_back(uid);
        }
        if (entry->allowed_write_uids())
        {
            for (auto uid : *entry->allowed_write_uids())
                slot.allowed_write_uids.push_back(uid);
        }

        score::mw::log::LogDebug() << LOG_PREFIX << "Loaded cert slot: '" << slot.slot_name << "'";
        out_config.AddSlotEntry(std::move(slot));
    }

    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseTrustStoreEntries(
    const CertSlotConfig* cert_slot_config,
    CertificateConfig& out_config)
{
    const auto* entries = cert_slot_config->trust_store_entries();
    if (!entries)
        return std::monostate{};

    for (const auto* entry : *entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null trust store entry encountered";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        if (!entry->store_name())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Trust store entry missing 'store_name'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        if (!entry->deployment_path())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Trust store entry missing 'deployment_path'";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }

        CertificateConfig::TrustStoreEntry store;
        store.store_name = entry->store_name()->str();
        store.deployment_path = entry->deployment_path()->str();
        store.deployment_format = entry->deployment_format() ? entry->deployment_format()->str() : "kv";

        // Map FlatBuffer enum to C++ enum
        switch (entry->conditional_slot_init())
        {
            case ConditionalSlotInit_kEnableAndAcceptCurrent:
                store.conditional_slot_initialization =
                    CertificateConfig::ConditionalSlotInitialization::kEnableAndAcceptCurrent;
                break;
            case ConditionalSlotInit_kDisableUntilAccepted:
            default:
                store.conditional_slot_initialization =
                    CertificateConfig::ConditionalSlotInitialization::kDisableUntilAccepted;
                break;
        }

        if (entry->allowed_uids())
        {
            for (auto uid : *entry->allowed_uids())
                store.allowed_uids.push_back(uid);
        }
        if (entry->allowed_write_uids())
        {
            for (auto uid : *entry->allowed_write_uids())
                store.allowed_write_uids.push_back(uid);
        }

        // Parse member entries
        if (entry->members())
        {
            for (const auto* member : *entry->members())
            {
                if (!member || !member->slot_name())
                {
                    score::mw::log::LogError() << LOG_PREFIX << "Trust store member missing 'slot_name'";
                    return make_unexpected(common::DaemonErrorCode::kInternalError);
                }

                CertificateConfig::TrustStoreMemberEntry mem;
                mem.slot_name = member->slot_name()->str();

                switch (member->kind())
                {
                    case TrustStoreMemberKind_kExclusiveMutable:
                        mem.kind = CertificateConfig::TrustStoreMemberKind::kExclusiveMutable;
                        break;
                    case TrustStoreMemberKind_kConditionalExternal:
                        mem.kind = CertificateConfig::TrustStoreMemberKind::kConditionalExternal;
                        break;
                    case TrustStoreMemberKind_kSharedStatic:
                    default:
                        mem.kind = CertificateConfig::TrustStoreMemberKind::kSharedStatic;
                        break;
                }
                store.members.push_back(std::move(mem));
            }
        }

        score::mw::log::LogDebug() << LOG_PREFIX << "Loaded trust store: '" << store.store_name << "' with "
                                   << store.members.size() << " member(s)";
        out_config.AddTrustStoreEntry(std::move(store));
    }

    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseAppCertSlotEntries(
    const CertSlotConfig* cert_slot_config,
    CertificateConfig& out_config)
{
    const auto* entries = cert_slot_config->app_cert_slot_entries();
    if (!entries)
        return std::monostate{};

    for (const auto* entry : *entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null app cert slot entry encountered";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        if (!entry->app_resource_id() || !entry->slot_name())
        {
            score::mw::log::LogError() << LOG_PREFIX << "App cert slot entry missing required fields";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }

        CertificateConfig::AppCertSlotEntry app;
        app.uid = entry->uid();
        app.app_resource_id = entry->app_resource_id()->str();
        app.slot_name = entry->slot_name()->str();
        out_config.AddAppCertSlotEntry(std::move(app));
    }

    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseAppTrustStoreEntries(
    const CertSlotConfig* cert_slot_config,
    CertificateConfig& out_config)
{
    const auto* entries = cert_slot_config->app_trust_store_entries();
    if (!entries)
        return std::monostate{};

    for (const auto* entry : *entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null app trust store entry encountered";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        if (!entry->app_resource_id() || !entry->trust_store_name())
        {
            score::mw::log::LogError() << LOG_PREFIX << "App trust store entry missing required fields";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }

        CertificateConfig::AppTrustStoreEntry app;
        app.uid = entry->uid();
        app.app_resource_id = entry->app_resource_id()->str();
        app.trust_store_name = entry->trust_store_name()->str();
        out_config.AddAppTrustStoreEntry(std::move(app));
    }

    return std::monostate{};
}

}  // namespace score::crypto::daemon::config
