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

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

// FlatBuffers-generated header (from crypto_config.fbs via genrule)
#include "score/crypto/src/daemon/config/crypto_config_generated.h"

using namespace score::crypto::daemon::config::keyslot;

namespace score::crypto::daemon::config
{

namespace
{

// A required name, path, or format is present, not blank, and free of control characters.
bool HasText(const flatbuffers::String* value)
{
    if (value == nullptr || value->size() == 0U)
    {
        return false;
    }
    const std::string_view text{value->c_str(), value->size()};
    if (text.find_first_not_of(" \t\r\n") == std::string_view::npos)
    {
        return false;
    }
    return std::none_of(text.begin(), text.end(), [](char c) {
        return std::iscntrl(static_cast<unsigned char>(c)) != 0;
    });
}

}  // namespace

// ---------------------------------------------------------------------------
// Binary FlatBuffers configuration parsing
// ---------------------------------------------------------------------------

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ValidateBuffer(const uint8_t* data,
                                                                                         size_t size)
{
    if (!data || size < kMinBufferSize)
    {
        score::mw::log::LogError() << LOG_PREFIX
                                   << "Buffer too small or null pointer. Required: >=8 bytes, Got:" << size;
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    if (!CryptoConfigBufferHasIdentifier(data))
    {
        score::mw::log::LogError() << LOG_PREFIX << "Buffer does not have expected file identifier";
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    flatbuffers::Verifier verifier{data, size};
    if (!VerifyCryptoConfigBuffer(verifier))
    {
        score::mw::log::LogError() << LOG_PREFIX << "Buffer failed FlatBuffers verification";
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
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
    {
        return make_unexpected(slot_entries_result.error());
    }

    auto app_resource_result = ParseAppKeySlotMappings(key_slot_config, out_config);
    if (!app_resource_result.has_value())
    {
        return make_unexpected(app_resource_result.error());
    }

    score::mw::log::LogDebug() << LOG_PREFIX << "Successfully parsed key config. Loaded "
                               << out_config.GetSlotEntries().size() << " slot(s) and "
                               << out_config.GetAppKeySlotMappings().size() << " app key slot mapping(s).";
    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseSlotEntries(
    const KeySlotConfig* key_slot_config,
    KeyConfig& out_config)
{
    const auto* slot_entries = key_slot_config->slot_entries();
    if (!slot_entries)
    {
        return std::monostate{};
    }

    for (const auto* entry : *slot_entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null slot entry encountered - invalid configuration";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }

        KeyConfig::KeySlotEntry slot_entry;

        if (!HasText(entry->slot_name()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing or empty 'slot_name'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        slot_entry.slot_name = entry->slot_name()->str();

        if (!HasText(entry->algorithm()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing or empty 'algorithm'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        slot_entry.algorithm = entry->algorithm()->str();

        // provider_names[0] is the primary provider, so the list must not be empty.
        if (!entry->provider_names() || entry->provider_names()->size() == 0U)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing or empty 'provider_names'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        for (const auto* provider : *entry->provider_names())
        {
            if (!HasText(provider))
            {
                score::mw::log::LogError() << LOG_PREFIX << "Slot entry has a missing or empty provider name";
                return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
            }
            slot_entry.provider_names.push_back(provider->str());
        }

        if (!HasText(entry->allowed_operations()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing or empty 'allowed_operations'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
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

        if (!HasText(entry->deployment_path()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing or empty 'deployment_path'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        slot_entry.deployment_path = entry->deployment_path()->str();

        if (!HasText(entry->deployment_format()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "Slot entry missing or empty 'deployment_format'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        slot_entry.deployment_format = entry->deployment_format()->str();

        out_config.AddSlotEntry(std::move(slot_entry));
        score::mw::log::LogDebug() << LOG_PREFIX << "Loaded key slot: '" << out_config.GetSlotEntries().back().slot_name
                                   << "'";
    }

    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseAppKeySlotMappings(
    const KeySlotConfig* key_slot_config,
    KeyConfig& out_config)
{
    const auto* app_key_slot_mappings = key_slot_config->app_key_slot_mappings();
    if (!app_key_slot_mappings)
    {
        return std::monostate{};
    }

    for (const auto* entry : *app_key_slot_mappings)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null app key slot entry encountered";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }

        KeyConfig::AppKeySlotMapping key_slot_entry;
        key_slot_entry.uid = entry->uid();

        if (!HasText(entry->app_resource_id()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "App key slot entry missing or empty 'app_resource_id'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        key_slot_entry.app_resource_id = entry->app_resource_id()->str();

        if (!HasText(entry->slot_name()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "App key slot entry missing or empty 'slot_name'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        key_slot_entry.slot_name = entry->slot_name()->str();

        out_config.AddAppKeySlotMapping(std::move(key_slot_entry));
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
// Section entry points
// ---------------------------------------------------------------------------

Expected<bool, common::DaemonErrorCode> FlatBufferConfigParser::ParseKeyManagementConfig(const ConfigFile& file,
                                                                                         KeyConfig& out_config)
{
    const auto* root = flatbuffers::GetRoot<CryptoConfig>(file.data());
    if (!root)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Failed to get CryptoConfig root";
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    }

    if (!root->key_slot_config())
    {
        score::mw::log::LogDebug() << LOG_PREFIX
                                   << "No key_slot_config in configuration - key management not configured";
        return false;
    }

    // Parse into a local so that out_config changes only when the whole section has parsed.
    KeyConfig parsed;
    auto key_res = ParseKeySlotConfig(root, parsed);
    if (!key_res.has_value())
    {
        return make_unexpected(key_res.error());
    }
    out_config = std::move(parsed);
    return true;
}

Expected<bool, common::DaemonErrorCode> FlatBufferConfigParser::ParseCertManagementConfig(const ConfigFile& file,
                                                                                          CertificateConfig& out_config)
{
    const auto* root = flatbuffers::GetRoot<CryptoConfig>(file.data());
    if (!root)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Failed to get CryptoConfig root";
        return make_unexpected(common::DaemonErrorCode::kInternalError);
    }

    if (!root->cert_slot_config())
    {
        score::mw::log::LogDebug() << LOG_PREFIX
                                   << "No cert_slot_config in configuration - cert management not configured";
        return false;
    }

    // Parse into a local so that out_config changes only when the whole section has parsed.
    CertificateConfig parsed;
    auto cert_res = ParseCertSlotConfig(root->cert_slot_config(), parsed);
    if (!cert_res.has_value())
    {
        return make_unexpected(cert_res.error());
    }
    out_config = std::move(parsed);
    return true;
}

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

Expected<ConfigFile, common::DaemonErrorCode> FlatBufferConfigParser::LoadFile(std::string_view filepath)
{
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

    auto validate_res = ValidateBuffer(buffer.data(), buffer.size());
    if (!validate_res.has_value())
    {
        return make_unexpected(validate_res.error());
    }
    return ConfigFile{std::move(buffer)};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseCertSlotConfig(
    const CertSlotConfig* cert_slot_config,
    CertificateConfig& out_config)
{
    const auto* parser_provider_name = cert_slot_config->parser_provider_name();
    out_config.SetParserProviderName(parser_provider_name ? parser_provider_name->str() : std::string{});

    auto res = ParseCertSlotEntries(cert_slot_config, out_config);
    if (!res.has_value())
    {
        return res;
    }

    res = ParseTrustStoreEntries(cert_slot_config, out_config);
    if (!res.has_value())
    {
        return res;
    }

    res = ParseAppCertSlotMappings(cert_slot_config, out_config);
    if (!res.has_value())
    {
        return res;
    }

    res = ParseAppTrustStoreMappings(cert_slot_config, out_config);
    if (!res.has_value())
    {
        return res;
    }

    score::mw::log::LogDebug() << LOG_PREFIX << "Cert config loaded: " << out_config.GetSlotEntries().size()
                               << " cert slot(s), " << out_config.GetTrustStoreEntries().size() << " trust store(s), "
                               << out_config.GetAppCertSlotMappings().size() << " app cert mapping(s), "
                               << out_config.GetAppTrustStoreMappings().size() << " app trust store mapping(s).";
    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseCertSlotEntries(
    const CertSlotConfig* cert_slot_config,
    CertificateConfig& out_config)
{
    const auto* entries = cert_slot_config->slot_entries();
    if (!entries)
    {
        return std::monostate{};
    }

    for (const auto* entry : *entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null cert slot entry encountered";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        if (!HasText(entry->slot_name()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "Cert slot entry missing or empty 'slot_name'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        if (!HasText(entry->deployment_path()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "Cert slot entry missing or empty 'deployment_path'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        // An absent field takes the schema default "kv"; an explicit value must be well formed.
        if (entry->deployment_format() && !HasText(entry->deployment_format()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "Cert slot entry has an empty or malformed 'deployment_format'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }

        CertificateConfig::CertSlotEntry slot;
        slot.slot_name = entry->slot_name()->str();
        // An absent field takes the schema default; an explicit value must be well formed, since no handler
        // can be selected for an empty one.
        if (entry->storage_backend() && !HasText(entry->storage_backend()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "Cert slot '" << slot.slot_name
                                       << "' has an empty or malformed storage_backend";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        slot.storage_backend = entry->storage_backend() ? entry->storage_backend()->str() : "DEFAULT";
        slot.deployment_path = entry->deployment_path()->str();
        slot.deployment_format = entry->deployment_format() ? entry->deployment_format()->str() : "kv";
        // An unknown value is rejected rather than defaulted, so a typo cannot silently disable the check.
        switch (entry->integrity_policy())
        {
            case IntegrityPolicy_disabled:
                slot.integrity_policy = CertificateConfig::IntegrityPolicy::kDisabled;
                break;
            case IntegrityPolicy_required:
                slot.integrity_policy = CertificateConfig::IntegrityPolicy::kRequired;
                break;
            default:
                score::mw::log::LogError()
                    << LOG_PREFIX << "Cert slot '" << slot.slot_name << "' has an unknown integrity_policy";
                return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }

        if (entry->allowed_uids())
        {
            for (auto uid : *entry->allowed_uids())
            {
                slot.allowed_uids.push_back(uid);
            }
        }
        if (entry->allowed_write_uids())
        {
            for (auto uid : *entry->allowed_write_uids())
            {
                slot.allowed_write_uids.push_back(uid);
            }
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
    {
        return std::monostate{};
    }

    for (const auto* entry : *entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null trust store entry encountered";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        if (!HasText(entry->store_name()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "Trust store entry missing or empty 'store_name'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        // An empty deployment_path is allowed: the store then keeps its state in memory only.
        if (!entry->deployment_path())
        {
            score::mw::log::LogError() << LOG_PREFIX << "Trust store entry missing 'deployment_path'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }
        // An absent field takes the schema default "kv"; an explicit value must be well formed.
        if (entry->deployment_format() && !HasText(entry->deployment_format()))
        {
            score::mw::log::LogError() << LOG_PREFIX
                                       << "Trust store entry has an empty or malformed 'deployment_format'";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
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
                store.conditional_slot_initialization =
                    CertificateConfig::ConditionalSlotInitialization::kDisableUntilAccepted;
                break;
            default:
                score::mw::log::LogError()
                    << LOG_PREFIX << "Trust store '" << store.store_name << "' has an unknown conditional_slot_init";
                return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }

        if (entry->allowed_uids())
        {
            for (auto uid : *entry->allowed_uids())
            {
                store.allowed_uids.push_back(uid);
            }
        }
        if (entry->allowed_write_uids())
        {
            for (auto uid : *entry->allowed_write_uids())
            {
                store.allowed_write_uids.push_back(uid);
            }
        }

        // Parse member entries
        if (entry->members())
        {
            for (const auto* member : *entry->members())
            {
                if (!member || !HasText(member->slot_name()))
                {
                    score::mw::log::LogError() << LOG_PREFIX << "Trust store member missing or empty 'slot_name'";
                    return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
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
                        mem.kind = CertificateConfig::TrustStoreMemberKind::kSharedStatic;
                        break;
                    default:
                        // An unknown kind must not default to a trusted member.
                        score::mw::log::LogError()
                            << LOG_PREFIX << "Trust store member '" << mem.slot_name << "' has an unknown kind";
                        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
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

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseAppCertSlotMappings(
    const CertSlotConfig* cert_slot_config,
    CertificateConfig& out_config)
{
    const auto* entries = cert_slot_config->app_cert_slot_mappings();
    if (!entries)
    {
        return std::monostate{};
    }

    for (const auto* entry : *entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null app cert slot entry encountered";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        if (!HasText(entry->app_resource_id()) || !HasText(entry->slot_name()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "App cert slot entry missing or empty required fields";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }

        CertificateConfig::AppCertSlotMapping app;
        app.uid = entry->uid();
        app.app_resource_id = entry->app_resource_id()->str();
        app.slot_name = entry->slot_name()->str();
        out_config.AddAppCertSlotMapping(std::move(app));
    }

    return std::monostate{};
}

Expected<std::monostate, common::DaemonErrorCode> FlatBufferConfigParser::ParseAppTrustStoreMappings(
    const CertSlotConfig* cert_slot_config,
    CertificateConfig& out_config)
{
    const auto* entries = cert_slot_config->app_trust_store_mappings();
    if (!entries)
    {
        return std::monostate{};
    }

    for (const auto* entry : *entries)
    {
        if (!entry)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Null app trust store entry encountered";
            return make_unexpected(common::DaemonErrorCode::kInternalError);
        }
        if (!HasText(entry->app_resource_id()) || !HasText(entry->trust_store_name()))
        {
            score::mw::log::LogError() << LOG_PREFIX << "App trust store entry missing or empty required fields";
            return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }

        CertificateConfig::AppTrustStoreMapping app;
        app.uid = entry->uid();
        app.app_resource_id = entry->app_resource_id()->str();
        app.trust_store_name = entry->trust_store_name()->str();
        out_config.AddAppTrustStoreMapping(std::move(app));
    }

    return std::monostate{};
}

}  // namespace score::crypto::daemon::config
