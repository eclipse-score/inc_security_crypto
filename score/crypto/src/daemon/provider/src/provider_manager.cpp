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

#include <algorithm>
#include <utility>

#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/mw/log/logging.h"

namespace score::crypto
{
namespace daemon
{
namespace provider
{

ProviderManager::ProviderManager(config::ProviderInitConfig provider_config)
    : m_providerConfig(std::move(provider_config))
{
}

ProviderManager::~ProviderManager()
{
    Shutdown();
    m_providers.clear();
    m_typeToProviderId.clear();
}

bool ProviderManager::Initialize()
{
    // Make an initial attempt for every registered provider before building
    // mappings. Individual failures are tolerated and retried on lookup.
    (void)InitializeAll();

    config::ProviderInitConfig activeConfig = m_providerConfig;

    if (activeConfig.typeToProviderName.find(common::CryptoProviderType::DEFAULT) ==
        activeConfig.typeToProviderName.end())
    {
        const auto defaultName = ResolveDefaultProviderName();
        if (!defaultName.empty())
        {
            activeConfig.typeToProviderName[common::CryptoProviderType::DEFAULT] = defaultName;
        }
    }

    // Build type-to-provider mappings, resolving configured names to runtime IDs.
    const bool mappings_ok = BuildTypeMappings(activeConfig.typeToProviderName);

    return mappings_ok && !m_providers.empty() && !m_hasFatalInitializationFailure;
}

void ProviderManager::RecordFactoryResult(const std::string& factoryName, ProviderFactoryResult result)
{
    for (auto& failure : result.failures)
    {
        if (failure.factoryName.empty())
        {
            failure.factoryName = factoryName;
        }
        if (failure.reason == ProviderFailureReason::kRequiredProviderUnavailable ||
            failure.reason == ProviderFailureReason::kDefaultProviderUnavailable)
        {
            m_hasFatalInitializationFailure = true;
        }
        m_initializationFailures.push_back(std::move(failure));
    }
}

common::ProviderName ProviderManager::ResolveDefaultProviderName(
    const std::vector<common::CryptoProviderType>& preferenceOrder)
{
    std::unordered_map<common::CryptoProviderType, common::ProviderName> byType;
    common::ProviderName anyName;
    for (const auto& [name, entry] : m_providers)
    {
        if (!entry.instance)
        {
            continue;
        }
        byType.emplace(entry.cryptoType, name);
        if (anyName.empty())
        {
            anyName = name;
        }
    }

    for (const auto& preferred : preferenceOrder)
    {
        auto it = byType.find(preferred);
        if (it != byType.end())
        {
            return it->second;
        }
    }
    return anyName;
}

bool ProviderManager::BuildTypeMappings(
    const std::unordered_map<common::CryptoProviderType, common::ProviderName>& type_to_name)
{
    bool mappings_ok = true;
    // Start from the type declared by each registered provider. This ensures
    // a SOFTWARE provider is reachable via CryptoProviderType::SOFTWARE and a
    // HARDWARE provider via CryptoProviderType::HARDWARE even when the daemon
    // config does not supply explicit type mappings.
    m_typeToProviderId.clear();
    for (const auto& entry : m_providers)
    {
        const auto& crypto_type = entry.second.cryptoType;
        if (m_typeToProviderId.find(crypto_type) == m_typeToProviderId.end())
        {
            m_typeToProviderId[crypto_type] = entry.second.numeric_id;
        }
    }

    // Apply config-driven overrides. Configured names take precedence over the
    // provider-declared types above.
    for (const auto& [crypto_type, provider_name] : type_to_name)
    {
        auto it = m_providers.find(provider_name);
        if (it == m_providers.end())
        {
            score::mw::log::LogWarn() << "[ProviderManager] Type mapping references unknown or disabled provider: "
                                      << provider_name;
            m_initializationFailures.push_back(ProviderFailure{"",
                                                               provider_name,
                                                               ProviderFailureReason::kDefaultProviderUnavailable,
                                                               common::DaemonErrorCode::kProviderNotAvailable});
            mappings_ok = false;
            continue;
        }
        m_typeToProviderId[crypto_type] = it->second.numeric_id;
    }
    return mappings_ok;
}

bool ProviderManager::RegisterProvider(const common::ProviderName& providerName,
                                       std::shared_ptr<IProvider> provider,
                                       common::CryptoProviderType cryptoType)
{
    // Check if provider name already exists
    if (m_providers.find(providerName) != m_providers.end())
    {
        return false;
    }

    if (!provider)
    {
        score::mw::log::LogError() << "[ProviderManager] Cannot register null provider for: " << providerName;
        return false;
    }

    // Assign numeric ID: next index in m_provider_by_id
    common::ProviderId numeric_id = static_cast<common::ProviderId>(m_provider_by_id.size());

    // Store the instance in the vector for O(1) numeric lookup
    m_provider_by_id.push_back(provider);

    // Store the entry in the map for O(1) name lookup
    m_providers.emplace(providerName, ProviderEntry(providerName, numeric_id, provider, cryptoType));
    score::mw::log::LogInfo() << "[ProviderManager] Provider registered: " << providerName
                              << " (numeric_id=" << numeric_id << ")";

    // Map the type to this numeric ID if not already mapped
    if (m_typeToProviderId.find(cryptoType) == m_typeToProviderId.end())
    {
        m_typeToProviderId[cryptoType] = numeric_id;
    }

    return true;
}

bool ProviderManager::IsProviderRegistered(const common::ProviderName& provider_name) const
{
    return m_providers.find(provider_name) != m_providers.end();
}

std::shared_ptr<IProvider> ProviderManager::GetProvider(common::ProviderId providerId) const
{
    if (providerId >= m_provider_by_id.size())
    {
        return nullptr;
    }
    auto& provider_entry = const_cast<ProviderEntry&>(m_providers.at(m_provider_by_id[providerId]->GetProviderName()));
    if (!EnsureProviderInitialized(provider_entry))
    {
        return nullptr;
    }
    return m_provider_by_id[providerId];
}

std::shared_ptr<IProvider> ProviderManager::GetProvider(const common::ProviderName& providerName) const
{
    auto it = m_providers.find(providerName);
    if (it == m_providers.end())
    {
        return nullptr;
    }
    auto& provider_entry = const_cast<ProviderEntry&>(it->second);
    if (!EnsureProviderInitialized(provider_entry))
    {
        return nullptr;
    }
    return it->second.instance;
}

std::shared_ptr<IProvider> ProviderManager::GetProvider(common::CryptoProviderType cryptoType) const
{
    auto it = m_typeToProviderId.find(cryptoType);
    if (it == m_typeToProviderId.end())
    {
        return nullptr;
    }
    if (it->second >= m_provider_by_id.size() || !m_provider_by_id[it->second])
    {
        return nullptr;
    }
    auto& provider_entry = const_cast<ProviderEntry&>(m_providers.at(m_provider_by_id[it->second]->GetProviderName()));
    if (!EnsureProviderInitialized(provider_entry))
    {
        return nullptr;
    }
    return provider_entry.instance;
}

bool ProviderManager::SetDefaultProviderForType(common::CryptoProviderType cryptoType, common::ProviderId providerId)
{
    // Verify the provider exists by numeric ID and is initialized
    if (!IsProviderInitialized(providerId))
    {
        return false;
    }

    // Update the mapping - same provider can be default for multiple types
    m_typeToProviderId[cryptoType] = providerId;
    return true;
}

bool ProviderManager::InitializeAll()
{
    bool any_ok = false;
    for (auto& entry : m_providers)
    {
        if (EnsureProviderInitialized(entry.second))
        {
            any_ok = true;
        }
    }
    return any_ok;
}

bool ProviderManager::EnsureProviderInitialized(ProviderEntry& entry) const
{
    if (!entry.instance)
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_providerMutex);
    if (entry.instance->IsInitialized())
    {
        return true;
    }

    score::mw::log::LogInfo() << "[ProviderManager] Initializing provider: " << entry.name;
    ProviderInitContext ctx{entry.numeric_id, entry.name};
    if (entry.instance->Initialize(ctx))
    {
        score::mw::log::LogInfo() << "[ProviderManager] Provider is available: " << entry.name;
        return true;
    }

    score::mw::log::LogWarn() << "[ProviderManager] Provider is not available yet: " << entry.name;
    const bool failure_already_recorded = std::any_of(
        m_initializationFailures.begin(), m_initializationFailures.end(), [&entry](const ProviderFailure& failure) {
            return failure.providerName == entry.name &&
                   failure.reason == ProviderFailureReason::kProviderInitializationFailed;
        });
    if (!failure_already_recorded)
    {
        m_initializationFailures.push_back(ProviderFailure{"",
                                                           entry.name,
                                                           ProviderFailureReason::kProviderInitializationFailed,
                                                           common::DaemonErrorCode::kProviderNotAvailable});
    }
    return false;
}

bool ProviderManager::IsProviderInitialized(common::ProviderId provider_id) const
{
    if (provider_id >= m_provider_by_id.size())
    {
        return false;
    }
    const auto& provider = m_provider_by_id[provider_id];
    return provider && provider->IsInitialized();
}

void ProviderManager::Shutdown()
{
    for (auto& pair : m_providers)
    {
        if (pair.second.instance)
        {
            pair.second.instance->Shutdown();
        }
    }
}

std::optional<common::CryptoProviderType> ProviderManager::GetProviderType(
    const common::ProviderName& provider_name) const
{
    const auto it = m_providers.find(provider_name);
    if (it == m_providers.end())
    {
        return std::nullopt;
    }
    return it->second.cryptoType;
}

bool ProviderManager::IsProviderCompatibleWithType(const common::ProviderId provider_id,
                                                   common::CryptoProviderType requested_type) const
{
    if (!IsProviderInitialized(provider_id))
    {
        return false;
    }
    if (requested_type == common::CryptoProviderType::DEFAULT)
    {
        return true;
    }
    // Look up provider type by iterating through entries to find matching numeric_id
    for (const auto& entry : m_providers)
    {
        if (entry.second.numeric_id == provider_id)
        {
            return entry.second.cryptoType == requested_type;
        }
    }
    return false;
}

}  // namespace provider
}  // namespace daemon
}  // namespace score::crypto
