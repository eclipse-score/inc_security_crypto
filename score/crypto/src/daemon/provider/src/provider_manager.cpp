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

#include <stdexcept>
#include <unordered_set>

#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/mw/log/logging.h"

namespace score::crypto
{
namespace daemon
{
namespace provider
{

ProviderManager::ProviderManager(const score::crypto::daemon::config::Config& config) : m_config(config) {}

ProviderManager::~ProviderManager()
{
    Shutdown();
    m_providers.clear();
    m_typeToProviderId.clear();
}

bool ProviderManager::Initialize()
{
    // Create and register all available providers
    if (!CreateProviders())
    {
        return false;
    }

    // Initialize all providers before deciding on default mappings.
    // Individual failures are tolerated; failed providers are hidden from lookups
    // because GetProvider() queries provider->IsInitialized() directly.
    const bool init_ok = InitializeAll();

    // Use provided config or create default from initialized providers only.
    config::ProviderInitConfig activeConfig = m_config.GetProviderInitConfig();

    if (activeConfig.providers.empty())
    {
        activeConfig = CreateDefaultConfig();
    }

    // Apply enablement: shutdown and hide providers not marked as enabled.
    ApplyEnablement(activeConfig.providers);

    // Build type-to-provider mappings, resolving configured names to runtime IDs.
    BuildTypeMappings(activeConfig.typeToProviderName);

    return init_ok;
}

config::ProviderInitConfig ProviderManager::CreateDefaultConfig(
    const std::vector<common::CryptoProviderType>& preferenceOrder)
{
    config::ProviderInitConfig config;

    // Add all initialized providers to config as enabled
    for (const auto& pair : m_providers)
    {
        if (pair.second.instance && pair.second.instance->IsInitialized())
        {
            config.AddProviderConfig(config::ProviderConfig(pair.first, pair.second.cryptoType, true));
        }
    }

    // Select a DEFAULT provider based on the preference order. SOFTWARE,
    // HARDWARE and SPECIALIZED mappings are derived from each provider's
    // declared cryptoType in BuildTypeMappings(), so they are not overridden
    // here.
    if (!config.providers.empty())
    {
        if (config.typeToProviderName.find(common::CryptoProviderType::DEFAULT) == config.typeToProviderName.end())
        {
            common::ProviderName defaultName;

            for (const auto& preferredType : preferenceOrder)
            {
                for (const auto& entry : m_providers)
                {
                    if (entry.second.instance && entry.second.instance->IsInitialized() &&
                        entry.second.cryptoType == preferredType)
                    {
                        defaultName = entry.first;
                        break;
                    }
                }
                if (!defaultName.empty())
                {
                    break;
                }
            }

            if (defaultName.empty())
            {
                defaultName = config.providers.front().providerName;
            }

            config.SetDefaultProviderForType(common::CryptoProviderType::DEFAULT, defaultName);
        }
    }

    return config;
}

void ProviderManager::ApplyEnablement(const std::vector<config::ProviderConfig>& provider_configs)
{
    std::unordered_set<common::ProviderName> enabled_names;
    for (const auto& cfg : provider_configs)
    {
        if (cfg.enabled)
        {
            enabled_names.insert(cfg.providerName);
        }
    }

    for (auto it = m_providers.begin(); it != m_providers.end();)
    {
        if (enabled_names.find(it->first) == enabled_names.end())
        {
            const auto numeric_id = it->second.numeric_id;
            if (it->second.instance)
            {
                it->second.instance->Shutdown();
            }
            if (numeric_id < m_provider_by_id.size())
            {
                m_provider_by_id[numeric_id].reset();
            }
            it = m_providers.erase(it);
        }
        else
        {
            ++it;
        }
    }
    // List the enabled providers after applying enablement
    score::mw::log::LogInfo() << "[ProviderManager] Enabled providers after applying enablement:";
    for (const auto& pair : m_providers)
    {
        score::mw::log::LogInfo() << "  - " << pair.first << " (numeric_id=" << pair.second.numeric_id
                                  << ", type=" << static_cast<int>(pair.second.cryptoType) << ")";
    }
}

void ProviderManager::BuildTypeMappings(
    const std::unordered_map<common::CryptoProviderType, common::ProviderName>& type_to_name)
{
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
            continue;
        }
        m_typeToProviderId[crypto_type] = it->second.numeric_id;
    }
}

bool ProviderManager::CreateProviders()
{
    // Invoke each registered factory in order.
    // Factories are wired externally (e.g. in daemon main()) via RegisterFactory().
    // Non-critical factories (e.g. PKCS#11/SoftHSM) may fail on platforms where
    // the backing library is unavailable. Continue with remaining factories.
    bool any_registered = false;
    for (auto& factory : m_factories)
    {
        if (factory->CreateAndRegister(*this))
        {
            any_registered = true;
        }
    }
    return any_registered;
}

void ProviderManager::RegisterFactory(std::unique_ptr<IProviderFactory> factory)
{
    if (!factory)
    {
        throw std::runtime_error("RegisterFactory: factory must not be null");
    }
    m_factories.emplace_back(std::move(factory));
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
        throw std::runtime_error("Cannot register null provider for: " + providerName);
    }

    // Assign numeric ID: next index in m_provider_by_id
    common::ProviderId numeric_id = static_cast<common::ProviderId>(m_provider_by_id.size());

    // Store the instance in the vector for O(1) numeric lookup
    m_provider_by_id.push_back(provider);

    // Store the entry in the map for O(1) name lookup
    m_providers.emplace(providerName, ProviderEntry(providerName, numeric_id, provider, cryptoType));

    // Map the type to this numeric ID if not already mapped
    if (m_typeToProviderId.find(cryptoType) == m_typeToProviderId.end())
    {
        m_typeToProviderId[cryptoType] = numeric_id;
    }

    return true;
}

std::shared_ptr<IProvider> ProviderManager::GetProvider(common::ProviderId providerId) const
{
    if (providerId >= m_provider_by_id.size())
    {
        return nullptr;
    }
    if (!IsProviderInitialized(providerId))
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
    if (!IsProviderInitialized(it->second.numeric_id))
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
    if (!IsProviderInitialized(it->second))
    {
        return nullptr;
    }
    return GetProvider(it->second);
}

bool ProviderManager::SetDefaultProviderForType(common::CryptoProviderType cryptoType, common::ProviderId providerId)
{
    // Verify the provider exists by numeric ID and is initialized
    if (providerId >= m_provider_by_id.size() || !m_provider_by_id[providerId] || !IsProviderInitialized(providerId))
    {
        return false;
    }

    // Update the mapping - same provider can be default for multiple types
    m_typeToProviderId[cryptoType] = providerId;
    return true;
}

bool ProviderManager::InitializeAll()
{
    bool all_ok = true;
    for (auto& entry : m_providers)
    {
        ProviderInitContext ctx{entry.second.numeric_id, entry.first};
        if (!entry.second.instance->Initialize(ctx))
        {
            all_ok = false;
        }
    }
    return all_ok;
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
