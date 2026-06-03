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

#include "score/crypto/daemon/provider/provider_manager.hpp"

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
        throw std::runtime_error("Failed to create providers");
    }

    // Use provided config or create default
    config::ProviderInitConfig activeConfig = m_config.GetProviderInitConfig();

    if (activeConfig.providers.empty())
    {
        activeConfig = CreateDefaultConfig();
    }

    // Set the type-to-provider mappings
    m_typeToProviderId = activeConfig.typeToProviderId;

    // Initialize all providers
    return InitializeAll();
}

config::ProviderInitConfig ProviderManager::CreateDefaultConfig()
{
    config::ProviderInitConfig config;

    // Add all created providers to config as enabled
    for (const auto& pair : m_providers)
    {
        config.AddProviderConfig(config::ProviderConfig(pair.second.numeric_id, pair.second.cryptoType, true));
    }

    // Set the first provider as default for all applicable types
    if (!m_providers.empty())
    {
        const auto& firstEntry = m_providers.begin()->second;
        common::ProviderId firstProviderId = firstEntry.numeric_id;

        config.typeToProviderId = m_typeToProviderId;

        // Set as default for all common types not configured with a provider

        if (config.typeToProviderId.find(common::CryptoProviderType::DEFAULT) == config.typeToProviderId.end())
        {
            // Prefer the HARDWARE provider (e.g., SoftHSM/PKCS#11) as DEFAULT when available,
            // falling back to SOFTWARE (OpenSSL) and then the first registered provider.
            common::ProviderId defaultId = common::kInvalidProviderId;

            // Search for HARDWARE or SOFTWARE provider
            for (const auto& entry : m_providers)
            {
                if (entry.second.cryptoType == common::CryptoProviderType::HARDWARE)
                {
                    defaultId = entry.second.numeric_id;
                    break;
                }
            }
            if (defaultId == common::kInvalidProviderId)
            {
                for (const auto& entry : m_providers)
                {
                    if (entry.second.cryptoType == common::CryptoProviderType::SOFTWARE)
                    {
                        defaultId = entry.second.numeric_id;
                        break;
                    }
                }
            }
            if (defaultId == common::kInvalidProviderId)
            {
                defaultId = firstProviderId;
            }

            config.SetDefaultProviderForType(common::CryptoProviderType::DEFAULT, defaultId);
        }
        if (config.typeToProviderId.find(common::CryptoProviderType::SOFTWARE) == config.typeToProviderId.end())
        {
            config.SetDefaultProviderForType(common::CryptoProviderType::SOFTWARE, firstProviderId);
        }
        if (config.typeToProviderId.find(common::CryptoProviderType::HARDWARE) == config.typeToProviderId.end())
        {
            config.SetDefaultProviderForType(common::CryptoProviderType::HARDWARE, firstProviderId);
        }
        if (config.typeToProviderId.find(common::CryptoProviderType::SPECIALIZED) == config.typeToProviderId.end())
        {
            config.SetDefaultProviderForType(common::CryptoProviderType::SPECIALIZED, firstProviderId);
        }
    }

    return config;
}

bool ProviderManager::CreateProviders()
{
    // Invoke each registered factory in order.
    // Factories are wired externally (e.g. in daemon main()) via RegisterFactory().
    for (auto& factory : m_factories)
    {
        if (!factory->CreateAndRegister(*this))
        {
            return false;
        }
    }
    return true;
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
    return m_provider_by_id[providerId];
}

std::shared_ptr<IProvider> ProviderManager::GetProvider(const common::ProviderName& providerName) const
{
    auto it = m_providers.find(providerName);
    if (it != m_providers.end())
    {
        return it->second.instance;
    }
    return nullptr;
}

std::shared_ptr<IProvider> ProviderManager::GetProvider(common::CryptoProviderType cryptoType) const
{
    auto it = m_typeToProviderId.find(cryptoType);
    if (it != m_typeToProviderId.end())
    {
        return GetProvider(it->second);
    }
    return nullptr;
}

bool ProviderManager::SetDefaultProviderForType(common::CryptoProviderType cryptoType, common::ProviderId providerId)
{
    // Verify the provider exists by numeric ID
    if (providerId >= m_provider_by_id.size() || !m_provider_by_id[providerId])
    {
        return false;
    }

    // Update the mapping - same provider can be default for multiple types
    m_typeToProviderId[cryptoType] = providerId;
    return true;
}

bool ProviderManager::InitializeAll()
{
    for (auto& entry : m_providers)
    {
        ProviderInitContext ctx{entry.second.numeric_id, entry.first};
        if (!entry.second.instance->Initialize(ctx))
        {
            return false;
        }
    }
    return true;
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
