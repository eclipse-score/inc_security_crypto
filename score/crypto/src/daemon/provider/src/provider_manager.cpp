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
#include <string_view>
#include <utility>

#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/mw/log/logging.h"

namespace score::crypto
{
namespace daemon
{
namespace provider
{
namespace
{
std::string_view ProviderFailureReasonName(const ProviderFailureReason reason) noexcept
{
    switch (reason)
    {
        case ProviderFailureReason::kFactoryCreationFailed:
            return "factory creation failed";
        case ProviderFailureReason::kProviderUnavailable:
            return "provider unavailable";
        case ProviderFailureReason::kProviderRegistrationFailed:
            return "provider registration failed";
        case ProviderFailureReason::kProviderInitializationFailed:
            return "provider initialization failed";
        case ProviderFailureReason::kRequiredProviderUnavailable:
            return "required provider unavailable";
        case ProviderFailureReason::kDefaultProviderUnavailable:
            return "default provider unavailable";
    }
    return "unknown provider failure";
}
}  // namespace

ProviderManager::ProviderManager(config::ProviderRoutingPolicy routing_policy)
    : m_routingPolicy(std::move(routing_policy))
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
    if (m_isShutdown.load())
    {
        return false;
    }

    // Make an initial attempt for every registered provider before building
    // mappings. Individual failures are tolerated and retried on lookup.
    (void)InitializeAll();

    // Build category mappings first so an implicit DEFAULT can honor explicit
    // SOFTWARE/HARDWARE/SPECIALIZED defaults from the routing policy.
    const bool mappings_ok = BuildTypeMappings(m_routingPolicy.typeToProviderName);

    if (mappings_ok && (m_routingPolicy.typeToProviderName.find(common::CryptoProviderType::DEFAULT) ==
                        m_routingPolicy.typeToProviderName.end()))
    {
        const auto defaultName = ResolveDefaultProviderName(m_routingPolicy.defaultProviderPreference);
        if (!defaultName.empty())
        {
            m_typeToProviderId[common::CryptoProviderType::DEFAULT] = m_providers.at(defaultName).numeric_id;
        }
    }

    return mappings_ok && !m_providers.empty() && !m_isShutdown.load();
}

void ProviderManager::RecordFactoryResult(const std::string& factoryName, ProviderFactoryResult result)
{
    for (auto& failure : result.failures)
    {
        if (failure.factoryName.empty())
        {
            failure.factoryName = factoryName;
        }
        score::mw::log::LogWarn() << "[ProviderManager] Provider startup failure: factory=" << failure.factoryName
                                  << ", provider=" << failure.providerName
                                  << ", reason=" << ProviderFailureReasonName(failure.reason)
                                  << ", error=" << static_cast<std::uint32_t>(failure.error);
        m_initializationFailures.push_back(std::move(failure));
    }
}

common::ProviderName ProviderManager::ResolveDefaultProviderName(
    const std::vector<common::CryptoProviderType>& preferenceOrder)
{
    // Category mappings have already been built. Within each preferred
    // category, try its configured default first and then the remaining
    // providers in registration order. This preserves category preference when
    // a category default is temporarily unavailable.
    for (const auto preferred : preferenceOrder)
    {
        const auto mapped = m_typeToProviderId.find(preferred);
        if (mapped != m_typeToProviderId.end())
        {
            const auto& entry = m_providers.at(m_name_by_id[mapped->second]);
            if (entry.instance && entry.instance->IsInitialized())
            {
                return entry.name;
            }
        }

        for (common::ProviderId id = 0; id < m_provider_by_id.size(); ++id)
        {
            if ((mapped != m_typeToProviderId.end()) && (id == mapped->second))
            {
                continue;
            }
            const auto& entry = m_providers.at(m_name_by_id[id]);
            if ((entry.cryptoType == preferred) && entry.instance && entry.instance->IsInitialized())
            {
                return entry.name;
            }
        }
    }

    // If no preferred category default is currently available, use any
    // initialized provider before falling back to a registered provider that
    // may support deferred initialization.
    common::ProviderName initializedFallback;
    common::ProviderName registeredFallback;

    for (common::ProviderId id = 0; id < m_provider_by_id.size(); ++id)
    {
        const auto& entry = m_providers.at(m_name_by_id[id]);
        if (!entry.instance)
        {
            continue;
        }
        if (registeredFallback.empty())
        {
            registeredFallback = entry.name;
        }
        if (entry.instance->IsInitialized())
        {
            if (initializedFallback.empty())
            {
                initializedFallback = entry.name;
            }
        }
    }

    if (!initializedFallback.empty())
    {
        return initializedFallback;
    }

    for (const auto preferred : preferenceOrder)
    {
        const auto mapped = m_typeToProviderId.find(preferred);
        if (mapped != m_typeToProviderId.end())
        {
            return m_name_by_id[mapped->second];
        }
    }
    return registeredFallback;
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
    for (common::ProviderId id = 0; id < m_name_by_id.size(); ++id)
    {
        const auto& entry = m_providers.at(m_name_by_id[id]);
        const auto crypto_type = entry.cryptoType;
        if (m_typeToProviderId.find(crypto_type) == m_typeToProviderId.end())
        {
            m_typeToProviderId[crypto_type] = entry.numeric_id;
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
        if ((crypto_type != common::CryptoProviderType::DEFAULT) && (it->second.cryptoType != crypto_type))
        {
            score::mw::log::LogWarn() << "[ProviderManager] Type mapping for " << provider_name
                                      << " does not match the provider's registered category";
            m_initializationFailures.push_back(ProviderFailure{"",
                                                               provider_name,
                                                               ProviderFailureReason::kDefaultProviderUnavailable,
                                                               common::DaemonErrorCode::kInvalidArgument});
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
    std::lock_guard<std::mutex> lock(m_providerMutex);
    if (m_isShutdown.load())
    {
        score::mw::log::LogError() << "[ProviderManager] Cannot register a provider after shutdown";
        return false;
    }

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

    // Store the instance and name for O(1) numeric lookup
    m_provider_by_id.push_back(provider);
    m_name_by_id.push_back(providerName);

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
    auto& provider_entry = const_cast<ProviderEntry&>(m_providers.at(m_name_by_id[providerId]));
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
    auto& provider_entry = const_cast<ProviderEntry&>(m_providers.at(m_name_by_id[it->second]));
    if (!EnsureProviderInitialized(provider_entry))
    {
        return nullptr;
    }
    return provider_entry.instance;
}

std::shared_ptr<IProvider> ProviderManager::GetProviderForCapability(common::ProviderCapability capability) const
{
    const auto it = m_routingPolicy.capabilityRouting.find(capability);
    if (it != m_routingPolicy.capabilityRouting.end())
    {
        return SelectProviderForCapability(capability, it->second.preferenceOrder, it->second.allowFallback);
    }
    return SelectProviderForCapability(capability, m_routingPolicy.defaultProviderPreference, true);
}

std::shared_ptr<IProvider> ProviderManager::GetProviderForCapability(
    common::ProviderCapability capability,
    const std::vector<common::CryptoProviderType>& preferenceOrder) const
{
    return SelectProviderForCapability(capability, preferenceOrder, true);
}

std::shared_ptr<IProvider> ProviderManager::SelectProviderForCapability(
    common::ProviderCapability capability,
    const std::vector<common::CryptoProviderType>& preference_order,
    bool allow_fallback) const
{
    if (capability == common::ProviderCapability::kNone)
    {
        return nullptr;
    }

    const auto try_type = [this, capability](const common::CryptoProviderType provider_type) {
        const auto try_id = [this, capability, provider_type](const common::ProviderId id) {
            auto& entry = const_cast<ProviderEntry&>(m_providers.at(m_name_by_id[id]));
            if ((entry.cryptoType == provider_type) && entry.instance &&
                common::HasCapability(entry.instance->GetProviderCapabilities(), capability) &&
                EnsureProviderInitialized(entry))
            {
                return entry.instance;
            }
            return std::shared_ptr<IProvider>{};
        };

        // The configured category default is the first candidate within that
        // category. If it cannot serve the capability, try the remaining
        // providers in deterministic registration order.
        const auto mapped = m_typeToProviderId.find(provider_type);
        if (mapped != m_typeToProviderId.end())
        {
            auto provider = try_id(mapped->second);
            if (provider)
            {
                return provider;
            }
        }
        for (common::ProviderId id = 0; id < m_provider_by_id.size(); ++id)
        {
            if ((mapped != m_typeToProviderId.end()) && (id == mapped->second))
            {
                continue;
            }
            auto provider = try_id(id);
            if (provider)
            {
                return provider;
            }
        }
        return std::shared_ptr<IProvider>{};
    };

    // Resolve preferred categories in policy order. Providers in lower-priority
    // or excluded categories are not initialized unless fallback is enabled.
    for (const auto preferred : preference_order)
    {
        auto provider = try_type(preferred);
        if (provider)
        {
            return provider;
        }
    }

    if (!allow_fallback)
    {
        return nullptr;
    }

    // Fallback considers only categories outside the explicit preference list,
    // preserving registration order for deterministic selection.
    for (common::ProviderId id = 0; id < m_provider_by_id.size(); ++id)
    {
        auto& entry = const_cast<ProviderEntry&>(m_providers.at(m_name_by_id[id]));
        if (std::find(preference_order.begin(), preference_order.end(), entry.cryptoType) != preference_order.end())
        {
            continue;
        }
        if (entry.instance && common::HasCapability(entry.instance->GetProviderCapabilities(), capability) &&
            EnsureProviderInitialized(entry))
        {
            return entry.instance;
        }
    }
    return nullptr;
}

bool ProviderManager::SetDefaultProviderForType(common::CryptoProviderType cryptoType, common::ProviderId providerId)
{
    // Verify the provider exists by numeric ID and is initialized
    if (!IsProviderInitialized(providerId))
    {
        return false;
    }

    const auto& entry = m_providers.at(m_name_by_id[providerId]);
    if ((cryptoType != common::CryptoProviderType::DEFAULT) && (entry.cryptoType != cryptoType))
    {
        return false;
    }

    // DEFAULT can point to any provider. Category-specific mappings require an
    // exact category match to preserve the routing contract.
    m_typeToProviderId[cryptoType] = providerId;
    return true;
}

bool ProviderManager::InitializeAll()
{
    bool any_ok = false;
    for (common::ProviderId id = 0; id < m_name_by_id.size(); ++id)
    {
        auto& entry = m_providers.at(m_name_by_id[id]);
        if (EnsureProviderInitialized(entry))
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
    if (m_isShutdown.load())
    {
        return false;
    }
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
    if (m_isShutdown.load() || (provider_id >= m_provider_by_id.size()))
    {
        return false;
    }
    const auto& provider = m_provider_by_id[provider_id];
    return provider && provider->IsInitialized();
}

void ProviderManager::Shutdown()
{
    std::vector<std::shared_ptr<IProvider>> providers;
    {
        // Wait for an in-flight initialization attempt, then prevent any new
        // provider operation from starting before releasing the lock.
        std::lock_guard<std::mutex> lock(m_providerMutex);
        if (m_isShutdown.exchange(true))
        {
            return;
        }
        providers = m_provider_by_id;
    }

    // Provider callbacks are external code. Invoke them outside the manager
    // mutex to avoid lock inversion or re-entrant deadlocks during shutdown.
    for (const auto& provider : providers)
    {
        if (provider)
        {
            provider->Shutdown();
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
    return m_providers.at(m_name_by_id[provider_id]).cryptoType == requested_type;
}

}  // namespace provider
}  // namespace daemon
}  // namespace score::crypto
