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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_MANAGER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_MANAGER_HPP

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "i_provider.hpp"
#include "i_provider_factory.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/config/inc/config.hpp"

namespace score::crypto
{
namespace daemon
{
namespace provider
{

/**
 * @brief Provider entry point - represents a registered provider instance
 *
 * Stores both the human-readable name (from configuration) and the assigned
 * numeric ID (from ProviderManager at registration time).
 */
struct ProviderEntry
{
    common::ProviderName name;              ///< Human-readable name from config/factory
    common::ProviderId numeric_id;          ///< Index assigned at registration
    std::shared_ptr<IProvider> instance;    ///< Provider instance
    common::CryptoProviderType cryptoType;  ///< Functional category

    // Default constructor
    ProviderEntry()
        : name(""),
          numeric_id(common::kInvalidProviderId),
          instance(nullptr),
          cryptoType(common::CryptoProviderType::DEFAULT)
    {
    }

    ProviderEntry(const common::ProviderName& providerName,
                  common::ProviderId id,
                  std::shared_ptr<IProvider> prov,
                  common::CryptoProviderType cryptoType)
        : name(providerName), numeric_id(id), instance(prov), cryptoType(cryptoType)
    {
    }
};

/**
 * @brief Initialization class for managing crypto provider instances
 *
 * This class manages the lifecycle of provider instances during daemon startup.
 * The daemon calls Initialize() once during startup with a configuration.
 *
 * To add new providers:
 * 1. Modify the Initialize() or CreateProviders() implementation in
 * provider_manager.cpp
 * 2. Add your provider instantiation logic
 * 3. The factory will register and manage your provider automatically
 *
 * Usage Pattern:
 * In daemon main:
 *   ProviderManager manager;
 *   ProviderInitConfig config;
 *   config.SetDefaultProviderForType(CryptoProviderType::SOFTWARE,
 * kProviderNameOpenSSL); manager.Initialize(config); auto provider =
 * manager.GetProvider(kProviderNameOpenSSL);
 */
class ProviderManager
{
  public:
    using Sptr = std::shared_ptr<ProviderManager>;
    /**
     * @brief Constructor
     */
    ProviderManager(const score::crypto::daemon::config::Config& config);

    /**
     * @brief Destructor - cleans up all registered providers
     */
    ~ProviderManager();

    // Disable copy operations
    ProviderManager(const ProviderManager&) = delete;
    ProviderManager& operator=(const ProviderManager&) = delete;

    // Allow move operations
    ProviderManager(ProviderManager&&) noexcept = delete;
    ProviderManager& operator=(ProviderManager&&) noexcept = delete;

    /**
     * @brief Initialize the factory with provider configuration
     *
     * This method initializes all providers based on the provided configuration.
     * If no config is provided, a default configuration is used that:
     * - Enables all available providers
     * - Sets the first available provider as default for all applicable types
     *
     * This is the only method the daemon needs to call during startup.
     * Provider instantiation logic is in the implementation file.
     *
     * @param config Optional provider initialization configuration. If not
     * provided, a default configuration is created automatically.
     * @return true if all providers initialized successfully, false otherwise
     * @throws std::runtime_error if provider initialization fails
     */
    bool Initialize();

    /**
     * @brief Get a provider by its numeric ID
     *
     * @param providerId The numeric provider identifier (uint16_t)
     * @return Shared pointer to the provider, or nullptr if not found
     */
    std::shared_ptr<IProvider> GetProvider(common::ProviderId providerId) const;

    /**
     * @brief Get a provider by its name string
     *
     * @param providerName The human-readable provider name
     * @return Shared pointer to the provider, or nullptr if not found
     */
    std::shared_ptr<IProvider> GetProvider(const common::ProviderName& providerName) const;

    /**
     * @brief Get the default provider for a specific crypto provider type
     *
     * @param cryptoType The functional category
     * @return Shared pointer to the provider for this type, or nullptr if not
     * found
     */
    std::shared_ptr<IProvider> GetProvider(common::CryptoProviderType cryptoType) const;

    /**
     * @brief Set a provider as default for a specific crypto provider type
     *
     * This allows configuring the same provider to serve as the default
     * for different CryptoProviderType categories.
     *
     * @param cryptoType The functional category
     * @param providerId The numeric provider ID to set as default for this type
     * @return true if successful, false if provider ID not found or type mismatch
     */
    bool SetDefaultProviderForType(common::CryptoProviderType cryptoType, common::ProviderId providerId);

    /**
     * @brief Shutdown all registered providers
     */
    void Shutdown();

    /**
     * @brief Register a provider in the factory registry.
     *
     * Called by IProviderFactory implementations during CreateAndRegister().
     * Automatically assigns a numeric ID (0, 1, 2, ...) in registration order.
     *
     * @param providerName Human-readable name for the provider
     * @param provider Shared pointer to the provider instance
     * @param cryptoType Functional category of provider
     * @return true if provider registered successfully, false if name already exists
     */
    bool RegisterProvider(const common::ProviderName& providerName,
                          std::shared_ptr<IProvider> provider,
                          common::CryptoProviderType cryptoType);

    /**
     * @brief Register a provider factory to be invoked during Initialize().
     *
     * Factories are called in registration order inside Initialize(), before
     * provider configuration is applied.  Ownership is transferred to the
     * ProviderManager.
     *
     * @param factory  Concrete factory instance (must be non-null).
     */
    void RegisterFactory(std::unique_ptr<IProviderFactory> factory);

    /**
     * @brief Invoke a callback for each registered provider.
     *
     * @param fn  Callable taking a const common::ProviderName& and a shared_ptr<IProvider>.
     */
    template <typename Fn>
    void ForEachProvider(Fn&& fn) const
    {
        for (const auto& entry : m_providers)
        {
            fn(entry.first, entry.second.instance);
        }
    }

    /**
     * @brief Look up the CryptoProviderType registered for a given provider by name.
     *
     * @param provider_name  The provider's human-readable name.
     * @return The provider's type, or std::nullopt if the name is not registered.
     */
    [[nodiscard]] std::optional<common::CryptoProviderType> GetProviderType(
        const common::ProviderName& provider_name) const;

    /**
     * @brief Check whether a provider's type is compatible with a requested type.
     *
     * Compatibility rules:
     *   DEFAULT   — matches any provider.
     *   HARDWARE  — matches only HARDWARE providers.
     *   SOFTWARE  — matches only SOFTWARE providers.
     *
     * @param provider_name  Registered provider name to check.
     * @param requested_type The caller's type preference.
     * @return true if the provider satisfies the type constraint, false otherwise.
     */
    [[nodiscard]] bool IsProviderCompatibleWithType(const common::ProviderId provider_id,
                                                    common::CryptoProviderType requested_type) const;

  private:
    /**
     * @brief Create a default provider initialization configuration
     *
     * The default configuration:
     * - Enables all available providers
     * - Sets first available provider as default for basic types
     *
     * @return ProviderInitConfig with default settings
     */
    config::ProviderInitConfig CreateDefaultConfig();

    /**
     * @brief Invoke all registered factories to create and register providers.
     *
     * Called once by Initialize().  Each registered IProviderFactory's
     * CreateAndRegister() is called in registration order.
     *
     * @return true if all factory invocations succeeded, false otherwise
     */
    bool CreateProviders();

    /**
     * @brief Initialize all registered providers with ProviderInitContext.
     *
     * Passes each provider a ProviderInitContext containing its assigned
     * numeric ID and name.
     *
     * @return true if all providers initialized successfully, false otherwise
     */
    bool InitializeAll();

    /// Ordered list of factories to invoke during Initialize().
    std::vector<std::unique_ptr<IProviderFactory>> m_factories;

    /// Registry of providers by name: ProviderName -> ProviderEntry
    std::unordered_map<common::ProviderName, ProviderEntry> m_providers;

    /// Vector for lookup by numeric ID: m_provider_by_id[numeric_id] = instance
    std::vector<std::shared_ptr<IProvider>> m_provider_by_id;

    /// Mapping of provider type to numeric provider ID for type-based lookups
    std::unordered_map<common::CryptoProviderType, common::ProviderId> m_typeToProviderId;

    /// Configuration reference
    const score::crypto::daemon::config::Config& m_config;
};

}  // namespace provider
}  // namespace daemon
}  // namespace score::crypto

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_MANAGER_HPP
