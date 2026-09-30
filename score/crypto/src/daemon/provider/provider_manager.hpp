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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_MANAGER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_MANAGER_HPP

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "i_provider.hpp"
#include "i_provider_factory.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"

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
 * This class manages provider registration, availability, and lifecycle.
 * Providers receive a stable ID at registration; initialization is attempted
 * at startup and retried under synchronization when a request needs a provider.
 *
 * To add new providers:
 * 1. Register providers through RegisterProvider().
 * 2. Add provider instantiation logic to the relevant backend factory.
 * 3. Call RegisterProvider() through the factory bootstrap path.
 *
 * Usage Pattern:
 * In daemon main:
 *   ProviderManager manager;
 *   ProviderInitConfig config;
 *   config.SetDefaultProviderForType(CryptoProviderType::SOFTWARE, "OPENSSL");
 *   ProviderManager manager(config);
 *   manager.Initialize();
 *   auto provider = manager.GetProvider("OPENSSL");
 */
class ProviderManager
{
  public:
    using Sptr = std::shared_ptr<ProviderManager>;
    /**
     * @brief Constructor
     */
    explicit ProviderManager(config::ProviderInitConfig provider_config);

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
     * @brief Make the initial initialization attempt and build type mappings
     *
     * Individual provider failures are retained and can be retried when a
     * provider lookup occurs. If the provider policy is empty, registered
     * providers are eligible and defaults are selected by preference.
     *
     * This is the only method the daemon needs to call during startup.
     * Provider instantiation logic is in the implementation file.
     *
     * @return true if registration and type mapping setup succeeded, false if
     * the manager cannot provide a usable registry or a required mapping failed
     */
    bool Initialize();

    /**
     * @brief Get the startup failures recorded for provider factories and providers.
     */
    [[nodiscard]] const std::vector<ProviderFailure>& GetInitializationFailures() const noexcept
    {
        return m_initializationFailures;
    }

    /**
     * @brief Record the result of a provider factory invocation.
     */
    void RecordFactoryResult(const std::string& factoryName, ProviderFactoryResult result);

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
     * @brief Select the preferred initialized provider that offers a capability.
     *
     * Filters registered providers to those that are initialized and advertise
     * @p capability (via IProvider::GetProviderCapabilities()), then chooses
     * among them using the per-capability default preference order defined in
     * ProviderManager. Falls back to the lowest-id capable provider when no
     * preferred-category provider is found.
     *
     * Per-capability defaults: kCertManagement → SOFTWARE first (parsing/verification
     * are inherently software); kKeyManagement and kCrypto → HARDWARE first.
     *
     * @param capability  The functional capability the provider must offer.
     * @return The selected provider, or nullptr if none offers the capability.
     */
    [[nodiscard]] std::shared_ptr<IProvider> GetProviderForCapability(common::ProviderCapability capability) const;

    /**
     * @brief Select the preferred initialized provider with an explicit category order.
     *
     * Same as GetProviderForCapability(capability) but lets the caller override
     * the preference order. Use this overload only when testing ordering behavior
     * or when a specific call site needs a non-default preference.
     *
     * @param capability      The functional capability the provider must offer.
     * @param preferenceOrder Category priority among capable providers.
     * @return The selected provider, or nullptr if none offers the capability.
     */
    [[nodiscard]] std::shared_ptr<IProvider> GetProviderForCapability(
        common::ProviderCapability capability,
        const std::vector<common::CryptoProviderType>& preferenceOrder) const;

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
     * @return true if provider registered successfully, false if name already exists or provider is null
     */
    bool RegisterProvider(const common::ProviderName& providerName,
                          std::shared_ptr<IProvider> provider,
                          common::CryptoProviderType cryptoType);

    /**
     * @brief Check whether a provider has been registered.
     *
     * Registration is independent from provider initialization. A registered
     * provider may be temporarily unavailable and retried by the manager later.
     *
     * @param provider_name The provider's human-readable name.
     * @return true if the provider is present in the registry.
     */
    [[nodiscard]] bool IsProviderRegistered(const common::ProviderName& provider_name) const;

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
    [[nodiscard]] bool EnsureProviderInitialized(ProviderEntry& entry) const;

    /**
     * @brief Resolve the name of the default provider by preference order.
     *
     * Scans registered providers and returns the name of the first one whose
     * cryptoType matches an entry in preferenceOrder. Falls back to the first
     * registered provider if no preferred type is found. Returns an empty
     * string when no providers are registered.
     *
     * @param preferenceOrder Priority order for selecting default provider.
     *        Defaults to HARDWARE → SOFTWARE fallback.
     * @return Name of the selected default provider, or empty if none available.
     */
    common::ProviderName ResolveDefaultProviderName(const std::vector<common::CryptoProviderType>& preferenceOrder = {
                                                        common::CryptoProviderType::HARDWARE,
                                                        common::CryptoProviderType::SOFTWARE});

    /**
     * @brief Build m_typeToProviderId from configured type-to-name mappings.
     *
     * Resolves provider names to the numeric IDs assigned at registration
     * time. Warnings are logged for names that reference unknown or
     * disabled providers.
     *
     * @param type_to_name Mapping from crypto provider type to provider name.
     */
    [[nodiscard]] bool BuildTypeMappings(
        const std::unordered_map<common::CryptoProviderType, common::ProviderName>& type_to_name);

    /**
     * @brief Initialize all registered providers with ProviderInitContext.
     *
     * Passes each provider a ProviderInitContext containing its assigned
     * numeric ID and name. Failed providers remain registered but are hidden
     * from lookups because GetProvider() queries provider->IsInitialized().
     *
     * @return true if at least one provider initialized, false if all current
     * initialization attempts failed
     */
    bool InitializeAll();

    /**
     * @brief Check whether a provider has been successfully initialized.
     *
     * @param provider_id The provider's numeric ID.
     * @return true if the provider has been successfully initialized, false otherwise.
     */
    [[nodiscard]] bool IsProviderInitialized(common::ProviderId provider_id) const;

    /// Registry of providers by name: ProviderName -> ProviderEntry
    std::unordered_map<common::ProviderName, ProviderEntry> m_providers;

    /// Vector for lookup by numeric ID: m_provider_by_id[numeric_id] = instance
    std::vector<std::shared_ptr<IProvider>> m_provider_by_id;

    /// Parallel name lookup: m_name_by_id[numeric_id] = providerName (set at registration, never depends on
    /// Initialize())
    std::vector<common::ProviderName> m_name_by_id;

    /// Mapping of provider type to numeric provider ID for type-based lookups
    std::unordered_map<common::CryptoProviderType, common::ProviderId> m_typeToProviderId;

    /// Provider activation and default-mapping policy snapshot.
    config::ProviderInitConfig m_providerConfig;

    /// Failures encountered while selecting, creating, registering, or initializing providers.
    mutable std::vector<ProviderFailure> m_initializationFailures;

    /// Serializes provider initialization and availability checks.
    mutable std::mutex m_providerMutex;

    /// Whether a required provider or explicit default mapping could not be satisfied.
    bool m_hasFatalInitializationFailure{false};
};

}  // namespace provider
}  // namespace daemon
}  // namespace score::crypto

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PROVIDER_MANAGER_HPP
