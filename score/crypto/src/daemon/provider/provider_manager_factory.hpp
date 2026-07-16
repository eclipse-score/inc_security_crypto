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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_MANAGER_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_MANAGER_FACTORY_HPP

#include <memory>

#include "provider_manager.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"

namespace score::crypto::daemon::provider
{

/**
 * @brief Factory for creating and initializing ProviderManager instances
 *
 * This factory encapsulates the complete setup of a ProviderManager:
 * 1. Discover active backends from compile-time list (backend/BUILD)
 * 2. Parse provider configurations
 * 3. Create provider factories for enabled backends
 * 4. Register factories with the provider manager
 * 5. Initialize all providers
 *
 * Backend discovery uses dependency injection:
 * - Score backends: Compile-time list from backend/active_backends_list.hpp
 * - PKCS#11 backend: Conditionally created based on configuration
 *
 * Usage:
 * @code
 *   Config config;
 *   config.ParseConfig();
 *   auto provider_manager = ProviderManagerFactory::Create(config);
 * @endcode
 */
class ProviderManagerFactory
{
  public:
    /**
     * @brief Create and initialize a fully configured ProviderManager
     *
     * This method:
     * - Discovers active score backends (compile-time)
     * - Invokes ParseConfig() on each provider-specific config section
     * - Creates and configures provider factories
     * - Registers factories with the provider manager
     * - Calls Initialize() on the provider manager
     *
     * @param config The daemon configuration containing provider settings
     * @return Shared pointer to initialized ProviderManager
     * @throws std::runtime_error if initialization fails
     */
    static std::shared_ptr<ProviderManager> Create(config::Config& config);

  private:
    ProviderManagerFactory() = delete;

    /**
     * @brief Create score provider factory if backends enabled
     *
     * Discovers active backends from backend/active_backends_list.hpp
     * (controlled by backend/BUILD). Creates a single ScoreProviderFactory
     * that handles all enabled score backends (OpenSSL, Primula, etc.).
     *
     * @param config Configuration containing score provider settings
     * @return unique_ptr to ScoreProviderFactory if score backends enabled,
     *         nullptr if ENABLE_SCORE_BACKEND = False
     */
    static std::unique_ptr<IProviderFactory> CreateScoreProviderFactory(config::Config& config);

    /**
     * @brief Create PKCS#11 provider factory if configured
     *
     * Checks PKCS#11 configuration and creates factory only if
     * PKCS#11 providers are configured in the config.
     *
     * @param config Configuration containing PKCS#11 settings
     * @return unique_ptr to Pkcs11ProviderFactory if configured,
     *         nullptr if PKCS#11 disabled or not configured
     */
    static std::unique_ptr<IProviderFactory> CreatePkcs11ProviderFactory(config::Config& config);
};

}  // namespace score::crypto::daemon::provider

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_MANAGER_FACTORY_HPP
