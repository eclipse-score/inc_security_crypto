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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_MANAGER_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_MANAGER_FACTORY_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <memory>

#include "provider_manager.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"

#include <string>

namespace score::crypto::daemon::provider
{

/**
 * @brief Factory for creating and initializing ProviderManager instances
 *
 * This factory encapsulates the complete setup of a ProviderManager:
 * 1. Parse provider-specific configuration sections
 * 2. Create provider factories for build-time enabled backends
 * 3. Invoke CreateAndRegister on each factory to register providers
 * 4. Call Initialize() on the manager to resolve type mappings and finalize setup
 *
 * Backend availability is determined at build time via compile-time flags:
 * - Score backend: enabled when SCORE_BACKEND_ENABLED is set
 * - PKCS#11 backend: enabled when SCORE_CRYPTO_PKCS11_ENABLED is set
 *
 * Usage:
 * @code
 *   Config config;
 *   config.ParseConfig();
 *   auto provider_manager = ProviderManagerFactory::Create(config);
 *   if (!provider_manager.has_value()) {
 *       // Handle provider configuration or initialization failure.
 *   }
 * @endcode
 */
class ProviderManagerFactory
{
  public:
    /**
     * @brief Create and initialize a fully configured ProviderManager
     *
     * @param config The daemon configuration containing provider settings
     * @return Expected containing the initialized ProviderManager, or a daemon
     *         error code if provider configuration or initialization fails
     */
    [[nodiscard]] static score::crypto::Expected<std::shared_ptr<ProviderManager>, common::DaemonErrorCode> Create(
        config::Config& config);

  private:
    ProviderManagerFactory() = delete;

    [[nodiscard]] static bool IsProviderAllowed(const std::string& provider_name,
                                                const config::ProviderInitConfig& provider_config);

    [[nodiscard]] static score::crypto::Expected<std::unique_ptr<IProviderFactory>, common::DaemonErrorCode>
    CreateScoreProviderFactory(config::Config& config);

    [[nodiscard]] static score::crypto::Expected<std::unique_ptr<IProviderFactory>, common::DaemonErrorCode>
    CreatePkcs11ProviderFactory(config::Config& config);
};

}  // namespace score::crypto::daemon::provider

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_MANAGER_FACTORY_HPP
