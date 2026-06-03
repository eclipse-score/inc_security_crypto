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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_I_PROVIDER_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_I_PROVIDER_FACTORY_HPP

namespace score::crypto::daemon::provider
{

// Forward declaration — avoids a circular include with provider_manager.hpp.
class ProviderManager;

/**
 * @brief Abstract factory interface for creating and registering providers.
 *
 * Each concrete factory encapsulates the construction and registration of one
 * or more related providers into a ProviderManager.  Factories are registered
 * externally (e.g. in daemon main()) via ProviderManager::RegisterFactory()
 * and called once during ProviderManager::Initialize().
 *
 * This decouples ProviderManager from concrete provider types: the manager
 * never includes provider_openssl.hpp or pkcs11_provider.hpp; instead, the
 * daemon bootstrapper wires the desired factories before calling Initialize().
 */
class IProviderFactory
{
  public:
    virtual ~IProviderFactory() = default;

    // Prevent copying; factories are owned via unique_ptr.
    IProviderFactory(const IProviderFactory&) = delete;
    IProviderFactory& operator=(const IProviderFactory&) = delete;
    IProviderFactory(IProviderFactory&&) = delete;
    IProviderFactory& operator=(IProviderFactory&&) = delete;

    /**
     * @brief Create and register provider(s) with the given ProviderManager.
     *
     * The implementation is responsible for constructing provider instances and
     * calling ProviderManager::RegisterProvider() for each one.  If any step
     * fails (module initialisation, provider construction, registration) the
     * method must return false immediately without partially registering.
     *
     * @param manager  The ProviderManager to register providers into.
     * @return true if all providers were created and registered successfully.
     */
    virtual bool CreateAndRegister(ProviderManager& manager) = 0;

  protected:
    IProviderFactory() = default;
};

}  // namespace score::crypto::daemon::provider

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_I_PROVIDER_FACTORY_HPP
