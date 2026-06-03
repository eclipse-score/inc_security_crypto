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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_PROVIDER_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_PROVIDER_FACTORY_HPP

#include "score/crypto/daemon/provider/i_provider_factory.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"

#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

/**
 * @brief Factory that creates and registers PKCS#11 token providers.
 *
 * Token configuration is supplied externally via SetTokenConfigs() (the acceptor
 * side of the Pkcs11Config visitor pattern) or the explicit vector constructor.
 * The daemon bootstrapper delegates config setup to Pkcs11Config::Configure():
 *
 * @code
 *   config.GetPkcs11Config().PopulateDefaults();
 *   auto factory = std::make_unique<Pkcs11ProviderFactory>();
 *   config.GetPkcs11Config().Configure(*factory);
 *   manager.RegisterFactory(std::move(factory));
 * @endcode
 *
 * All configured tokens share a single Pkcs11Module so that C_Initialize is
 * called only once for the linked PKCS#11 library, regardless of how many
 * token-bound providers are registered.
 */
class Pkcs11ProviderFactory final : public IProviderFactory
{
  public:
    /// Construct with default (empty) token configuration.
    Pkcs11ProviderFactory() = default;

    /// Construct with externally supplied token configurations.
    ///
    /// Called by Pkcs11Config::Configure() via SetTokenConfigs(), or directly
    /// in tests that need to inject specific PKCS#11 provider configs.
    explicit Pkcs11ProviderFactory(std::vector<Pkcs11ProviderConfig> configs);

    /// @brief Accept a token-config vector pushed by Pkcs11Config::Configure().
    ///
    /// This is the "acceptor" side of the visitor pattern: Pkcs11Config
    /// (the visitor) converts its Pkcs11TokenEntry list to Pkcs11ProviderConfigs
    /// and hands them to the factory via this method.
    void SetTokenConfigs(std::vector<Pkcs11ProviderConfig> configs);

    ~Pkcs11ProviderFactory() override = default;

    /**
     * @brief Initialise a shared Pkcs11Module (C_Initialize called once), then
     *        construct and register one Pkcs11Provider per configured token as
     *        CryptoProviderType::HARDWARE.
     *
     * Returns true if module initialisation and all registrations succeeded.
     * Returns false on the first failure without partial registration.
     * Returns true immediately (no-op) when no token configs were injected.
     *
     * @param manager  The ProviderManager to register providers into.
     * @return true on full success.
     */
    bool CreateAndRegister(ProviderManager& manager) override;

  private:
    /// Token configurations injected at construction (empty = no providers registered).
    std::vector<Pkcs11ProviderConfig> m_injected_configs;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_PROVIDER_FACTORY_HPP
