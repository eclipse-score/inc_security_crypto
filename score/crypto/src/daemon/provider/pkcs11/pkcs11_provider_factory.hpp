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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_PKCS11_PROVIDER_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_PKCS11_PROVIDER_FACTORY_HPP

#include "score/crypto/src/daemon/provider/i_provider_factory.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_token_config.hpp"

#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

/**
 * @brief Factory that creates and registers PKCS#11 token providers.
 *
 * Token configuration is supplied as one complete Pkcs11ProviderFactoryConfig
 * snapshot. This prevents partially configured or order-dependent factories
 * when additional factory-wide options are added.
 *
 * @code
 *   Pkcs11ProviderFactoryConfig factory_config{token_entries};
 *   auto factory = std::make_unique<Pkcs11ProviderFactory>(std::move(factory_config));
 *   manager.RegisterFactory(std::move(factory));
 * @endcode
 *
 * The factory accepts plain-data Pkcs11TokenEntry objects and converts them to
 * the internal Pkcs11ProviderConfig type in the implementation file.  This keeps
 * pkcs11.h (and CK_* types) out of this header so that provider_manager_factory
 * does not transitively depend on the PKCS#11 C API.
 *
 * All configured tokens share a single Pkcs11Module so that C_Initialize is
 * called only once for the linked PKCS#11 library, regardless of how many
 * token-bound providers are registered.
 */
class Pkcs11ProviderFactory final : public IProviderFactory
{
  public:
    explicit Pkcs11ProviderFactory(Pkcs11ProviderFactoryConfig config);

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
    Pkcs11ProviderFactoryConfig m_config;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_PKCS11_PROVIDER_FACTORY_HPP
