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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_PROVIDER_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_PROVIDER_FACTORY_HPP

#include "score/crypto/daemon/provider/i_provider_factory.hpp"

namespace score::crypto::daemon::provider::score_provider::openssl
{

/**
 * @brief Factory that creates and registers the OpenSSL software provider.
 *
 * Constructs an openssl::OpenSSL instance and registers it under the
 * common::kProviderNameOpenSSL name with CryptoProviderType::SOFTWARE.
 *
 * No configuration fields are required — the OpenSSL provider needs no
 * per-token setup beyond what is compiled in.
 */
class OpenSSLProviderFactory final : public IProviderFactory
{
  public:
    OpenSSLProviderFactory() = default;
    ~OpenSSLProviderFactory() override = default;

    /**
     * @brief Constructs an OpenSSL provider and registers it as SOFTWARE.
     *
     * @param manager  The ProviderManager to register the provider into.
     * @return true if the provider was registered successfully.
     */
    bool CreateAndRegister(ProviderManager& manager) override;
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_PROVIDER_FACTORY_HPP
