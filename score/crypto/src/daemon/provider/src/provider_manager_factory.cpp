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

#include "score/crypto/src/daemon/provider/provider_manager_factory.hpp"

#if SCORE_BACKEND_ENABLED
    #include "score/crypto/src/daemon/provider/score_provider/score_provider_factory.hpp"
#endif

#if SCORE_CRYPTO_PKCS11_ENABLED
    #include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider_factory.hpp"
#endif

namespace score::crypto::daemon::provider
{

std::shared_ptr<ProviderManager> ProviderManagerFactory::Create(config::Config& config)
{
    // Create the provider manager instance
    auto provider_manager = std::make_shared<ProviderManager>(config);

    // Create and register Score provider factory if backends enabled
    auto score_factory = CreateScoreProviderFactory(config);
    if (score_factory)
    {
        provider_manager->RegisterFactory(std::move(score_factory));
    }

    // Create and register PKCS#11 factory if configured
    auto pkcs11_factory = CreatePkcs11ProviderFactory(config);
    if (pkcs11_factory)
    {
        provider_manager->RegisterFactory(std::move(pkcs11_factory));
    }

    // Initialize all registered providers
    provider_manager->Initialize();

    return provider_manager;
}

std::unique_ptr<IProviderFactory> ProviderManagerFactory::CreateScoreProviderFactory(
    config::Config& config)
{
#if SCORE_BACKEND_ENABLED
    config.GetScoreProviderConfig().ParseConfig();
    if (config.GetScoreProviderConfig().GetProviderEntries().empty())
    {
        return nullptr;
    }

    auto score_factory = std::make_unique<score_provider::ScoreProviderFactory>();
    config.GetScoreProviderConfig().Configure(*score_factory);
    return score_factory;
#else
    (void)config;
    return nullptr;
#endif
}

std::unique_ptr<IProviderFactory> ProviderManagerFactory::CreatePkcs11ProviderFactory(
    config::Config& config)
{
#if SCORE_CRYPTO_PKCS11_ENABLED
    // Parse PKCS#11 configuration
    config.GetPkcs11Config().ParseConfig();

    // Check if PKCS#11 is configured
    if (config.GetPkcs11Config().GetTokenEntries().empty())
    {
        // PKCS#11 not configured or disabled
        return nullptr;
    }

    // Create and configure PKCS#11 factory
    auto factory = std::make_unique<pkcs11::Pkcs11ProviderFactory>();
    config.GetPkcs11Config().Configure(*factory);

    return factory;
#else
    // PKCS#11 backend not enabled in build
    (void)config;  // Suppress unused parameter warning
    return nullptr;
#endif
}

}  // namespace score::crypto::daemon::provider
