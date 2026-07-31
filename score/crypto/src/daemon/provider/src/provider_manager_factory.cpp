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

score::crypto::Expected<std::shared_ptr<ProviderManager>, common::DaemonErrorCode> ProviderManagerFactory::Create(
    config::Config& config)
{
    // Create the provider manager instance
    auto provider_manager = std::make_shared<ProviderManager>(config);

    // Create and register Score provider factory if backends enabled
    auto score_factory = CreateScoreProviderFactory(config);
    if (!score_factory.has_value())
    {
        return score::crypto::make_unexpected(score_factory.error());
    }
    if (score_factory.value())
    {
        provider_manager->RegisterFactory(std::move(*score_factory));
    }

    // Create and register PKCS#11 factory if configured
    auto pkcs11_factory = CreatePkcs11ProviderFactory(config);
    if (!pkcs11_factory.has_value())
    {
        return score::crypto::make_unexpected(pkcs11_factory.error());
    }
    if (pkcs11_factory.value())
    {
        provider_manager->RegisterFactory(std::move(*pkcs11_factory));
    }

    // Initialize all registered providers. Ignore failures here;
    // Individual provider failures are logged and hidden from lookups.
    if (!provider_manager->Initialize())
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInternalError);
    }

    return provider_manager;
}

score::crypto::Expected<std::unique_ptr<IProviderFactory>, common::DaemonErrorCode>
ProviderManagerFactory::CreateScoreProviderFactory(config::Config& config)
{
#if SCORE_BACKEND_ENABLED
    auto& provider_config = config.GetScoreProviderConfig();
    auto parse_result = provider_config.ParseConfig(config);
    if (!parse_result.has_value())
    {
        return score::crypto::make_unexpected(parse_result.error());
    }
    if (provider_config.GetConfig().providers.empty())
    {
        return std::unique_ptr<IProviderFactory>{};
    }

    return std::make_unique<score_provider::ScoreProviderFactory>(provider_config.GetConfig());
#else
    (void)config;
    return std::unique_ptr<IProviderFactory>{};
#endif
}

score::crypto::Expected<std::unique_ptr<IProviderFactory>, common::DaemonErrorCode>
ProviderManagerFactory::CreatePkcs11ProviderFactory(config::Config& config)
{
#if SCORE_CRYPTO_PKCS11_ENABLED
    // Parse PKCS#11 configuration
    auto& pkcs11_config = config.GetPkcs11Config();
    auto parse_result = pkcs11_config.ParseConfig(config);
    if (!parse_result.has_value())
    {
        return score::crypto::make_unexpected(parse_result.error());
    }

    // Check if PKCS#11 is configured
    if (pkcs11_config.GetConfig().tokens.empty())
    {
        // PKCS#11 not configured or disabled
        return std::unique_ptr<IProviderFactory>{};
    }

    // Create and configure PKCS#11 factory
    return std::make_unique<pkcs11::Pkcs11ProviderFactory>(pkcs11_config.GetConfig());
#else
    // PKCS#11 backend not enabled in build
    (void)config;  // Suppress unused parameter warning
    return std::unique_ptr<IProviderFactory>{};
#endif
}

}  // namespace score::crypto::daemon::provider
