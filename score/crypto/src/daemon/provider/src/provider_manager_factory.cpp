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
#include "score/mw/log/logging.h"

#if SCORE_CRYPTO_SCORE_BACKEND_ENABLED
#include "score/crypto/src/daemon/provider/score_provider/score_provider_factory.hpp"
#endif

#if SCORE_CRYPTO_PKCS11_BACKEND_ENABLED
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider_factory.hpp"
#endif

namespace score::crypto::daemon::provider
{

bool ProviderManagerFactory::IsProviderAllowed(const std::string& provider_name,
                                               const config::ProviderInitConfig& provider_config)
{
    if (provider_config.providers.empty())
    {
        return true;
    }

    for (const auto& configured_provider : provider_config.providers)
    {
        if (configured_provider.providerName == provider_name)
        {
            return configured_provider.enabled;
        }
    }
    return false;
}

score::crypto::Expected<std::shared_ptr<ProviderManager>, common::DaemonErrorCode> ProviderManagerFactory::Create(
    config::Config& config)
{
    // Create the provider manager instance
    auto provider_manager = std::make_shared<ProviderManager>(config.GetProviderInitConfig());

    // Attempt each backend independently so one unavailable backend does not
    // prevent other providers from being used.
    auto score_factory = CreateScoreProviderFactory(config);
    if (!score_factory.has_value())
    {
        provider_manager->RecordFactoryResult(
            "ScoreProviderFactory",
            ProviderFactoryResult{0U,
                                  {ProviderFailure{"ScoreProviderFactory",
                                                   "",
                                                   ProviderFailureReason::kFactoryCreationFailed,
                                                   score_factory.error()}}});
    }
    else if (score_factory.value())
    {
        provider_manager->RecordFactoryResult("ScoreProviderFactory",
                                              (*score_factory)->CreateAndRegister(*provider_manager));
    }

    auto pkcs11_factory = CreatePkcs11ProviderFactory(config);
    if (!pkcs11_factory.has_value())
    {
        provider_manager->RecordFactoryResult(
            "Pkcs11ProviderFactory",
            ProviderFactoryResult{0U,
                                  {ProviderFailure{"Pkcs11ProviderFactory",
                                                   "",
                                                   ProviderFailureReason::kFactoryCreationFailed,
                                                   pkcs11_factory.error()}}});
    }
    else if (pkcs11_factory.value())
    {
        provider_manager->RecordFactoryResult("Pkcs11ProviderFactory",
                                              (*pkcs11_factory)->CreateAndRegister(*provider_manager));
    }

    for (const auto& configured_provider : config.GetProviderInitConfig().providers)
    {
        if (configured_provider.enabled && configured_provider.required &&
            !provider_manager->IsProviderRegistered(configured_provider.providerName))
        {
            score::mw::log::LogError() << "[ProviderManagerFactory] Required provider was not registered: "
                                       << configured_provider.providerName;
            provider_manager->RecordFactoryResult(
                "ProviderManagerFactory",
                ProviderFactoryResult{0U,
                                      {ProviderFailure{"ProviderManagerFactory",
                                                       configured_provider.providerName,
                                                       ProviderFailureReason::kRequiredProviderUnavailable,
                                                       common::DaemonErrorCode::kProviderNotAvailable}}});
        }
    }

    if (!provider_manager->Initialize())
    {
        score::mw::log::LogError() << "[ProviderManagerFactory] Failed to initialize provider manager. Shutting down.";
        provider_manager->Shutdown();
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInternalError);
    }

    return provider_manager;
}

score::crypto::Expected<std::unique_ptr<IProviderFactory>, common::DaemonErrorCode>
ProviderManagerFactory::CreateScoreProviderFactory(config::Config& config)
{
#if SCORE_CRYPTO_SCORE_BACKEND_ENABLED
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

    score_provider::ScoreProviderFactoryConfig filtered_config;
    for (const auto& entry : provider_config.GetConfig().providers)
    {
        if (ProviderManagerFactory::IsProviderAllowed(entry.providerName, config.GetProviderInitConfig()))
        {
            filtered_config.providers.push_back(entry);
        }
    }
    if (filtered_config.providers.empty())
    {
        return std::unique_ptr<IProviderFactory>{};
    }

    return std::make_unique<score_provider::ScoreProviderFactory>(std::move(filtered_config));
#else
    (void)config;
    return std::unique_ptr<IProviderFactory>{};
#endif
}

score::crypto::Expected<std::unique_ptr<IProviderFactory>, common::DaemonErrorCode>
ProviderManagerFactory::CreatePkcs11ProviderFactory(config::Config& config)
{
#if SCORE_CRYPTO_PKCS11_BACKEND_ENABLED
    // Parse PKCS#11 configuration
    auto& pkcs11_config = config.GetPkcs11Config();
    auto parse_result = pkcs11_config.ParseConfig(config);
    if (!parse_result.has_value())
    {
        return score::crypto::make_unexpected(parse_result.error());
    }

    pkcs11::Pkcs11ProviderFactoryConfig filtered_config;
    for (const auto& entry : pkcs11_config.GetConfig().tokens)
    {
        if (ProviderManagerFactory::IsProviderAllowed(entry.providerName, config.GetProviderInitConfig()))
        {
            filtered_config.tokens.push_back(entry);
        }
    }
    if (filtered_config.tokens.empty())
    {
        return std::unique_ptr<IProviderFactory>{};
    }

    return std::make_unique<pkcs11::Pkcs11ProviderFactory>(std::move(filtered_config));
#else
    // PKCS#11 backend not enabled in build
    (void)config;  // Suppress unused parameter warning
    return std::unique_ptr<IProviderFactory>{};
#endif
}

}  // namespace score::crypto::daemon::provider
