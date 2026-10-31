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
namespace
{
using ProviderFactoryCreationResult =
    score::crypto::Expected<std::unique_ptr<IProviderFactory>, common::DaemonErrorCode>;

void CreateAndRegisterProviders(const std::string& factory_name,
                                ProviderFactoryCreationResult& factory_result,
                                ProviderManager& provider_manager)
{
    if (!factory_result.has_value())
    {
        provider_manager.RecordFactoryResult(
            factory_name,
            ProviderFactoryResult{
                0U,
                {ProviderFailure{
                    factory_name, "", ProviderFailureReason::kFactoryCreationFailed, factory_result.error()}}});
        return;
    }
    if (factory_result.value())
    {
        provider_manager.RecordFactoryResult(factory_name, factory_result.value()->CreateAndRegister(provider_manager));
    }
}
}  // namespace

score::crypto::Expected<std::shared_ptr<ProviderManager>, common::DaemonErrorCode> ProviderManagerFactory::Create(
    config::Config& config)
{
    const auto& construction_policy = config.GetProviderConstructionPolicy();
    const auto& routing_policy = config.GetProviderRoutingPolicy();
    if (!config.Validate())
    {
        score::mw::log::LogError() << "[ProviderManagerFactory] Invalid provider policy configuration";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    // Create the provider manager instance
    auto provider_manager = std::make_shared<ProviderManager>(routing_policy);

    // Attempt each backend independently so one unavailable backend does not
    // prevent other providers from being used.
    auto score_factory = CreateScoreProviderFactory(config);
    CreateAndRegisterProviders("ScoreProviderFactory", score_factory, *provider_manager);

    auto pkcs11_factory = CreatePkcs11ProviderFactory(config);
    CreateAndRegisterProviders("Pkcs11ProviderFactory", pkcs11_factory, *provider_manager);

    return FinalizeProviderManager(std::move(provider_manager), construction_policy);
}

score::crypto::Expected<std::shared_ptr<ProviderManager>, common::DaemonErrorCode>
ProviderManagerFactory::FinalizeProviderManager(std::shared_ptr<ProviderManager> provider_manager,
                                                const config::ProviderConstructionPolicy& construction_policy)
{
    bool missing_required_provider = false;
    for (const auto& configured_provider : construction_policy.providers)
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
            missing_required_provider = true;
        }
    }

    // Required-provider semantics belong to the construction policy and are
    // therefore resolved by the factory. ProviderManager remains responsible
    // only for runtime routing and provider lifecycle.
    if (missing_required_provider)
    {
        provider_manager->Shutdown();
        return score::crypto::make_unexpected(common::DaemonErrorCode::kProviderNotAvailable);
    }

    if (!provider_manager->Initialize())
    {
        score::mw::log::LogError() << "[ProviderManagerFactory] Failed to initialize provider manager. Shutting down.";
        auto startup_error = provider_manager->HasRegisteredProviders()
                                 ? common::DaemonErrorCode::kInternalError
                                 : common::DaemonErrorCode::kProviderNotAvailable;
        for (const auto& failure : provider_manager->GetInitializationFailures())
        {
            if (failure.reason == ProviderFailureReason::kDefaultProviderUnavailable)
            {
                startup_error = failure.error;
                if (startup_error == common::DaemonErrorCode::kInvalidArgument)
                {
                    break;
                }
            }
        }
        provider_manager->Shutdown();
        return score::crypto::make_unexpected(startup_error);
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
        if (config.GetProviderConstructionPolicy().IsProviderEnabled(entry.providerName))
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
        if (config.GetProviderConstructionPolicy().IsProviderEnabled(entry.providerName))
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
