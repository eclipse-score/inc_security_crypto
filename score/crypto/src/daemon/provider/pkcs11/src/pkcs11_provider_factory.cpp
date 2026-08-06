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

#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider_factory.hpp"

#include <memory>

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

namespace score::crypto::daemon::provider::pkcs11
{

Pkcs11ProviderFactory::Pkcs11ProviderFactory(Pkcs11ProviderFactoryConfig config) : m_config{std::move(config)} {}

ProviderFactoryResult Pkcs11ProviderFactory::CreateAndRegister(ProviderManager& manager)
{
    ProviderFactoryResult result;
    if (m_config.tokens.empty())
    {
        return result;
    }

    // Convert plain-data entries to internal PKCS#11 configs here, rather than
    // in the header, so callers (including provider_manager_factory) never see
    // pkcs11.h types.
    auto convertTokenEntry = [](const Pkcs11TokenEntry& entry) {
        Pkcs11ProviderConfig cfg{};
        cfg.tokenLabel = entry.tokenLabel;
        cfg.tokenModel = entry.tokenModel;
        cfg.userPin = entry.userPin;
        cfg.providerName = entry.providerName;
        cfg.providerType = entry.providerType;
        cfg.cleanupStrategy = entry.useHardCleanup ? Pkcs11SessionCleanupStrategy::kHardCleanup
                                                   : Pkcs11SessionCleanupStrategy::kSoftCleanup;
        return cfg;
    };

    std::vector<Pkcs11ProviderConfig> provider_configs;
    provider_configs.reserve(m_config.tokens.size());
    for (const auto& entry : m_config.tokens)
    {
        provider_configs.push_back(convertTokenEntry(entry));
    }

    // All tokens on the same linked library MUST share a single Pkcs11Module
    // so that C_Initialize is called exactly once and C_Finalize is deferred
    // until the very last provider (and therefore all its sessions) is destroyed.
    auto pkcs11Module = std::make_shared<Pkcs11Module>();
    const auto initResult = pkcs11Module->Init();
    if (!initResult.has_value())
    {
        result.failures.push_back(ProviderFailure{
            "Pkcs11ProviderFactory", "", ProviderFailureReason::kFactoryCreationFailed, initResult.error()});
        return result;
    }

    for (const auto& config : provider_configs)
    {
        auto provider = std::make_shared<Pkcs11Provider>(config, pkcs11Module);
        if (!manager.RegisterProvider(
                config.providerName, provider, common::CryptoProviderTypeFromString(config.providerType)))
        {
            result.failures.push_back(ProviderFailure{"Pkcs11ProviderFactory",
                                                      config.providerName,
                                                      ProviderFailureReason::kProviderRegistrationFailed,
                                                      common::DaemonErrorCode::kInternalError});
            continue;
        }
        ++result.registeredCount;
    }

    return result;
}

}  // namespace score::crypto::daemon::provider::pkcs11
