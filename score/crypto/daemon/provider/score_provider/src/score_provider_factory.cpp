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

#include "score/crypto/daemon/provider/score_provider/score_provider_factory.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/openssl_provider_factory.hpp"

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::provider::score_provider
{

ScoreProviderFactory::ScoreProviderFactory(std::vector<ScoreProviderEntry> configs) : m_configs{std::move(configs)} {}

void ScoreProviderFactory::SetConfigs(std::vector<ScoreProviderEntry> configs)
{
    m_configs = std::move(configs);
}

bool ScoreProviderFactory::CreateAndRegister(ProviderManager& manager)
{
    bool all_ok = true;
    for (const auto& entry : m_configs)
    {
        if (entry.providerImpl == "openssl")
        {
            openssl::OpenSSLProviderFactory openssl_factory;
            if (!openssl_factory.CreateAndRegister(manager))
            {
                score::mw::log::LogError()
                    << "[ScoreProviderFactory] Failed to create OpenSSL provider:" << entry.providerName;
                all_ok = false;
            }
        }
        else
        {
            score::mw::log::LogError() << "[ScoreProviderFactory] Unknown provider implementation: "
                                       << entry.providerImpl;
            all_ok = false;
        }
    }
    return all_ok;
}

}  // namespace score::crypto::daemon::provider::score_provider
