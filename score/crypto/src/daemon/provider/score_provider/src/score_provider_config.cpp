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

#include "score/crypto/daemon/provider/score_provider/score_provider_config.hpp"

#include "score/crypto/daemon/provider/score_provider/score_provider_factory.hpp"

namespace score::crypto::daemon::provider::score_provider
{

void ScoreProviderConfig::PopulateDefaults()
{
    if (!m_providers.empty())
    {
        return;  // Entries already present (from config file or test fixture).
    }
    ScoreProviderEntry openssl{};
    openssl.providerName = "OPENSSL";
    openssl.providerImpl = "openssl";
    m_providers.push_back(std::move(openssl));
}

void ScoreProviderConfig::Configure(ScoreProviderFactory& factory) const
{
    factory.SetConfigs(m_providers);
}

}  // namespace score::crypto::daemon::provider::score_provider
