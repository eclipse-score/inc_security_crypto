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

#include "score/crypto/backend/score_provider/active_backends_list.hpp"

namespace score::crypto::daemon::provider::score_provider
{

// This function can later  parse the actual configuration file to populate
// the ScoreProviderConfig with entries for each backend.
void ScoreProviderConfig::ParseConfig()
{
    if (!m_providers.empty())
    {
        return;
    }

    auto backends = backend::GetActiveBackends();

    for (auto& b : backends)
    {
        auto creator = b->GetProviderCreator();

        ScoreProviderEntry entry{};
        entry.providerName = creator.backend_name;
        entry.providerImpl = creator.backend_id;
        entry.providerType = creator.provider_type;

        m_providers.push_back(std::move(entry));
    }
}

}  // namespace score::crypto::daemon::provider::score_provider
