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

#include "score/crypto/src/daemon/provider/score_provider/score_provider_factory.hpp"

#include "score/crypto/src/backend/score_provider/active_backends_list.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/mw/log/logging.h"

namespace score::crypto::daemon::provider::score_provider
{

ScoreProviderFactory::ScoreProviderFactory(ScoreProviderFactoryConfig config) : m_config{std::move(config)} {}

ProviderFactoryResult ScoreProviderFactory::CreateAndRegister(ProviderManager& manager)
{
    ProviderFactoryResult result;

    // Get active backends to resolve providerImpl -> factory creator
    auto backends = score::crypto::backend::score_provider::GetActiveBackends();

    for (const auto& entry : m_config.providers)
    {
        // Find backend adapter for this provider implementation
        auto backend_it = std::find_if(backends.begin(), backends.end(), [&entry](const auto& backend) {
            return backend->GetProviderCreator().backend_id == entry.providerImpl;
        });

        if (backend_it == backends.end())
        {
            score::mw::log::LogError() << "[ScoreProviderFactory] Unknown provider implementation: "
                                       << entry.providerImpl;
            result.failures.push_back(ProviderFailure{"ScoreProviderFactory",
                                                      entry.providerName,
                                                      ProviderFailureReason::kProviderUnavailable,
                                                      common::DaemonErrorCode::kProviderNotAvailable});
            continue;
        }

        // Construct the provider via the backend's creator; register with config-driven name and type
        auto creator = (*backend_it)->GetProviderCreator();
        auto provider = creator.create_provider();
        auto type = common::CryptoProviderTypeFromString(entry.providerType);

        if (!manager.RegisterProvider(entry.providerName, std::move(provider), type))
        {
            score::mw::log::LogError() << "[ScoreProviderFactory] Failed to register provider: " << entry.providerName;
            result.failures.push_back(ProviderFailure{"ScoreProviderFactory",
                                                      entry.providerName,
                                                      ProviderFailureReason::kProviderRegistrationFailed,
                                                      common::DaemonErrorCode::kInternalError});
        }
        else
        {
            ++result.registeredCount;
        }
    }

    return result;
}

}  // namespace score::crypto::daemon::provider::score_provider
