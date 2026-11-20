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

#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/pqc_provider.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/factory/pqc_provider_handler_factory.hpp"

namespace score::crypto::daemon::provider::score_provider::pqc_provider
{

bool PqcProvider::InitialiseBackend(const ProviderInitContext& ctx)
{
    const bool initialized = true;
    if (initialized)
    {
        m_factory = std::make_shared<PqcProviderKeyFactory>(ctx.numeric_id);
    }
    return initialized;
}

void PqcProvider::Shutdown()
{
    if (!IsInitialized())
    {
        return;
    }

    m_factory.reset();
    m_keyManagementService.reset();

    // TODO implement cleanup of the PqcProvider handler ressources on shutdown if required

    // Base class resets factory and flags.
    ScoreProvider::Shutdown();
}

std::shared_ptr<key_management::IKeyFactory> PqcProvider::GetKeyFactory()
{
    return m_factory;
}

std::shared_ptr<key_management::IKeySlotHandler> PqcProvider::GetKeySlotHandler(
    const key_management::KeySlotConfig& config)
{
    // TODO: return PqcProvider-specific key slot handler if supported.
    return ScoreProvider::GetKeySlotHandler(config);
}

void PqcProvider::SetKeyManagementService(std::shared_ptr<key_management::KeyManagementService> service)
{
    m_keyManagementService = std::move(service);
}

/// @brief Create the PQC Provider-specific handler factory.
///
/// The provider exposes only the generic handler-factory interface to the
/// daemon. PQC implementation details remain below that boundary.
std::shared_ptr<handler::ICryptoHandlerFactory> PqcProvider::CreateHandlerFactory()
{
    return std::make_shared<PqcProviderHandlerFactory>(m_factory,
                                                      nullptr,  // PqcProvider slot operations are currently unsupported.
                                                      m_keyManagementService);
}

}  // namespace score::crypto::daemon::provider::score_provider::pqc_provider
