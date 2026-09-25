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

#include "score/crypto/src/daemon/provider/score_provider/iav_primula/iav_primula_provider.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/factory/iav_primula_handler_factory.hpp"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

bool IavPrimulaProvider::InitialiseBackend(const ProviderInitContext& ctx)
{
    const bool initialized = true;
    if (initialized)
    {
        m_factory = std::make_shared<IavPrimulaKeyFactory>(ctx.numeric_id);
    }
    return initialized;
}

void IavPrimulaProvider::Shutdown()
{
    if (!IsInitialized())
    {
        return;
    }

    m_factory.reset();
    m_keyManagementService.reset();

    // TODO implement cleanup of the Primula handler ressources on shutdown if required

    // Base class resets factory and flags.
    ScoreProvider::Shutdown();
}

std::shared_ptr<key_management::IKeyFactory> IavPrimulaProvider::GetKeyFactory()
{
    return m_factory;
}

std::shared_ptr<key_management::IKeySlotHandler> IavPrimulaProvider::GetKeySlotHandler(
    const key_management::KeySlotConfig& config)
{
    // TODO: return Primula-specific key slot handler if supported.
    return ScoreProvider::GetKeySlotHandler(config);
}

void IavPrimulaProvider::SetKeyManagementService(std::shared_ptr<key_management::KeyManagementService> service)
{
    m_keyManagementService = std::move(service);
}

/// @brief Create the IAV-Primula-specific handler factory.
///
/// The provider exposes only the generic handler-factory interface to the
/// daemon. PQC implementation details remain below that boundary.
std::shared_ptr<handler::ICryptoHandlerFactory> IavPrimulaProvider::CreateHandlerFactory()
{
    return std::make_shared<IavPrimulaHandlerFactory>(m_factory,
                                                      nullptr,  // TODO This needs to be a key slot handler for primula
                                                      m_keyManagementService);
}

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula
