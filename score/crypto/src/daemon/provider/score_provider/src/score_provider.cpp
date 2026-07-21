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

#include "score/crypto/daemon/provider/score_provider/score_provider.hpp"

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::provider::score_provider
{

bool ScoreProvider::Initialize(const ProviderInitContext& ctx)
{
    if (m_initialized)
    {
        return true;
    }

    m_numeric_id = ctx.numeric_id;
    m_provider_name = ctx.name;
    m_initialized = true;

    score::mw::log::LogDebug() << "[ScoreProvider] Initialized (ID:" << m_numeric_id << ", Name:" << m_provider_name
                               << ")";
    return true;
}

void ScoreProvider::Shutdown()
{
    if (!m_initialized)
    {
        return;
    }
    m_handler_factory.reset();
    m_initialized = false;
}

common::ProviderId ScoreProvider::GetProviderId() const
{
    return m_numeric_id;
}

const common::ProviderName& ScoreProvider::GetProviderName() const
{
    return m_provider_name;
}

std::shared_ptr<handler::ICryptoHandlerFactory> ScoreProvider::GetCryptoHandlerFactory()
{
    if (!m_handler_factory)
    {
        m_handler_factory = CreateHandlerFactory();
    }
    return m_handler_factory;
}

}  // namespace score::crypto::daemon::provider::score_provider
