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

#include "score/crypto/daemon/control_plane/basic_handler_chain_factory.hpp"
#include "score/crypto/daemon/config/inc/config.hpp"
#include "score/crypto/daemon/control_plane/i_handler_chain_factory.hpp"
#include "score/crypto/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/daemon/control_plane/src/connection_handler.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/daemon/mediator/src/mediator_impl.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"

#include <memory>
#include <utility>

namespace score::crypto::daemon::control_plane
{

BasicHandlerChainFactory::BasicHandlerChainFactory(std::shared_ptr<data_manager::IDataManager> data_manager,
                                                   std::shared_ptr<provider::ProviderManager> provider_manager,
                                                   const config::Config& config,
                                                   key_management::KeyManagementService::Sptr km_service)
    : IHandlerChainFactory(),
      m_data_manager(std::move(data_manager)),
      m_provider_manager(std::move(provider_manager)),
      m_config(config),
      m_km_service(std::move(km_service))
{
}

std::unique_ptr<IRequestHandler> BasicHandlerChainFactory::CreateRequestHandler()
{
    // whole chain i.e mediator and ConnectionHandler are created per invocation
    auto mediator =
        std::make_unique<mediator::MediatorImpl>(m_data_manager, m_provider_manager, m_config, m_km_service);
    auto handler = std::make_unique<ConnectionHandler>(std::move(mediator),
                                                       m_data_manager,  // Shared data manager
                                                       m_config);

    return handler;
}

}  // namespace score::crypto::daemon::control_plane
