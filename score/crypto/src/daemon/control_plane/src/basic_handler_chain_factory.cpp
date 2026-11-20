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

#include "score/crypto/src/daemon/control_plane/basic_handler_chain_factory.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/i_handler_chain_factory.hpp"
#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/src/daemon/control_plane/src/connection_handler.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/src/daemon/data_plane/src/shm_request_handler.hpp"
#include "score/crypto/src/daemon/mediator/i_mediator.hpp"

#include <memory>
#include <utility>

namespace score::crypto::daemon::control_plane
{

BasicHandlerChainFactory::BasicHandlerChainFactory(std::shared_ptr<data_manager::IDataManager> data_manager,
                                                   const config::Config& config,
                                                   std::shared_ptr<mediator::IMediator> mediator)
    : IHandlerChainFactory(), m_data_manager(std::move(data_manager)), m_config(config), m_mediator(std::move(mediator))
{
}

std::unique_ptr<IRequestHandler> BasicHandlerChainFactory::CreateRequestHandler()
{
    // The mediator is shared; the ShmRequestHandler and ConnectionHandler are per connection.
    auto next_handler = std::make_unique<data_plane::ShmRequestHandler>(m_mediator, m_data_manager);
    auto handler = std::make_unique<ConnectionHandler>(std::move(next_handler),
                                                       m_data_manager,  // Shared data manager
                                                       m_config);

    return handler;
}

}  // namespace score::crypto::daemon::control_plane
