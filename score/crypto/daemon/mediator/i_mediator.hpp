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

#ifndef SCORE_CRYPTO_DAEMON_MEDIATOR_IMediator_HPP_
#define SCORE_CRYPTO_DAEMON_MEDIATOR_IMediator_HPP_

#include <memory>

#include "score/crypto/daemon/config/inc/config.hpp"
#include "score/crypto/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"

namespace score::crypto::daemon::mediator
{

/**
 * @interface IMediator
 * @brief Interface for mediating API requests in the crypto daemon.
 *
 * The IMediator interface, implementation shall classify the type of the
 * crypto operation the incoming request pertains to and delegate it to the
 * appropriate handler within the crypto daemon. It inherits from IRequestHandler
 * to participate in the chain of responsibility pattern.
 */
class IMediator : public score::crypto::daemon::control_plane::IRequestHandler
{
  public:
    /**
     * @brief Default constructor.
     */
    IMediator(daemon::data_manager::IDataManager::Sptr data_manager,
              daemon::provider::ProviderManager::Sptr provider_manager,
              const config::Config& config,
              daemon::key_management::KeyManagementService::Sptr km_service = nullptr)
        : m_data_manager(data_manager),
          m_provider_manager(provider_manager),
          m_config(config),
          m_km_service(std::move(km_service))
    {
    }

    /**
     * @brief Virtual destructor.
     */
    virtual ~IMediator() = default;

    // Delete copy and move operations
    IMediator(const IMediator&) = delete;
    IMediator& operator=(const IMediator&) = delete;
    IMediator(IMediator&&) = delete;
    IMediator& operator=(IMediator&&) = delete;

    /**
     * @brief Processes a control request and generates a corresponding response.
     *
     * @param request The control request to be processed, containing command and
     * parameters.
     * @return ControlResponse The response generated after processing the
     * request.
     */
    virtual score::crypto::daemon::control_plane::ControlResponse processRequest(
        const score::crypto::daemon::control_plane::ControlRequest& request) override = 0;

  protected:
    daemon::data_manager::IDataManager::Sptr m_data_manager;
    daemon::provider::ProviderManager::Sptr m_provider_manager;
    const config::Config& m_config;
    daemon::key_management::KeyManagementService::Sptr m_km_service;
};

}  // namespace score::crypto::daemon::mediator

#endif  // IPC_IMediator_HPP_
