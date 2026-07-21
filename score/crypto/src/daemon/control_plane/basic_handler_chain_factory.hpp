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

#ifndef SCORE_CRYPTO_DAEMON_CONTROL_PLANE_REQUEST_HANDLER_FACTORY_IMPL_HPP_
#define SCORE_CRYPTO_DAEMON_CONTROL_PLANE_REQUEST_HANDLER_FACTORY_IMPL_HPP_

#include "score/crypto/daemon/config/inc/config.hpp"
#include "score/crypto/daemon/control_plane/i_handler_chain_factory.hpp"
#include "score/crypto/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"
#include "score/crypto/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"
#include <memory>

namespace score::crypto::daemon::control_plane
{

/**
 * @class BasicHandlerChainFactory
 * @brief Concrete factory implementation for creating request handler chains.
 *
 * Shares thread-safe components: IDataManager, ProviderManager
 */
class BasicHandlerChainFactory : public IHandlerChainFactory
{
  public:
    /**
     * @brief Constructs factory with shared thread-safe dependencies.
     *
     * @param data_manager Thread-safe shared data manager (shared across threads)
     * @param provider_manager Shared provider manager (shared across threads)
     * @param config Configuration reference (must outlive factory)
     */
    BasicHandlerChainFactory(std::shared_ptr<data_manager::IDataManager> data_manager,
                             std::shared_ptr<provider::ProviderManager> provider_manager,
                             const config::Config& config,
                             key_management::KeyManagementService::Sptr km_service = nullptr);

    // Non-copyable - factories should not be duplicated
    BasicHandlerChainFactory(const BasicHandlerChainFactory&) = delete;
    BasicHandlerChainFactory& operator=(const BasicHandlerChainFactory&) = delete;

    // Movable - factories can be transferred (unique_ptr ownership transfer)

    /**
     * @brief Creates a new request handler wrapper.
     *
     * Each call creates NEW ConnectionHandler wrapping SHARED Mediator.
     * The shared mediator preserves context state across requests from different threads.
     *
     * @return std::unique_ptr<IRequestHandler> New handler wrapper
     *
     * @par Thread-safety Requirements
     * Implementation is thread safe : The current implementation has no shared mutable state.
     */
    std::unique_ptr<IRequestHandler> CreateRequestHandler() override;

  private:
    std::shared_ptr<data_manager::IDataManager> m_data_manager;     // Shared across threads
    std::shared_ptr<provider::ProviderManager> m_provider_manager;  // Shared across threads
    const config::Config& m_config;
    key_management::KeyManagementService::Sptr m_km_service;  // Shared across threads
};

}  // namespace score::crypto::daemon::control_plane

#endif  // SCORE_CRYPTO_DAEMON_CONTROL_PLANE_REQUEST_HANDLER_FACTORY_IMPL_HPP_
