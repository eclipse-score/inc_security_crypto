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

#ifndef SCORE_CRYPTO_DAEMON_CONTROL_PLANE_REQUEST_HANDLER_FACTORY_HPP_
#define SCORE_CRYPTO_DAEMON_CONTROL_PLANE_REQUEST_HANDLER_FACTORY_HPP_

#include "score/crypto/daemon/control_plane/i_request_handler.hpp"
#include <memory>

namespace score::crypto::daemon::control_plane
{

/**
 * @interface IHandlerChainFactory
 * @brief Factory interface for creating IRequestHandler instances.
 *
 * This interface enables creation of handler instances per thread context,
 * supporting thread-safe request processing with isolated handler state.
 */
class IHandlerChainFactory
{
  public:
    /**
     * @brief Default constructor.
     */
    IHandlerChainFactory() = default;

    /**
     * @brief Virtual destructor.
     */
    virtual ~IHandlerChainFactory() = default;

    // Non-copyable - factories should not be duplicated
    IHandlerChainFactory(const IHandlerChainFactory&) = delete;
    IHandlerChainFactory& operator=(const IHandlerChainFactory&) = delete;

    // Movable - factories can be transferred (unique_ptr ownership transfer)

    /**
     * @brief Creates a new request handler instance.
     *
     * Each call creates a fresh handler with the complete chain of responsibility.
     * This enables per-thread handler isolation in multi-threaded environments.
     *
     * @return std::unique_ptr<control_plane::IRequestHandler> New handler instance
     *
     * @par Thread-safety Requirements
     * Implementations must be thread-safe
     */
    virtual std::unique_ptr<IRequestHandler> CreateRequestHandler() = 0;
};

}  // namespace score::crypto::daemon::control_plane

#endif  // SCORE_CRYPTO_DAEMON_CONTROL_PLANE_REQUEST_HANDLER_FACTORY_HPP_
