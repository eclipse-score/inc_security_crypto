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

#ifndef CRYPTO_DAEMON_CONTROL_PLANE_REQUEST_HANDLER_HPP_
#define CRYPTO_DAEMON_CONTROL_PLANE_REQUEST_HANDLER_HPP_

#include <cstdint>

#include "score/crypto/daemon/control_plane/control_protocol.h"

namespace score::crypto::daemon::control_plane
{

using SingleOperationRequest = protocol::SingleOperationRequest;
using SingleOperationResponse = protocol::SingleOperationResponse;

using ControlRequest = protocol::ControlRequest;
using ControlResponse = protocol::ControlResponse;

/**
 * @interface IRequestHandler
 * @brief Base interface for chain of responsibility pattern in request processing.
 *
 * This interface provides a common contract for all elements in the request
 * processing chain (brokers, mediators, etc.). It enables dynamic insertion
 * and deletion of handlers in the chain.
 */
class IRequestHandler
{
  public:
    /**
     * @brief Default constructor.
     */
    IRequestHandler() = default;

    /**
     * @brief Virtual destructor.
     */
    virtual ~IRequestHandler() = default;

    // Delete copy and move operations
    IRequestHandler(const IRequestHandler&) = delete;
    IRequestHandler& operator=(const IRequestHandler&) = delete;
    IRequestHandler(IRequestHandler&&) = delete;
    IRequestHandler& operator=(IRequestHandler&&) = delete;

    /**
     * @brief Processes a control request and generates a corresponding response.
     *
     * @param request The control request to be processed.
     * @return ControlResponse The response generated after processing the request.
     */
    virtual ControlResponse processRequest(const ControlRequest& request) = 0;
};

}  // namespace score::crypto::daemon::control_plane

#endif  // CRYPTO_DAEMON_CONTROL_PLANE_REQUEST_HANDLER_HPP_
