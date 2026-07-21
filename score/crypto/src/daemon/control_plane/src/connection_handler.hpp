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

#ifndef CONTROL_HANDLER_IMPL_H
#define CONTROL_HANDLER_IMPL_H

#include <memory>

#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/config/inc/config.hpp"
#include "score/crypto/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"

namespace score::crypto::daemon::control_plane
{

class ConnectionHandler : public IRequestHandler
{
  public:
    ConnectionHandler(std::unique_ptr<IRequestHandler> next_request_handler,
                      std::shared_ptr<data_manager::IDataManager> data_manager,
                      const config::Config& config);

    ~ConnectionHandler() override = default;

    // Move semantics - handler is move-only due to unique_ptr member
    ConnectionHandler(ConnectionHandler&&) = default;
    ConnectionHandler& operator=(ConnectionHandler&&) = default;

    // Delete copy semantics
    ConnectionHandler(const ConnectionHandler&) = delete;
    ConnectionHandler& operator=(const ConnectionHandler&) = delete;

    ControlResponse processRequest(const ControlRequest& request) override;

  private:
    std::unique_ptr<IRequestHandler> m_next_request_handler;
    std::shared_ptr<data_manager::IDataManager> m_data_manager;

    bool ProcessSingleRequest(const ControlRequest& request,
                              const common::OperationIdentifier& opId,
                              control_plane::protocol::OperationResponseBuilder& responseBuilder);

    bool ProcessConnectionCreation(const ControlRequest& request,
                                   const common::OperationIdentifier& opId,
                                   control_plane::protocol::OperationResponseBuilder& responseBuilder);
    bool ProcessConnectionClosure(const ControlRequest& request,
                                  const common::OperationIdentifier& opId,
                                  control_plane::protocol::OperationResponseBuilder& responseBuilder);
    bool ProcessUnknownRequest(const ControlRequest& request,
                               const common::OperationIdentifier& opId,
                               control_plane::protocol::OperationResponseBuilder& responseBuilder);
};

}  // namespace score::crypto::daemon::control_plane

#endif  // CONTROL_HANDLER_IMPL_H
