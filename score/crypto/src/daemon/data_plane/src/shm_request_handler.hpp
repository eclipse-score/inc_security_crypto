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

#ifndef SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_SHM_REQUEST_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_SHM_REQUEST_HANDLER_HPP

#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"

#include <memory>
#include <string_view>

namespace score::crypto::daemon::data_plane
{

/// @brief Request handler for SHM parameter translation.
///
/// Resolves DataShm parameters to virtual addresses (via DataManager → ShmDataNode)
/// before forwarding any request to the next handler in the chain.
class ShmRequestHandler final : public control_plane::IRequestHandler
{
  public:
    /// @param next_handler   Next handler in the chain (typically the Mediator).
    /// @param data_manager   DataManager for ShmDataNode resolution.
    ShmRequestHandler(std::unique_ptr<control_plane::IRequestHandler> next_handler,
                      data_manager::IDataManager::Sptr data_manager);

    control_plane::ControlResponse processRequest(control_plane::ControlRequest& request) override;

  private:
    control_plane::ControlResponse ForwardWithResolvedShm(control_plane::ControlRequest& request);

    std::unique_ptr<control_plane::IRequestHandler> m_next_handler;
    data_manager::IDataManager::Sptr m_data_manager;

    static constexpr std::string_view LOG_PREFIX = "[SHM_REQUEST_HANDLER] ";
};

}  // namespace score::crypto::daemon::data_plane

#endif  // SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_SHM_REQUEST_HANDLER_HPP
