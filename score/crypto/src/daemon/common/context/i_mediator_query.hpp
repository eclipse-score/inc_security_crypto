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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_MEDIATOR_QUERY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_MEDIATOR_QUERY_HPP

#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <memory>

namespace score::crypto::daemon::common
{

/// @brief Handles one mediator operation code that the mediator does not implement itself.
///
/// Implementations are called from connection threads and must be thread-safe.
class IMediatorQuery
{
  public:
    /// @brief Shared pointer to a mediator query.
    using Sptr = std::shared_ptr<IMediatorQuery>;

    /// @brief Virtual destructor.
    virtual ~IMediatorQuery() = default;

    /// @brief Handle the operation and write its result to the response.
    /// @param request Parent control-plane request identifying the client.
    /// @param operation Operation to handle.
    /// @param responseBuilder Builder receiving the result or an error.
    /// @return True if the operation succeeded.
    [[nodiscard]] virtual bool Handle(const control_plane::protocol::ControlRequest& request,
                                      const control_plane::protocol::SingleOperationRequest& operation,
                                      control_plane::protocol::OperationResponseBuilder& responseBuilder) = 0;
};

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_I_MEDIATOR_QUERY_HPP
