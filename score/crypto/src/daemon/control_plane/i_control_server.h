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

#ifndef CONTROL_SERVER_H
#define CONTROL_SERVER_H

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <variant>

namespace score::crypto::daemon::control_plane
{

/// Abstract interface for control plane server lifecycle management
class IControlServer
{
  public:
    virtual ~IControlServer() = default;

    /// Start the server listening
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    Start() = 0;

    /// Block until server termination
    virtual void WaitForTermination() = 0;

    /// Stop the server gracefully, cleaning up resources
    virtual void Stop() = 0;
};

}  // namespace score::crypto::daemon::control_plane

#endif  // CONTROL_SERVER_H
