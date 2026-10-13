/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_SERVER_CALLBACKS_HPP
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_SERVER_CALLBACKS_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <sys/types.h>
#include <cstdint>
#include <functional>
#include <variant>

namespace score::crypto::ipc::message_passing
{

/**
 * @brief AuthorizationCallback:
 * Decides whether a peer identified by user and group ID may connect.
 * @endrst
 */
using AuthorizationCallback =
    std::function<score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode>(uid_t uid, gid_t gid)>;
/**
 * @brief DisconnectCleanupCallback:
 * Releases application-owned resources after a client's session disconnects.
 * @endrst
 */
using DisconnectCleanupCallback =
    std::function<score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>(
        score::crypto::daemon::control_plane::protocol::ClientId client_id)>;

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_SERVER_CALLBACKS_HPP
