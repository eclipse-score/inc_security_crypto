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
#include "score/crypto/src/daemon/common/types.hpp"

#include <sys/types.h>
#include <functional>
#include <variant>

namespace score::crypto::ipc::message_passing
{

/// @brief Decides whether a peer may establish a server connection.
/// @param uid Peer user ID reported by the transport.
/// @param gid Peer group ID reported by the transport.
/// @return True to authorize, false to deny, or a daemon error if authorization fails.
using AuthorizationCallback =
    std::function<score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode>(uid_t uid, gid_t gid)>;

/// @brief Releases application-owned resources after a client session disconnects.
/// @param client_id Server-assigned identity of the disconnected client.
/// @return Success when cleanup completes, or the daemon error that caused it to fail.
using DisconnectCleanupCallback =
    std::function<score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>(
        score::crypto::daemon::common::ClientId client_id)>;

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_SERVER_CALLBACKS_HPP
