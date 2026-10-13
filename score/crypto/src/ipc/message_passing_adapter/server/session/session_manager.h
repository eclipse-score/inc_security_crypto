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

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_MANAGER_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_MANAGER_H

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/server_callbacks.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/session/session_registry.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/work_item_execution/i_work_item_submitter.h"

#include "score/message_passing/i_server_connection.h"

#include <sys/types.h>
#include <cstdint>
#include <memory>

namespace score::crypto::ipc::message_passing
{

/**
 * @brief
 * Authorizes transport connections and routes them to registered server sessions.
 * Coordinates admission, disconnect notification, and waiting for connection cleanup through
 * SessionRegistry.
 * @endrst
 */
class SessionManager final
{
  public:
    SessionManager(IWorkItemSubmitter& submitter,
                   AuthorizationCallback authorization,
                   DisconnectCleanupCallback cleanup_callback);

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> OnConnect(
        score::message_passing::IServerConnection& connection) noexcept;
    void OnDisconnect(score::message_passing::IServerConnection& connection) noexcept;
    std::shared_ptr<detail::Session> FindSessionForRequest(
        score::message_passing::IServerConnection& connection) const noexcept;

    void EnableAdmissions() noexcept;
    void DisableAdmissions() noexcept;
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> DrainConnections() noexcept;
    void WaitForAllConnectionsClosed() noexcept;

  private:
    score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode> IsAuthorizedToConnect(uid_t uid,
                                                                                                        gid_t gid);
    SessionRegistry::SessionFactory CreateSessionFactory();

    IWorkItemSubmitter& submitter_;
    AuthorizationCallback authorization_;
    DisconnectCleanupCallback cleanup_callback_;
    SessionRegistry session_registry_;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_MANAGER_H
