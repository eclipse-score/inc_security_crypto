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

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/server_callbacks.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/session/session_registry.h"

#include <sys/types.h>
#include <memory>

namespace score::message_passing
{
class IServerConnection;
}  // namespace score::message_passing

namespace score::crypto::ipc::message_passing
{

class IWorkItemSubmitter;

/**
 * @brief
 * Authorizes transport connections and routes them to registered server sessions.
 * Coordinates admission, disconnect notification, and waiting for connection cleanup through
 * SessionRegistry.
 */
class SessionManager final
{
  public:
    /// @brief Creates a manager for authorizing and tracking server sessions.
    /// @param submitter Executor that accepts request and cleanup jobs.
    /// @param authorization Callback that decides whether a peer UID/GID may connect.
    /// @param cleanup_callback Callback invoked after a session drains.
    SessionManager(IWorkItemSubmitter& submitter,
                   AuthorizationCallback authorization,
                   DisconnectCleanupCallback cleanup_callback);

    /// @brief Authorizes and registers an incoming transport connection.
    /// @param connection Connection requesting admission.
    /// @return Success when registered, or an authorization/admission error.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> OnConnect(
        score::message_passing::IServerConnection& connection) noexcept;

    /// @brief Detaches a disconnected connection and starts its cleanup lifecycle.
    /// @param connection Connection reported by the transport as disconnected.
    void OnDisconnect(score::message_passing::IServerConnection& connection) noexcept;

    /// @brief Finds the session associated with a connection for request dispatch.
    /// @param connection Transport connection that sent the request.
    /// @return The matching session, or null if the connection is not registered.
    std::shared_ptr<detail::Session> FindSessionForRequest(
        score::message_passing::IServerConnection& connection) const noexcept;

    /// @brief Enables admission of authorized connections.
    void StartAcceptConnections() noexcept;
    /// @brief Disables admission of new connections.
    void StopAcceptConnections() noexcept;

    /// @brief Detaches every registered connection and starts session cleanup.
    /// @return Success when draining begins, or an error if the registry cannot snapshot connections.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> DrainConnections() noexcept;

    /// @brief Waits until all detached sessions finish cleanup.
    void WaitForAllConnectionsClosed() noexcept;

  private:
    /// @brief Invokes and validates the configured authorization callback.
    /// @param uid Peer user ID reported by the transport.
    /// @param gid Peer group ID reported by the transport.
    /// @return True when authorized, false when denied, or an error if the callback fails.
    score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode> IsAuthorizedToConnect(uid_t uid,
                                                                                                        gid_t gid);

    /// @brief Creates the registry callback used to instantiate sessions.
    /// @return A factory that binds new sessions to this manager's submitter and cleanup callback.
    SessionRegistry::SessionFactory CreateSessionFactory();

    IWorkItemSubmitter& m_submitter;
    AuthorizationCallback m_authorization;
    DisconnectCleanupCallback m_cleanup_callback;
    SessionRegistry m_session_registry;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_MANAGER_H
