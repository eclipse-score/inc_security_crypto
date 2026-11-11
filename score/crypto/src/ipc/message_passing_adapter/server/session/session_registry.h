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

#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_REGISTRY_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_REGISTRY_H

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/session/session.h"

#include <score/unordered_map.hpp>

#include <sys/types.h>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace score::crypto::ipc::message_passing
{

/**
 * @brief
 * Owns synchronized connection registration, admission reservations, and cleanup accounting.
 * Maps transport connections to sessions and releases admission capacity only when disconnect
 * cleanup has completed.
 * @endrst
 */
class SessionRegistry final
{
  public:
    using ClientId = score::crypto::daemon::common::ClientId;
    using SessionFactory = std::function<std::shared_ptr<detail::Session>(score::message_passing::IServerConnection&,
                                                                          ClientId,
                                                                          detail::Session::CleanupFinishedCallback)>;

    /// @brief Creates a registry with connection admission disabled.
    SessionRegistry() = default;

    /// @brief Registers an authorized connection and reserves its session capacity.
    /// @param connection Transport connection being registered.
    /// @param uid Peer UID used for per-UID capacity accounting.
    /// @param session_factory Factory that creates the session for this connection.
    /// @return Success when registered, or an error if admission, allocation, or registration fails.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    TryRegisterAuthorizedConnection(score::message_passing::IServerConnection& connection,
                                    uid_t uid,
                                    SessionFactory session_factory);
    /// @brief Removes a transport connection and begins its disconnect cleanup accounting.
    /// @param connection Transport connection to detach.
    /// @return The detached session, or null if the connection was not registered.
    std::shared_ptr<detail::Session> DetachConnection(score::message_passing::IServerConnection& connection) noexcept;

    /// @brief Detaches all registered connections for server shutdown.
    /// @return The detached sessions, or an error if the snapshot cannot be allocated.
    score::crypto::Expected<std::vector<std::shared_ptr<detail::Session>>,
                            score::crypto::daemon::common::DaemonErrorCode>
    DetachAllConnections() noexcept;

    /// @brief Finds the session associated with a transport connection.
    /// @param connection Transport connection to look up.
    /// @return The registered session, or null when no mapping exists.
    std::shared_ptr<detail::Session> FindSessionForRequest(
        score::message_passing::IServerConnection& connection) const noexcept;

    /// @brief Enables admission of authorized connections.
    void StartAcceptConnections() noexcept;
    /// @brief Disables admission of new authorized connections.
    void StopAcceptConnections() noexcept;
    /// @brief Waits until all pending disconnect cleanup callbacks finish.
    void WaitForAllConnectionsClosed() noexcept;

  private:
    enum class ClientLifecycleState : std::uint8_t
    {
        kConnectionActive,       ///< Connection is active and consumes UID/global capacity.
        kCleanupPending,         ///< Detached session is draining or running cleanup.
        kConnectionQuarantined,  ///< Cleanup failed; its capacity reservation is retained.
    };

    /// Per-client UID reservation and lifecycle state.
    struct ClientState final
    {
        uid_t uid{0U};  ///< UID charged for this client's connection reservation.
        ClientLifecycleState lifecycle{ClientLifecycleState::kConnectionActive};  ///< Reservation lifecycle.
    };
    using ClientStateMap = std::unordered_map<ClientId, ClientState>;
    using ConnectionMap =
        std::unordered_map<score::message_passing::IServerConnection*, std::shared_ptr<detail::Session>>;

    /// @brief Generates an unused client ID without committing its sequence number.
    /// @details If used, the ClientId shall be committed via CommitClientId.
    /// @param lock Registry lock held by the caller.
    /// @param uid Peer UID encoded into the client ID.
    /// @return An unused client ID, or an internal error if none is available.
    score::crypto::Expected<ClientId, score::crypto::daemon::common::DaemonErrorCode> GenerateClientId(
        std::lock_guard<std::mutex>& lock,
        uid_t uid) const noexcept;

    /// @brief Commits the client-ID sequence after a reservation fully succeeds.
    /// @param lock Registry lock held by the caller.
    /// @param client_id Successfully reserved client ID.
    void CommitClientId(std::lock_guard<std::mutex>& lock, ClientId client_id) noexcept;

    /// @brief Checks whether the global connection capacity has room.
    /// @param lock Registry lock held by the caller.
    /// @return True when another client can be admitted in the global connection capacity.
    bool NewConnectionFitsInTotalCapacity(std::lock_guard<std::mutex>& lock) const noexcept;

    /// @brief Checks whether the UID is below its connection capacity.
    /// @param lock Registry lock held by the caller.
    /// @param uid Peer UID to check.
    /// @return True when another connection for the UID can be admitted in the per UID capacity..
    bool NewConnectionFitsInUidCapacity(std::lock_guard<std::mutex>& lock, uid_t uid) const noexcept;

    /// @brief Creates a session and commits the registry reservations in order.
    /// @param lock Registry lock held by the caller.
    /// @param connection Transport connection being reserved.
    /// @param uid Peer UID charged for the reservation.
    /// @param session_factory Factory used to create the session.
    /// @return Success after all reservations commit, or an error with prior map changes rolled back.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> TryReserveClient(
        std::lock_guard<std::mutex>& lock,
        score::message_passing::IServerConnection& connection,
        uid_t uid,
        SessionFactory& session_factory) noexcept;

    /// @brief Creates a session and translates factory exceptions to daemon errors.
    /// @param connection Transport connection owned by the session.
    /// @param client_id ID assigned to the session.
    /// @param session_factory Factory used to construct the session.
    /// @return The created session, or an error if creation fails.
    score::crypto::Expected<std::shared_ptr<detail::Session>, score::crypto::daemon::common::DaemonErrorCode>
    CreateSession(score::message_passing::IServerConnection& connection,
                  ClientId client_id,
                  SessionFactory& session_factory) noexcept;

    /// @brief Adds the connection-to-session mapping.
    /// @param lock Registry lock held by the caller.
    /// @param connection Transport connection to map.
    /// @param session Session associated with the connection.
    /// @param client_id ID used for diagnostic messages.
    /// @return The inserted map iterator, or an error for duplicates or insertion failure.
    /// @details Needs to be undone, if the later registration of the connection fails.
    score::crypto::Expected<ConnectionMap::iterator, score::crypto::daemon::common::DaemonErrorCode> RegisterConnection(
        std::lock_guard<std::mutex>& lock,
        score::message_passing::IServerConnection& connection,
        const std::shared_ptr<detail::Session>& session,
        ClientId client_id) noexcept;

    /// @brief Adds the lifecycle record for a client ID.
    /// @param lock Registry lock held by the caller.
    /// @param client_id ID of the new session.
    /// @param uid Peer UID charged for this session.
    /// @return The inserted state iterator, or an error for duplicates or insertion failure.
    /// @details Needs to be undone, if the later registration of the connection fails.
    score::crypto::Expected<ClientStateMap::iterator, score::crypto::daemon::common::DaemonErrorCode>
    RegisterClientState(std::lock_guard<std::mutex>& lock, ClientId client_id, uid_t uid) noexcept;

    /// @brief Increments the reserved connection count for a UID.
    /// @param lock Registry lock held by the caller.
    /// @param uid Peer UID whose capacity is reserved.
    /// @param client_id ID used for diagnostic messages.
    /// @return Success when reserved, or an error if insertion fails.
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ReserveConnectionForUid(std::lock_guard<std::mutex>& lock, uid_t uid, ClientId client_id) noexcept;

    /// @brief Detaches a connection while the registry lock is already held.
    /// @param lock Registry lock held by the caller.
    /// @param connection_iterator Iterator to the connection mapping to remove.
    /// @return The detached session.
    std::shared_ptr<detail::Session> DetachConnection(std::lock_guard<std::mutex>& lock,
                                                      ConnectionMap::iterator connection_iterator) noexcept;

    /// @brief Applies cleanup completion to lifecycle and capacity accounting.
    /// @param client_id Session whose cleanup completed.
    /// @param cleanup_succeeded Whether the disconnect cleanup callback succeeded.
    void OnCleanupFinished(ClientId client_id, bool cleanup_succeeded) noexcept;

    mutable std::mutex m_mutex;
    std::condition_variable m_all_connections_cleaned_up;
    std::size_t m_pending_disconnect_count{0U};
    bool m_accept_connections{false};
    ClientStateMap m_client_states{};
    std::unordered_map<uid_t, std::size_t> m_reserved_connections_by_uid{};
    ConnectionMap m_connections{};
    std::uint32_t m_next_connection_generation{1U};
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_REGISTRY_H
