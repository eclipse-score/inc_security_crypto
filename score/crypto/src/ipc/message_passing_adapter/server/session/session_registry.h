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

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/server_callbacks.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/session/session.h"

#include <score/unordered_map.hpp>

#include <sys/types.h>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
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
    using ClientId = score::crypto::daemon::control_plane::protocol::ClientId;
    using SessionFactory = std::function<std::shared_ptr<detail::Session>(score::message_passing::IServerConnection&,
                                                                          ClientId,
                                                                          detail::Session::CleanupFinishedCallback)>;

    SessionRegistry() = default;

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    TryRegisterAuthorizedConnection(score::message_passing::IServerConnection& connection,
                                    uid_t uid,
                                    SessionFactory session_factory);
    std::shared_ptr<detail::Session> DetachConnection(score::message_passing::IServerConnection& connection) noexcept;
    score::crypto::Expected<std::vector<std::shared_ptr<detail::Session>>,
                            score::crypto::daemon::common::DaemonErrorCode>
    DetachAllConnections() noexcept;
    std::shared_ptr<detail::Session> FindSessionForRequest(
        score::message_passing::IServerConnection& connection) const noexcept;

    void EnableAdmissions() noexcept;
    void DisableAdmissions() noexcept;
    void WaitForAllConnectionsClosed() noexcept;

  private:
    enum class ClientLifecycleState : std::uint8_t
    {
        kConnectionActive,
        kCleanupPending,
        kConnectionQuarantined,
    };

    struct ClientState final
    {
        uid_t uid{0U};
        ClientLifecycleState lifecycle{ClientLifecycleState::kConnectionActive};
    };
    using ConnectionMap =
        std::unordered_map<score::message_passing::IServerConnection*, std::shared_ptr<detail::Session>>;

    score::crypto::Expected<ClientId, score::crypto::daemon::common::DaemonErrorCode> GenerateClientId(
        std::lock_guard<std::mutex>& lock,
        uid_t uid) const noexcept;
    void CommitClientId(std::lock_guard<std::mutex>& lock, ClientId client_id) noexcept;

    bool NewConnectionFitsInTotalCapacity(std::lock_guard<std::mutex>& lock) const noexcept;
    bool NewConnectionFitsInUidCapacity(std::lock_guard<std::mutex>& lock, uid_t uid) const noexcept;
    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> TryReserveClient(
        std::lock_guard<std::mutex>& lock,
        score::message_passing::IServerConnection& connection,
        uid_t uid,
        SessionFactory& session_factory) noexcept;
    std::shared_ptr<detail::Session> DetachConnection(std::lock_guard<std::mutex>& lock,
                                                      ConnectionMap::iterator connection_iterator) noexcept;

    void OnCleanupFinished(ClientId client_id, bool cleanup_succeeded) noexcept;

    mutable std::mutex mutex_;
    std::condition_variable disconnect_condition_;
    std::size_t pending_disconnect_count_{0U};
    bool admissions_enabled_{true};
    std::unordered_map<ClientId, ClientState> client_states_{};
    std::unordered_map<uid_t, std::size_t> reserved_connections_by_uid_{};
    ConnectionMap connections_{};
    std::uint32_t next_connection_generation_{1U};
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_SESSION_REGISTRY_H
