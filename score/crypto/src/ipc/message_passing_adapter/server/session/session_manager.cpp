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

#include "score/crypto/src/ipc/message_passing_adapter/server/session/session_manager.h"

#include "score/message_passing/i_server_connection.h"
#include "score/mw/log/logging.h"

#include <new>
#include <utility>

namespace score::crypto::ipc::message_passing
{
namespace
{

AuthorizationCallback DefaultDenyAuthorization()
{
    return [](uid_t, gid_t) noexcept {
        return score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode>{false};
    };
}

}  // namespace

SessionManager::SessionManager(IWorkItemSubmitter& submitter,
                               AuthorizationCallback authorization,
                               DisconnectCleanupCallback cleanup_callback)
    : m_submitter(submitter),
      m_authorization(authorization ? std::move(authorization) : DefaultDenyAuthorization()),
      m_cleanup_callback(std::move(cleanup_callback))
{
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> SessionManager::OnConnect(
    score::message_passing::IServerConnection& connection) noexcept
{
    try
    {
        const auto identity = connection.GetClientIdentity();
        const auto authorization_result = IsAuthorizedToConnect(identity.uid, identity.gid);
        if (!authorization_result.has_value())
        {
            return score::crypto::make_unexpected(authorization_result.error());
        }
        if (!authorization_result.value())
        {
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAccessDenied);
        }

        auto registration_result =
            m_session_registry.TryRegisterAuthorizedConnection(connection, identity.uid, CreateSessionFactory());
        if (!registration_result.has_value())
        {
            return score::crypto::make_unexpected(registration_result.error());
        }
        return std::monostate{};
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Allocation failed while accepting connection";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Unexpected exception while accepting connection";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
}

score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode> SessionManager::IsAuthorizedToConnect(
    const uid_t uid,
    const gid_t gid)
{
    score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode> authorization_result{false};
    try
    {
        authorization_result = m_authorization(uid, gid);
    }
    catch (...)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Authorization callback threw for uid=" << uid
                                   << ", gid=" << gid;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    if (!authorization_result.has_value())
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Authorization callback failed for uid=" << uid
                                   << ", gid=" << gid;
        return score::crypto::make_unexpected(authorization_result.error());
    }
    if (!authorization_result.value())
    {
        score::mw::log::LogWarn() << "[MESSAGE_PASSING_SERVER] Authorization denied for uid=" << uid << ", gid=" << gid;
        return {false};
    }
    return {true};
}

SessionRegistry::SessionFactory SessionManager::CreateSessionFactory()
{
    return [this](score::message_passing::IServerConnection& connection,
                  const SessionRegistry::ClientId client_id,
                  detail::Session::CleanupFinishedCallback cleanup_finished_callback) {
        return std::make_shared<detail::Session>(
            connection, client_id, m_submitter, m_cleanup_callback, std::move(cleanup_finished_callback));
    };
}

void SessionManager::OnDisconnect(score::message_passing::IServerConnection& connection) noexcept
{
    auto detached = m_session_registry.DetachConnection(connection);
    if (detached != nullptr)
    {
        detached->Disconnect();
    }
}

std::shared_ptr<detail::Session> SessionManager::FindSessionForRequest(
    score::message_passing::IServerConnection& connection) const noexcept
{
    return m_session_registry.FindSessionForRequest(connection);
}

void SessionManager::StartAcceptConnections() noexcept
{
    m_session_registry.StartAcceptConnections();
}

void SessionManager::StopAcceptConnections() noexcept
{
    m_session_registry.StopAcceptConnections();
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
SessionManager::DrainConnections() noexcept
{
    auto detached_connections = m_session_registry.DetachAllConnections();
    if (!detached_connections.has_value())
    {
        return score::crypto::make_unexpected(detached_connections.error());
    }

    for (auto& session : detached_connections.value())
    {
        if (session != nullptr)
        {
            session->Disconnect();
        }
    }
    return {};
}

void SessionManager::WaitForAllConnectionsClosed() noexcept
{
    m_session_registry.WaitForAllConnectionsClosed();
}

}  // namespace score::crypto::ipc::message_passing
