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

#include "score/crypto/src/ipc/message_passing_adapter/server/session/session_registry.h"

#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/ipc_config.h"

#include "score/mw/log/logging.h"

#include <optional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace score::crypto::ipc::message_passing
{
score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
SessionRegistry::TryRegisterAuthorizedConnection(score::message_passing::IServerConnection& connection,
                                                 const uid_t uid,
                                                 SessionFactory session_factory)
{
    if (!session_factory)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Missing session factory while registering connection";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_accept_connections)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kConnectionFailed);
    }
    if (!NewConnectionFitsInTotalCapacity(lock))
    {
        score::mw::log::LogWarn() << "[MESSAGE_PASSING_SERVER] Total connection capacity reached for uid=" << uid;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
    }
    if (!NewConnectionFitsInUidCapacity(lock, uid))
    {
        score::mw::log::LogWarn() << "[MESSAGE_PASSING_SERVER] Per-UID connection capacity reached for uid=" << uid;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
    }
    const auto reservation_result = TryReserveClient(lock, connection, uid, session_factory);
    if (!reservation_result.has_value())
    {
        return score::crypto::make_unexpected(reservation_result.error());
    }

    return std::monostate{};
}

bool SessionRegistry::NewConnectionFitsInTotalCapacity(std::lock_guard<std::mutex>& lock) const noexcept
{
    static_cast<void>(lock);
    return m_client_states.size() < ipc::kMaxTotalConnections;
}

bool SessionRegistry::NewConnectionFitsInUidCapacity(std::lock_guard<std::mutex>& lock, const uid_t uid) const noexcept
{
    static_cast<void>(lock);
    const auto iterator = m_reserved_connections_by_uid.find(uid);
    return (iterator == m_reserved_connections_by_uid.end()) || (iterator->second < ipc::kMaxConnectionsPerUid);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
SessionRegistry::TryReserveClient(std::lock_guard<std::mutex>& lock,
                                  score::message_passing::IServerConnection& connection,
                                  const uid_t uid,
                                  SessionFactory& session_factory) noexcept
{

    const auto client_id = GenerateClientId(lock, uid);
    if (!client_id.has_value())
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Failed to generate client ID for uid=" << uid
                                   << " (error=" << static_cast<int>(client_id.error()) << ")";
        return score::crypto::make_unexpected(client_id.error());
    }

    std::shared_ptr<detail::Session> session;
    // Creating a session allocates the object and its shared ownership state.
    try
    {
        detail::Session::CleanupFinishedCallback cleanup_finished_callback =
            [this](const ClientId completed_client_id, const bool cleanup_succeeded) noexcept {
                OnCleanupFinished(completed_client_id, cleanup_succeeded);
            };
        session = session_factory(connection, client_id.value(), std::move(cleanup_finished_callback));
        if (session == nullptr)
        {
            score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Session factory returned null for client_id="
                                       << client_id.value();
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
        }
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Allocation failed while creating session for client_id="
                                   << client_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        score::mw::log::LogError()
            << "[MESSAGE_PASSING_SERVER] Unexpected failure while creating session for client_id=" << client_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    decltype(m_connections)::iterator connection_iterator;
    // The connection registry insertion may allocate before the admission gate is committed.
    try
    {
        const auto insertion = m_connections.try_emplace(&connection, session);
        connection_iterator = insertion.first;
        if (!insertion.second)
        {
            score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Duplicate connection while registering client_id="
                                       << client_id.value();
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
        }
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError()
            << "[MESSAGE_PASSING_SERVER] Allocation failed while registering connection for client_id="
            << client_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        score::mw::log::LogError()
            << "[MESSAGE_PASSING_SERVER] Unexpected failure while registering connection for client_id="
            << client_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    decltype(m_client_states)::iterator client_iterator;
    try
    {
        const auto client_result =
            m_client_states.try_emplace(client_id.value(), ClientState{uid, ClientLifecycleState::kConnectionActive});
        if (!client_result.second)
        {
            m_connections.erase(connection_iterator);
            score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Duplicate generated client_id="
                                       << client_id.value();
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
        }
        client_iterator = client_result.first;
    }
    catch (const std::bad_alloc&)
    {
        m_connections.erase(connection_iterator);
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Allocation failed while reserving client_id="
                                   << client_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        m_connections.erase(connection_iterator);
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Unexpected failure while reserving client_id="
                                   << client_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    try
    {
        const auto uid_result = m_reserved_connections_by_uid.try_emplace(uid, 0U);
        ++uid_result.first->second;
    }
    catch (const std::bad_alloc&)
    {
        m_connections.erase(connection_iterator);
        m_client_states.erase(client_iterator);
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Allocation failed while reserving UID for client_id="
                                   << client_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        m_connections.erase(connection_iterator);
        m_client_states.erase(client_iterator);
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Unexpected failure while reserving UID for client_id="
                                   << client_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    CommitClientId(lock, client_id.value());

    return {};
}

auto SessionRegistry::GenerateClientId(std::lock_guard<std::mutex>& lock, const uid_t uid) const noexcept
    -> score::crypto::Expected<ClientId, score::crypto::daemon::common::DaemonErrorCode>
{
    static_cast<void>(lock);
    auto candidate_generation = m_next_connection_generation;
    // Since we have at most kMaxTotalConnections, we shall always find a free ID within
    // kMaxTotalConnections attempts.
    for (std::size_t attempt{0U}; attempt <= ipc::kMaxTotalConnections; ++attempt)
    {
        const auto candidate_client_id =
            score::crypto::daemon::common::MakeClientId(candidate_generation, static_cast<std::uint32_t>(uid));
        if (m_client_states.find(candidate_client_id) == m_client_states.end())
        {
            return candidate_client_id;
        }
        ++candidate_generation;
        if (candidate_generation == 0U)
        {
            candidate_generation = 1U;
        }
    }
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
}

void SessionRegistry::CommitClientId(std::lock_guard<std::mutex>& lock, ClientId client_id) noexcept
{
    static_cast<void>(lock);
    const auto server_side_id = score::crypto::daemon::common::GetClientIdParts(client_id).opaque_id;
    m_next_connection_generation = server_side_id + 1U;
    if (m_next_connection_generation == 0U)
    {
        m_next_connection_generation = 1U;
    }
}

std::shared_ptr<detail::Session> SessionRegistry::DetachConnection(
    score::message_passing::IServerConnection& connection) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto iterator = m_connections.find(&connection);
    if (iterator == m_connections.end())
    {
        return {};
    }
    return DetachConnection(lock, iterator);
}

std::shared_ptr<detail::Session> SessionRegistry::DetachConnection(
    std::lock_guard<std::mutex>& lock,
    const ConnectionMap::iterator connection_iterator) noexcept
{
    static_cast<void>(lock);
    auto session = connection_iterator->second;
    const auto iterator = m_client_states.find(session->client_id());
    if ((iterator == m_client_states.end()) || (iterator->second.lifecycle != ClientLifecycleState::kConnectionActive))
    {
        score::mw::log::LogWarn() << "DetachConnection: Admission reservation was not active for client_id="
                                  << session->client_id();
        return session;
    }

    iterator->second.lifecycle = ClientLifecycleState::kCleanupPending;
    ++m_pending_disconnect_count;

    // Close session admission and responses before removing its transport mapping.
    session->BeginDisconnect();
    m_connections.erase(connection_iterator);

    return session;
}

std::shared_ptr<detail::Session> SessionRegistry::FindSessionForRequest(
    score::message_passing::IServerConnection& connection) const noexcept
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    const auto iterator = m_connections.find(&connection);
    return iterator == m_connections.end() ? nullptr : iterator->second;
}

void SessionRegistry::StartAcceptConnections() noexcept
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    m_accept_connections = true;
}

void SessionRegistry::StopAcceptConnections() noexcept
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    m_accept_connections = false;
}

score::crypto::Expected<std::vector<std::shared_ptr<detail::Session>>, score::crypto::daemon::common::DaemonErrorCode>
SessionRegistry::DetachAllConnections() noexcept
{
    std::vector<std::shared_ptr<detail::Session>> result;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_accept_connections = false;

        // Reserve the full snapshot before mutation so allocation failure leaves the registry intact.
        try
        {
            result.reserve(m_connections.size());
        }
        catch (const std::bad_alloc&)
        {
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
        }
        catch (...)
        {
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
        }

        while (!m_connections.empty())
        {
            result.push_back(DetachConnection(lock, m_connections.begin()));
        }
    }
    return result;
}

void SessionRegistry::WaitForAllConnectionsClosed() noexcept
{
    std::unique_lock<std::mutex> lock(m_mutex);
    m_all_connections_cleaned_up.wait(lock, [this] {
        return m_pending_disconnect_count == 0U;
    });
}

void SessionRegistry::OnCleanupFinished(const ClientId client_id, const bool cleanup_succeeded) noexcept
{
    bool all_cleaned_up{false};
    {
        const std::lock_guard<std::mutex> lock(m_mutex);

        const auto iterator = m_client_states.find(client_id);
        if ((iterator == m_client_states.end()) ||
            (iterator->second.lifecycle != ClientLifecycleState::kCleanupPending))
        {
            return;
        }
        if (!cleanup_succeeded)
        {
            iterator->second.lifecycle = ClientLifecycleState::kConnectionQuarantined;
        }
        else
        {
            const auto uid_reservation = m_reserved_connections_by_uid.find(iterator->second.uid);
            if ((uid_reservation == m_reserved_connections_by_uid.end()) || (uid_reservation->second == 0U))
            {
                score::mw::log::LogError() << "Cleanup completion found no UID reservation for client_id=" << client_id;
                iterator->second.lifecycle = ClientLifecycleState::kConnectionQuarantined;
            }
            else
            {
                m_client_states.erase(iterator);
                --uid_reservation->second;
                if (uid_reservation->second == 0U)
                {
                    m_reserved_connections_by_uid.erase(uid_reservation);
                }
            }
        }

        if (m_pending_disconnect_count > 0U)
        {
            --m_pending_disconnect_count;
        }
        if (m_pending_disconnect_count == 0U)
        {
            all_cleaned_up = true;
        }
    }
    if (all_cleaned_up)
    {
        m_all_connections_cleaned_up.notify_all();
    }
}

}  // namespace score::crypto::ipc::message_passing
