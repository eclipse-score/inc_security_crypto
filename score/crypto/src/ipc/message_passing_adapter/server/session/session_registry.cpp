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

#include "score/crypto/src/ipc/message_passing_adapter/ipc_config.h"

#include "score/mw/log/logging.h"

#include <array>
#include <optional>
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
    std::lock_guard<std::mutex> lock(mutex_);
    if (!admissions_enabled_)
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
    return client_states_.size() < ipc::kMaxTotalConnections;
}

bool SessionRegistry::NewConnectionFitsInUidCapacity(std::lock_guard<std::mutex>& lock, const uid_t uid) const noexcept
{
    const auto iterator = reserved_connections_by_uid_.find(uid);
    return (iterator == reserved_connections_by_uid_.end()) || (iterator->second < ipc::kMaxConnectionsPerUid);
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

    decltype(connections_)::iterator connection_iterator;
    // The connection registry insertion may allocate before the admission gate is committed.
    try
    {
        const auto insertion = connections_.try_emplace(&connection, session);
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

    decltype(client_states_)::iterator client_iterator;
    try
    {
        const auto client_result =
            client_states_.try_emplace(client_id.value(), ClientState{uid, ClientLifecycleState::kConnectionActive});
        if (!client_result.second)
        {
            connections_.erase(connection_iterator);
            score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Duplicate generated client_id="
                                       << client_id.value();
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
        }
        client_iterator = client_result.first;
    }
    catch (const std::bad_alloc&)
    {
        connections_.erase(connection_iterator);
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Allocation failed while reserving client_id="
                                   << client_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        connections_.erase(connection_iterator);
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Unexpected failure while reserving client_id="
                                   << client_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    try
    {
        const auto uid_result = reserved_connections_by_uid_.try_emplace(uid, 0U);
        ++uid_result.first->second;
    }
    catch (const std::bad_alloc&)
    {
        connections_.erase(connection_iterator);
        client_states_.erase(client_iterator);
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Allocation failed while reserving UID for client_id="
                                   << client_id.value();
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        connections_.erase(connection_iterator);
        client_states_.erase(client_iterator);
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
    auto candidate_generation = next_connection_generation_;
    // Since we have at most kMaxTotalConnections, we shall always find a free ID within
    // kMaxTotalConnections attempts.
    for (std::size_t attempt{0U}; attempt <= ipc::kMaxTotalConnections; ++attempt)
    {
        auto candidate_client_id = (static_cast<ClientId>(uid) << 32U) | static_cast<ClientId>(candidate_generation);
        if (client_states_.find(candidate_client_id) == client_states_.end())
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
    // TODO: Improve this
    const auto server_side_id = static_cast<std::uint32_t>(client_id & 0xFFFFFFFFU);
    next_connection_generation_ = server_side_id + 1U;
    if (next_connection_generation_ == 0U)
    {
        next_connection_generation_ = 1U;
    }
}

std::shared_ptr<detail::Session> SessionRegistry::DetachConnection(
    score::message_passing::IServerConnection& connection) noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);
    const auto iterator = connections_.find(&connection);
    if (iterator == connections_.end())
    {
        return {};
    }
    return DetachConnection(lock, iterator);
}

std::shared_ptr<detail::Session> SessionRegistry::DetachConnection(
    std::lock_guard<std::mutex>& lock,
    const ConnectionMap::iterator connection_iterator) noexcept
{
    auto session = std::move(connection_iterator->second);
    connections_.erase(connection_iterator);
    ++pending_disconnect_count_;

    const auto iterator = client_states_.find(session->client_id());
    if ((iterator == client_states_.end()) || (iterator->second.lifecycle != ClientLifecycleState::kConnectionActive))
    {
        score::mw::log::LogWarn() << "DetachConnection: Admission reservation was not active for client_id="
                                  << session->client_id();
        return session;
    }
    iterator->second.lifecycle = ClientLifecycleState::kCleanupPending;

    return session;
}

std::shared_ptr<detail::Session> SessionRegistry::FindSessionForRequest(
    score::message_passing::IServerConnection& connection) const noexcept
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto iterator = connections_.find(&connection);
    return iterator == connections_.end() ? nullptr : iterator->second;
}

void SessionRegistry::EnableAdmissions() noexcept
{
    const std::lock_guard<std::mutex> lock(mutex_);
    admissions_enabled_ = true;
}

void SessionRegistry::DisableAdmissions() noexcept
{
    const std::lock_guard<std::mutex> lock(mutex_);
    admissions_enabled_ = false;
}

score::crypto::Expected<std::vector<std::shared_ptr<detail::Session>>, score::crypto::daemon::common::DaemonErrorCode>
SessionRegistry::DetachAllConnections() noexcept
{
    std::vector<std::shared_ptr<detail::Session>> result;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        admissions_enabled_ = false;

        // Reserve the full snapshot before mutation so allocation failure leaves the registry intact.
        try
        {
            result.reserve(connections_.size());
        }
        catch (const std::bad_alloc&)
        {
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
        }
        catch (...)
        {
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
        }

        while (!connections_.empty())
        {
            result.push_back(DetachConnection(lock, connections_.begin()));
        }
    }
    return result;
}

void SessionRegistry::WaitForAllConnectionsClosed() noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);
    disconnect_condition_.wait(lock, [this] {
        return pending_disconnect_count_ == 0U;
    });
}

void SessionRegistry::OnCleanupFinished(const ClientId client_id, const bool cleanup_succeeded) noexcept
{
    bool completed{false};
    {
        const std::lock_guard<std::mutex> lock(mutex_);

        const auto iterator = client_states_.find(client_id);
        if ((iterator == client_states_.end()) || (iterator->second.lifecycle != ClientLifecycleState::kCleanupPending))
        {
            return;
        }
        if (!cleanup_succeeded)
        {
            iterator->second.lifecycle = ClientLifecycleState::kConnectionQuarantined;
        }
        else
        {
            const auto uid_reservation = reserved_connections_by_uid_.find(iterator->second.uid);
            if ((uid_reservation == reserved_connections_by_uid_.end()) || (uid_reservation->second == 0U))
            {
                score::mw::log::LogError() << "Cleanup completion found no UID reservation for client_id=" << client_id;
                iterator->second.lifecycle = ClientLifecycleState::kConnectionQuarantined;
            }
            else
            {
                client_states_.erase(iterator);
                --uid_reservation->second;
                if (uid_reservation->second == 0U)
                {
                    reserved_connections_by_uid_.erase(uid_reservation);
                }
            }
        }

        if (pending_disconnect_count_ > 0U)
        {
            --pending_disconnect_count_;
        }
        completed = true;
    }
    if (completed)
    {
        disconnect_condition_.notify_all();
    }
}

}  // namespace score::crypto::ipc::message_passing
