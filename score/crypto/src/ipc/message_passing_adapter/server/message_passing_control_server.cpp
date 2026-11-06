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

#include "score/crypto/src/ipc/message_passing_adapter/server/message_passing_control_server.h"

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/ipc_config.h"

#include "score/message_passing/service_protocol_config.h"
#include "score/mw/log/logging.h"
#include "score/os/errno.h"

#include <cerrno>
#include <new>
#include <utility>

namespace score::crypto::ipc::message_passing
{
namespace
{

score::os::Error MapCryptoErrorToOsError(const score::crypto::CryptoErrorCode error) noexcept
{
    switch (error)
    {
        case score::crypto::CryptoErrorCode::kAccessDenied:
            return score::os::Error::createFromErrno(EACCES);
        case score::crypto::CryptoErrorCode::kProviderBusy:
            return score::os::Error::createFromErrno(EAGAIN);
        case score::crypto::CryptoErrorCode::kAllocationFailed:
            return score::os::Error::createFromErrno(ENOMEM);
        case score::crypto::CryptoErrorCode::kInvalidArgument:
        case score::crypto::CryptoErrorCode::kInvalidFormat:
            return score::os::Error::createFromErrno(EINVAL);
        case score::crypto::CryptoErrorCode::kConnectionFailed:
            return score::os::Error::createFromErrno(EPIPE);
        default:
            return score::os::Error::createFromErrno(EIO);
    }
}

}  // namespace

score::message_passing::IServerFactory::ServerConfig MessagePassingControlServer::BuildServerConfig() noexcept
{
    score::message_passing::IServerFactory::ServerConfig config{};
    config.max_queued_sends = ipc::kMaxTotalConnections;
    config.pre_alloc_connections = ipc::kMaxTotalConnections;
    config.max_queued_notifies = ipc::kServerNotificationCapacityPerConnection;
    return config;
}

score::message_passing::ServiceProtocolConfig MessagePassingControlServer::BuildProtocolConfig(
    const std::string_view service_identifier) noexcept
{
    return score::message_passing::ServiceProtocolConfig{
        service_identifier,
        ipc::kMaxPayloadBytes,
        0U,
        ipc::kMaxPayloadBytes,
    };
}

score::crypto::Expected<std::unique_ptr<MessagePassingControlServer>, score::crypto::daemon::common::DaemonErrorCode>
MessagePassingControlServer::Create(std::unique_ptr<daemon::control_plane::IHandlerChainFactory> factory,
                                    AuthorizationCallback authorization,
                                    DisconnectCleanupCallback cleanup_callback) noexcept
{
    if (factory == nullptr)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Cannot create server without a handler-chain factory";
        return score::crypto::make_unexpected(daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    // Construction allocates server state and maps failures to the public creation error.
    try
    {
        return std::unique_ptr<MessagePassingControlServer>{
            new MessagePassingControlServer{std::move(factory), std::move(authorization), std::move(cleanup_callback)}};
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Allocation failed while creating server";
        return score::crypto::make_unexpected(daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    catch (...)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Unexpected failure while creating server";
        return score::crypto::make_unexpected(daemon::common::DaemonErrorCode::kInternalError);
    }
}

MessagePassingControlServer::MessagePassingControlServer(
    std::unique_ptr<daemon::control_plane::IHandlerChainFactory> factory,
    AuthorizationCallback authorization,
    DisconnectCleanupCallback cleanup_callback)
    : m_server_factory(std::make_unique<score::message_passing::ServerFactory>()),
      m_handler_chain_factory(std::move(factory)),
      m_work_item_executor(ipc::kWorkerThreads, ipc::kCleanupQueueCapacity),
      m_codec{},
      m_session_manager(m_work_item_executor, std::move(authorization), std::move(cleanup_callback)),
      m_work_item_dispatcher(m_session_manager, m_work_item_executor, m_codec)
{
}

MessagePassingControlServer::~MessagePassingControlServer() noexcept
{
    Stop();
    m_work_item_executor.Shutdown();
    m_work_item_executor.Join();
}

void MessagePassingControlServer::RollbackStartup() noexcept
{
    if (m_message_server != nullptr)
    {
        static_cast<void>(m_message_server->StopListening());
    }
    m_message_server.reset();
    m_session_manager.StopAcceptConnections();
    const auto drain_result = m_session_manager.DrainConnections();
    if (!drain_result.has_value())
    {
        score::mw::log::LogError()
            << "[MESSAGE_PASSING_SERVER] Failed to drain connections during startup rollback (error="
            << static_cast<int>(drain_result.error()) << ")";
    }
    m_work_item_executor.Shutdown();
    m_work_item_executor.Join();

    static_cast<void>(m_server_state_machine.MarkStopped());
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
MessagePassingControlServer::Start(std::string_view service_identifier) noexcept
{
    if (!m_server_state_machine.TryBeginStart().has_value())
    {
        return score::crypto::make_unexpected(daemon::common::DaemonErrorCode::kAlreadyInitialized);
    }
    auto startup_error = daemon::common::DaemonErrorCode::kInternalError;
    // Startup spans several resources; exceptions must trigger rollback before returning failure.
    try
    {
        m_message_server = m_server_factory->Create(BuildProtocolConfig(service_identifier), BuildServerConfig());
        auto startup_failed = m_message_server == nullptr;
        if (startup_failed)
        {
            startup_error = daemon::common::DaemonErrorCode::kConnectionFailed;
            score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Server factory returned no server instance";
        }

        if (!startup_failed)
        {
            startup_failed = !m_work_item_executor.Start([this] {
                return m_handler_chain_factory->CreateRequestHandler();
            });
        }

        if (!startup_failed)
        {
            m_session_manager.StartAcceptConnections();
            const auto listening_result = m_message_server->StartListening(
                [this](score::message_passing::IServerConnection& connection) {
                    return OnConnect(connection);
                },
                [this](score::message_passing::IServerConnection& connection) {
                    OnDisconnect(connection);
                },
                [this](score::message_passing::IServerConnection& connection,
                       score::cpp::span<const std::uint8_t> message) {
                    return OnRequest(connection, message);
                },
                [](score::message_passing::IServerConnection&,
                   score::cpp::span<const std::uint8_t>) -> score::cpp::expected_blank<score::os::Error> {
                    return score::cpp::make_unexpected(score::os::Error::createFromErrno(ENOTSUP));
                });
            startup_failed = !listening_result.has_value();
            if (startup_failed)
            {
                startup_error = daemon::common::DaemonErrorCode::kConnectionFailed;
                score::mw::log::LogError()
                    << "[MESSAGE_PASSING_SERVER] Failed to start listening on service=" << service_identifier;
            }
        }

        if (!startup_failed)
        {
            static_cast<void>(m_server_state_machine.MarkStarted());
            return std::monostate{};
        }
    }
    catch (const std::bad_alloc&)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Allocation failed during startup for service="
                                   << service_identifier;
        startup_error = daemon::common::DaemonErrorCode::kAllocationFailed;
    }
    catch (...)
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Unexpected exception during startup for service="
                                   << service_identifier;
        startup_error = daemon::common::DaemonErrorCode::kInternalError;
    }
    RollbackStartup();
    return score::crypto::make_unexpected(startup_error);
}

score::cpp::expected<score::message_passing::UserData, score::os::Error> MessagePassingControlServer::OnConnect(
    score::message_passing::IServerConnection& connection) noexcept
{
    auto result = m_session_manager.OnConnect(connection);
    if (!result.has_value())
    {
        return score::cpp::make_unexpected(
            MapCryptoErrorToOsError(score::crypto::daemon::common::ToCryptoErrorCode(result.error())));
    }
    const pid_t client_pid = connection.GetClientIdentity().pid;
    return {static_cast<std::uintptr_t>(client_pid)};
}

void MessagePassingControlServer::OnDisconnect(score::message_passing::IServerConnection& connection) noexcept
{
    m_session_manager.OnDisconnect(connection);
}

score::cpp::expected_blank<score::os::Error> MessagePassingControlServer::OnRequest(
    score::message_passing::IServerConnection& connection,
    const score::cpp::span<const std::uint8_t> message) noexcept
{
    const auto result = m_work_item_dispatcher.OnRequest(connection, message);
    if (!result.has_value())
    {
        return score::cpp::make_unexpected(
            MapCryptoErrorToOsError(score::crypto::daemon::common::ToCryptoErrorCode(result.error())));
    }
    return {};
}

void MessagePassingControlServer::Stop() noexcept
{
    if (!m_server_state_machine.BeginStopping())
    {
        return;
    }
    m_session_manager.StopAcceptConnections();
    if (m_message_server != nullptr)
    {
        m_message_server->StopListening();
    }
    const auto drain_result = m_session_manager.DrainConnections();
    if (!drain_result.has_value())
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Failed to drain connections during stop (error="
                                   << static_cast<int>(drain_result.error()) << ")";
    }
}

void MessagePassingControlServer::WaitForTermination() noexcept
{
    m_session_manager.WaitForAllConnectionsClosed();
    m_work_item_executor.Shutdown();
    m_work_item_executor.Join();
    m_session_manager.StopAcceptConnections();
    m_message_server.reset();
    static_cast<void>(m_server_state_machine.MarkStopped());
}

}  // namespace score::crypto::ipc::message_passing
