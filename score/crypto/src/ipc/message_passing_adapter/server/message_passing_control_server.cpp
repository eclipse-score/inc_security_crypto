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
    : server_factory_(std::make_unique<score::message_passing::ServerFactory>()),
      handler_chain_factory_(std::move(factory)),
      work_item_executor_(ipc::kWorkerThreads, ipc::kCleanupQueueCapacity),
      codec_{},
      session_manager_(work_item_executor_, std::move(authorization), std::move(cleanup_callback)),
      work_item_dispatcher_(session_manager_, work_item_executor_, codec_)
{
}

MessagePassingControlServer::~MessagePassingControlServer() noexcept
{
    Stop();
    work_item_executor_.Shutdown();
    work_item_executor_.Join();
}

void MessagePassingControlServer::RollbackStartup() noexcept
{
    if (message_server_ != nullptr)
    {
        static_cast<void>(message_server_->StopListening());
    }
    message_server_.reset();
    session_manager_.DisableAdmissions();
    const auto drain_result = session_manager_.DrainConnections();
    if (!drain_result.has_value())
    {
        score::mw::log::LogError()
            << "[MESSAGE_PASSING_SERVER] Failed to drain connections during startup rollback (error="
            << static_cast<int>(drain_result.error()) << ")";
    }
    work_item_executor_.Shutdown();
    work_item_executor_.Join();
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
MessagePassingControlServer::Start(std::string_view service_identifier) noexcept
{
    auto start_guard = lifecycle_.TryBeginStart();
    if (!start_guard.has_value())
    {
        return score::crypto::make_unexpected(daemon::common::DaemonErrorCode::kAlreadyInitialized);
    }
    auto startup_error = daemon::common::DaemonErrorCode::kInternalError;
    // Startup spans several resources; exceptions must trigger rollback before returning failure.
    try
    {
        message_server_ = server_factory_->Create(BuildProtocolConfig(service_identifier), BuildServerConfig());
        auto startup_failed = message_server_ == nullptr;
        if (startup_failed)
        {
            startup_error = daemon::common::DaemonErrorCode::kConnectionFailed;
            score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Server factory returned no server instance";
        }

        if (!startup_failed)
        {
            startup_failed = !work_item_executor_.Start([this] {
                return handler_chain_factory_->CreateRequestHandler();
            });
        }

        if (!startup_failed)
        {
            session_manager_.EnableAdmissions();
            const auto listening_result = message_server_->StartListening(
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
            lifecycle_.MarkStarted(*start_guard);
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
    auto result = session_manager_.OnConnect(connection);
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
    session_manager_.OnDisconnect(connection);
}

score::cpp::expected_blank<score::os::Error> MessagePassingControlServer::OnRequest(
    score::message_passing::IServerConnection& connection,
    const score::cpp::span<const std::uint8_t> message) noexcept
{
    const auto result = work_item_dispatcher_.OnRequest(connection, message);
    if (!result.has_value())
    {
        return score::cpp::make_unexpected(
            MapCryptoErrorToOsError(score::crypto::daemon::common::ToCryptoErrorCode(result.error())));
    }
    return {};
}

void MessagePassingControlServer::Stop() noexcept
{
    if (!lifecycle_.BeginStopping())
    {
        return;
    }
    session_manager_.DisableAdmissions();
    if (message_server_ != nullptr)
    {
        message_server_->StopListening();
    }
    const auto drain_result = session_manager_.DrainConnections();
    if (!drain_result.has_value())
    {
        score::mw::log::LogError() << "[MESSAGE_PASSING_SERVER] Failed to drain connections during stop (error="
                                   << static_cast<int>(drain_result.error()) << ")";
    }
}

void MessagePassingControlServer::WaitForTermination() noexcept
{
    session_manager_.WaitForAllConnectionsClosed();
    work_item_executor_.Shutdown();
    work_item_executor_.Join();
    session_manager_.DisableAdmissions();
    message_server_.reset();
    lifecycle_.MarkStopped();
}

}  // namespace score::crypto::ipc::message_passing
