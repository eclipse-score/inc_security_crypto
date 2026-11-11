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
#ifndef SCORE_CRYPTO_IPC_MESSAGE_PASSING_CONTROL_SERVER_H
#define SCORE_CRYPTO_IPC_MESSAGE_PASSING_CONTROL_SERVER_H

#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/i_control_server.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/server_callbacks.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/server_state_machine.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/session/session_manager.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/session/work_item_dispatcher.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/work_item_execution/fixed_worker_work_item_executor.h"
#include "score/crypto/src/ipc/protocol/flatbuffer_codec.h"

#include <score/memory.hpp>
#include <score/span.hpp>

#include "score/message_passing/server_factory.h"

#include <cstdint>
#include <memory>
#include <string_view>

namespace score::crypto::daemon::control_plane
{
class IHandlerChainFactory;
}  // namespace score::crypto::daemon::control_plane

namespace score::message_passing
{
class IServerConnection;
class ServiceProtocolConfig;
}  // namespace score::message_passing

namespace score::crypto::ipc::message_passing
{

/**
 * @brief
 * Hosts the control protocol over SCORE message passing.
 * Composes transport callbacks, connection/session management, request dispatch, the wire codec,
 * and bounded worker execution behind the daemon's control-server interface.
 * @endrst
 */
class MessagePassingControlServer final : public daemon::control_plane::IControlServer
{
  public:
    using AuthorizationCallback = ::score::crypto::ipc::message_passing::AuthorizationCallback;
    using DisconnectCleanupCallback = ::score::crypto::ipc::message_passing::DisconnectCleanupCallback;

    static score::crypto::Expected<std::unique_ptr<MessagePassingControlServer>,
                                   score::crypto::daemon::common::DaemonErrorCode>
    Create(std::unique_ptr<daemon::control_plane::IHandlerChainFactory> factory,
           const daemon::config::IPCConfig& config,
           AuthorizationCallback authorization = {},
           DisconnectCleanupCallback cleanup_callback = {}) noexcept;
    ~MessagePassingControlServer() noexcept override;

    MessagePassingControlServer(const MessagePassingControlServer&) = delete;
    MessagePassingControlServer& operator=(const MessagePassingControlServer&) = delete;
    MessagePassingControlServer(MessagePassingControlServer&&) = delete;
    MessagePassingControlServer& operator=(MessagePassingControlServer&&) = delete;

    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    Start() noexcept override;
    void Stop() noexcept override;
    void WaitForTermination() noexcept override;

  private:
    MessagePassingControlServer(std::unique_ptr<daemon::control_plane::IHandlerChainFactory> factory,
                                const daemon::config::IPCConfig& config,
                                AuthorizationCallback authorization,
                                DisconnectCleanupCallback cleanup_callback);

    static score::message_passing::IServerFactory::ServerConfig BuildServerConfig() noexcept;
    static score::message_passing::ServiceProtocolConfig BuildProtocolConfig(std::string_view endpoint) noexcept;

    score::cpp::expected<score::message_passing::UserData, score::os::Error> OnConnect(
        score::message_passing::IServerConnection& connection) noexcept;
    void OnDisconnect(score::message_passing::IServerConnection& connection) noexcept;
    score::cpp::expected_blank<score::os::Error> OnRequest(score::message_passing::IServerConnection& connection,
                                                           score::cpp::span<const std::uint8_t> message) noexcept;
    void RollbackStartup() noexcept;

    // The score::message_passing server-factory holds the memory resources for the server.
    // Keep the factory alive until m_message_server is destroyed.
    std::unique_ptr<score::message_passing::ServerFactory> m_server_factory;
    score::cpp::pmr::unique_ptr<score::message_passing::IServer> m_message_server;
    std::unique_ptr<daemon::control_plane::IHandlerChainFactory> m_handler_chain_factory;
    daemon::config::IPCConfig m_ipc_config;

    FixedWorkerWorkItemExecutor m_work_item_executor;
    score::crypto::ipc::protocol::FlatBufferCodec m_codec;
    SessionManager m_session_manager;
    WorkItemDispatcher m_work_item_dispatcher;

    ServerStateMachine m_server_state_machine;
};

}  // namespace score::crypto::ipc::message_passing

#endif  // SCORE_CRYPTO_IPC_MESSAGE_PASSING_CONTROL_SERVER_H
