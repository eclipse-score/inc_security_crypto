/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#include "score/crypto/src/ipc/tests/message_passing_adapter_integration_test_process_separation_common.h"

#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/control_plane/i_handler_chain_factory.hpp"
#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/server/message_passing_control_server.h"

#include <gtest/gtest.h>

#include <pthread.h>
#include <unistd.h>
#include <signal.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>
#include <utility>

namespace
{

namespace process_test = score::crypto::ipc::message_passing::process_test;
namespace protocol = score::crypto::daemon::control_plane::protocol;
using DaemonErrorCode = score::crypto::daemon::common::DaemonErrorCode;

score::crypto::daemon::config::IPCConfig MakeIPCConfig(const std::string_view endpoint)
{
    score::crypto::daemon::config::IPCConfig config{};
    config.SetEndpoint(endpoint);
    return config;
}

class DisconnectCleanupObserver final
{
  public:
    void Record() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_cleanup_called = true;
        }
        m_condition.notify_one();
    }

    bool WaitForCleanup(const std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_condition.wait_for(lock, timeout, [this] {
            return m_cleanup_called;
        });
    }

  private:
    std::mutex m_mutex{};
    std::condition_variable m_condition{};
    bool m_cleanup_called{false};
};

class EchoRequestHandler final : public score::crypto::daemon::control_plane::IRequestHandler
{
  public:
    score::crypto::daemon::control_plane::ControlResponse processRequest(
        score::crypto::daemon::control_plane::ControlRequest& request) override
    {
        return ProcessRequest(request);
    }

  private:
    score::crypto::daemon::control_plane::ControlResponse ProcessRequest(
        score::crypto::daemon::control_plane::ControlRequest& request)
    {
        protocol::ControlResponse response{};
        response.request_id = request.request_id;
        for (const auto& operation : request.operations)
        {
            const auto input = operation.getParameter<std::uint64_t>(0U);
            if (!input.has_value())
            {
                response.operations.push_back(protocol::SingleOperationResponse{
                    operation.operationId,
                    static_cast<protocol::OperationResult>(score::crypto::CryptoErrorCode::kInvalidArgument),
                    {}});
                continue;
            }
            if (input.value() == process_test::kLongRunningOperationValue)
            {
                std::cout << "SERVER_TIMEOUT_HANDLER_BLOCKED\n" << std::flush;
                std::this_thread::sleep_for(std::chrono::seconds{3});
                response.operations.push_back(protocol::SingleOperationResponse{
                    operation.operationId,
                    static_cast<protocol::OperationResult>(score::crypto::CryptoErrorCode::kOperationTimedOut),
                    {}});
                continue;
            }
            response.operations.push_back(protocol::SingleOperationResponse{
                operation.operationId, protocol::OPERATION_RESULT_SUCCESS, {input.value()}});
        }
        return response;
    }
};

class EchoHandlerFactory final : public score::crypto::daemon::control_plane::IHandlerChainFactory
{
  public:
    std::unique_ptr<score::crypto::daemon::control_plane::IRequestHandler> CreateRequestHandler() override
    {
        return std::make_unique<EchoRequestHandler>();
    }
};

}  // namespace

TEST(MessagePassingServerProcessTest, StopsAfterTerminationSignal)
{
    const char* service_identifier_env = std::getenv("MESSAGE_PASSING_SERVICE_ID");
    const std::string_view service_identifier = (service_identifier_env == nullptr)
                                                    ? process_test::kServiceIdentifier
                                                    : std::string_view{service_identifier_env};
    ASSERT_FALSE(service_identifier.empty());

    sigset_t shutdown_signals{};
    ASSERT_EQ(::sigemptyset(&shutdown_signals), 0);
    ASSERT_EQ(::sigaddset(&shutdown_signals, SIGINT), 0);
    ASSERT_EQ(::sigaddset(&shutdown_signals, SIGTERM), 0);

    const auto signal_mask_result = ::pthread_sigmask(SIG_BLOCK, &shutdown_signals, nullptr);
    ASSERT_EQ(signal_mask_result, 0) << "Failed to block shutdown signals";

    const auto ipc_config = MakeIPCConfig(service_identifier);
    auto server_result = score::crypto::ipc::message_passing::MessagePassingControlServer::Create(
        std::make_unique<EchoHandlerFactory>(),
        ipc_config,
        [](const auto, const auto) -> score::crypto::Expected<bool, DaemonErrorCode> {
            return score::crypto::Expected<bool, DaemonErrorCode>{true};
        });
    ASSERT_TRUE(server_result.has_value()) << "Failed to create message-passing server";
    auto server = std::move(server_result).value();
    const auto start_result = server->Start();
    ASSERT_TRUE(start_result.has_value()) << "Failed to start message-passing server";

    std::cout << "SERVER_READY\n" << std::flush;
    int received_signal{0};
    const auto wait_result = ::sigwait(&shutdown_signals, &received_signal);
    server->Stop();
    server->WaitForTermination();
    ASSERT_EQ(wait_result, 0) << "Failed while waiting for shutdown signal";
    EXPECT_EQ(received_signal, SIGTERM);
}

TEST(MessagePassingServerProcessTest, DeniesClientMatchingServerUid)
{
    const char* service_identifier_env = std::getenv("MESSAGE_PASSING_SERVICE_ID");
    const std::string_view service_identifier = (service_identifier_env == nullptr)
                                                    ? process_test::kServiceIdentifier
                                                    : std::string_view{service_identifier_env};
    ASSERT_FALSE(service_identifier.empty());

    sigset_t shutdown_signals{};
    ASSERT_EQ(::sigemptyset(&shutdown_signals), 0);
    ASSERT_EQ(::sigaddset(&shutdown_signals, SIGINT), 0);
    ASSERT_EQ(::sigaddset(&shutdown_signals, SIGTERM), 0);
    const auto signal_mask_result = ::pthread_sigmask(SIG_BLOCK, &shutdown_signals, nullptr);
    ASSERT_EQ(signal_mask_result, 0) << "Failed to block shutdown signals";

    const auto server_uid = ::getuid();
    std::atomic<bool> authorization_callback_invoked{false};
    std::atomic<uid_t> observed_client_uid{};
    const auto authorization_callback = [&server_uid, &authorization_callback_invoked, &observed_client_uid](
                                            const uid_t client_uid, const gid_t) {
        observed_client_uid.store(client_uid, std::memory_order_relaxed);
        authorization_callback_invoked.store(true, std::memory_order_release);
        return score::crypto::Expected<bool, DaemonErrorCode>{client_uid != server_uid};
    };

    const auto ipc_config = MakeIPCConfig(service_identifier);
    auto server_result = score::crypto::ipc::message_passing::MessagePassingControlServer::Create(
        std::make_unique<EchoHandlerFactory>(), ipc_config, authorization_callback);
    ASSERT_TRUE(server_result.has_value()) << "Failed to create message-passing server";
    auto server = std::move(server_result).value();
    const auto start_result = server->Start();
    ASSERT_TRUE(start_result.has_value()) << "Failed to start message-passing server";

    std::cout << "SERVER_READY\n" << std::flush;
    int received_signal{0};
    const auto wait_result = ::sigwait(&shutdown_signals, &received_signal);
    server->Stop();
    server->WaitForTermination();
    ASSERT_EQ(wait_result, 0) << "Failed while waiting for shutdown signal";
    ASSERT_TRUE(authorization_callback_invoked.load(std::memory_order_acquire))
        << "Authorization callback was not invoked";
    EXPECT_EQ(observed_client_uid.load(std::memory_order_relaxed), server_uid);
    EXPECT_EQ(received_signal, SIGTERM);
}

TEST(MessagePassingServerProcessTest, AuthorizesConnectionsByEffectiveUid)
{
    const char* service_identifier_env = std::getenv("MESSAGE_PASSING_SERVICE_ID");
    const std::string_view service_identifier = (service_identifier_env == nullptr)
                                                    ? process_test::kServiceIdentifier
                                                    : std::string_view{service_identifier_env};
    ASSERT_FALSE(service_identifier.empty());

    sigset_t shutdown_signals{};
    ASSERT_EQ(::sigemptyset(&shutdown_signals), 0);
    ASSERT_EQ(::sigaddset(&shutdown_signals, SIGINT), 0);
    ASSERT_EQ(::sigaddset(&shutdown_signals, SIGTERM), 0);
    const auto signal_mask_result = ::pthread_sigmask(SIG_BLOCK, &shutdown_signals, nullptr);
    ASSERT_EQ(signal_mask_result, 0) << "Failed to block shutdown signals";

    std::atomic<bool> allowed_uid_observed{false};
    std::atomic<bool> denied_uid_observed{false};
    const auto authorization_callback = [&allowed_uid_observed, &denied_uid_observed](const uid_t client_uid,
                                                                                      const gid_t) {
        if (client_uid == static_cast<uid_t>(process_test::kAllowedNonRootUid))
        {
            allowed_uid_observed.store(true, std::memory_order_release);
            return score::crypto::Expected<bool, DaemonErrorCode>{true};
        }
        if (client_uid == static_cast<uid_t>(process_test::kDeniedNonRootUid))
        {
            denied_uid_observed.store(true, std::memory_order_release);
        }
        return score::crypto::Expected<bool, DaemonErrorCode>{false};
    };

    const auto ipc_config = MakeIPCConfig(service_identifier);
    auto server_result = score::crypto::ipc::message_passing::MessagePassingControlServer::Create(
        std::make_unique<EchoHandlerFactory>(), ipc_config, authorization_callback);
    ASSERT_TRUE(server_result.has_value()) << "Failed to create message-passing server";
    auto server = std::move(server_result).value();
    const auto start_result = server->Start();
    ASSERT_TRUE(start_result.has_value()) << "Failed to start message-passing server";

    std::cout << "SERVER_READY\n" << std::flush;
    int received_signal{0};
    const auto wait_result = ::sigwait(&shutdown_signals, &received_signal);
    server->Stop();
    server->WaitForTermination();
    ASSERT_EQ(wait_result, 0) << "Failed while waiting for shutdown signal";
    EXPECT_TRUE(allowed_uid_observed.load(std::memory_order_acquire))
        << "The server did not observe the allowed non-root UID";
    EXPECT_TRUE(denied_uid_observed.load(std::memory_order_acquire))
        << "The server did not observe the denied non-root UID on the new connection";
    EXPECT_EQ(received_signal, SIGTERM);
}

TEST(MessagePassingServerProcessTest, RunsCleanupAfterClientProcessDisconnects)
{
    const char* service_identifier_env = std::getenv("MESSAGE_PASSING_SERVICE_ID");
    const std::string_view service_identifier = (service_identifier_env == nullptr)
                                                    ? process_test::kServiceIdentifier
                                                    : std::string_view{service_identifier_env};
    ASSERT_FALSE(service_identifier.empty());

    sigset_t shutdown_signals{};
    ASSERT_EQ(::sigemptyset(&shutdown_signals), 0);
    ASSERT_EQ(::sigaddset(&shutdown_signals, SIGINT), 0);
    ASSERT_EQ(::sigaddset(&shutdown_signals, SIGTERM), 0);
    const auto signal_mask_result = ::pthread_sigmask(SIG_BLOCK, &shutdown_signals, nullptr);
    ASSERT_EQ(signal_mask_result, 0) << "Failed to block shutdown signals";

    const auto cleanup_observer = std::make_shared<DisconnectCleanupObserver>();
    const auto ipc_config = MakeIPCConfig(service_identifier);
    auto server_result = score::crypto::ipc::message_passing::MessagePassingControlServer::Create(
        std::make_unique<EchoHandlerFactory>(),
        ipc_config,
        [](const auto, const auto) -> score::crypto::Expected<bool, DaemonErrorCode> {
            return score::crypto::Expected<bool, DaemonErrorCode>{true};
        },
        [cleanup_observer](const auto) -> score::crypto::Expected<std::monostate, DaemonErrorCode> {
            cleanup_observer->Record();
            return score::crypto::Expected<std::monostate, DaemonErrorCode>{std::monostate{}};
        });
    ASSERT_TRUE(server_result.has_value()) << "Failed to create message-passing server";
    auto server = std::move(server_result).value();
    const auto start_result = server->Start();
    ASSERT_TRUE(start_result.has_value()) << "Failed to start message-passing server";

    std::cout << "SERVER_READY\n" << std::flush;
    const auto cleanup_called = cleanup_observer->WaitForCleanup(std::chrono::seconds{20});
    if (cleanup_called)
    {
        std::cout << "SERVER_CLEANUP_DONE\n" << std::flush;
    }

    int received_signal{0};
    const auto wait_result = ::sigwait(&shutdown_signals, &received_signal);
    server->Stop();
    server->WaitForTermination();
    ASSERT_EQ(wait_result, 0) << "Failed while waiting for shutdown signal";
    ASSERT_TRUE(cleanup_called) << "Disconnect cleanup callback did not run before timeout";
    EXPECT_EQ(received_signal, SIGTERM);
}
