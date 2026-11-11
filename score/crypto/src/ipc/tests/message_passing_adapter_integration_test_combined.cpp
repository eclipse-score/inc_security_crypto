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

#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/control_plane/i_handler_chain_factory.hpp"
#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/src/ipc/message_passing_adapter/client/message_passing_control_client.h"
#include "score/crypto/src/ipc/message_passing_adapter/ipc_config.h"
#include "score/crypto/src/ipc/message_passing_adapter/server/message_passing_control_server.h"

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace score::crypto::ipc::message_passing
{
namespace
{

namespace protocol = daemon::control_plane::protocol;
using DaemonErrorCode = score::crypto::daemon::common::DaemonErrorCode;
using ClientResult = score::crypto::Expected<protocol::ControlResponse, score::crypto::CryptoErrorCode>;

constexpr protocol::OperationIdentifier kEchoOperationId{17U, 3U};

// Use different payloads to trigger specific test scenarios
constexpr std::uint64_t kPayload{0x123456789ABCDEF0ULL};
constexpr std::uint64_t kBlockedPayload{0x0FEDCBA987654321ULL};
constexpr std::uint64_t kServerTimeoutPayload{0x0BADF00DDEADBEEFULL};
constexpr std::uint64_t kLateResponseGuardPayload{0x0A1B2C3D4E5F6071ULL};

// Helper to limit the number of concurrent requests
class RequestConcurrencyGate final
{
  public:
    explicit RequestConcurrencyGate(const std::size_t limit) : m_limit(limit) {}

    void Acquire()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_condition.wait(lock, [this] {
            return m_active_requests < m_limit;
        });
        ++m_active_requests;
    }

    void Release() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            --m_active_requests;
        }
        m_condition.notify_one();
    }

  private:
    const std::size_t m_limit;
    std::mutex m_mutex{};
    std::condition_variable m_condition{};
    std::size_t m_active_requests{0U};
};

// Helper to block execution of the server-side request handler for long-running request tests.
class HandlerBlocker final
{
  public:
    void WaitForRelease()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_entered = true;
        ++m_entered_count;
        m_condition.notify_all();
        m_condition.wait(lock, [this] {
            return m_released;
        });
        m_handler_resumed = true;
        lock.unlock();
        m_condition.notify_all();
    }

    bool WaitUntilEntered(const std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_condition.wait_for(lock, timeout, [this] {
            return m_entered;
        });
    }

    bool WaitUntilEnteredCount(const std::size_t expected_count, const std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_condition.wait_for(lock, timeout, [this, expected_count] {
            return m_entered_count >= expected_count;
        });
    }

    bool WaitUntilHandlerResumed(const std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_condition.wait_for(lock, timeout, [this] {
            return m_handler_resumed;
        });
    }

    void Release() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_released = true;
        }
        m_condition.notify_all();
    }

  private:
    std::mutex m_mutex{};
    std::condition_variable m_condition{};
    bool m_entered{false};
    std::size_t m_entered_count{0U};
    bool m_released{false};
    bool m_handler_resumed{false};
};

// Helper to observe cleanup events, e.g., to verify resource deallocation
class CleanupObserver final
{
  public:
    void Record() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_cleanup_count;
        }
        m_condition.notify_all();
    }

    bool WaitForCount(const std::size_t expected_count, const std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_condition.wait_for(lock, timeout, [this, expected_count] {
            return m_cleanup_count >= expected_count;
        });
    }

    std::size_t count() const noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_cleanup_count;
    }

  private:
    mutable std::mutex m_mutex{};
    std::condition_variable m_condition{};
    std::size_t m_cleanup_count{0U};
};

class EchoRequestHandler final : public daemon::control_plane::IRequestHandler
{
  public:
    EchoRequestHandler(std::shared_ptr<HandlerBlocker> blocker,
                       std::shared_ptr<HandlerBlocker> late_response_blocker,
                       std::shared_ptr<std::atomic<std::size_t>> handler_invocation_count)
        : m_blocker(std::move(blocker)),
          m_late_response_blocker(std::move(late_response_blocker)),
          m_handler_invocation_count(std::move(handler_invocation_count))
    {
    }

    daemon::control_plane::ControlResponse processRequest(daemon::control_plane::ControlRequest& request) override
    {
        return ProcessRequest(request);
    }

  private:
    daemon::control_plane::ControlResponse ProcessRequest(daemon::control_plane::ControlRequest& request)
    {
        m_handler_invocation_count->fetch_add(1U, std::memory_order_relaxed);
        protocol::ControlResponse response{};
        response.request_id = request.request_id;
        for (const auto& operation : request.operations)
        {
            const auto value = operation.getParameter<std::uint64_t>(0U);
            if (!value.has_value())
            {
                response.operations.push_back(protocol::SingleOperationResponse{
                    operation.operationId,
                    static_cast<protocol::OperationResult>(score::crypto::CryptoErrorCode::kInvalidArgument),
                    {}});
                continue;
            }
            if (value.value() == kBlockedPayload)
            {
                m_blocker->WaitForRelease();
            }
            if (value.value() == kLateResponseGuardPayload)
            {
                m_late_response_blocker->WaitForRelease();
            }
            if (value.value() == kServerTimeoutPayload)
            {
                response.operations.push_back(protocol::SingleOperationResponse{
                    operation.operationId,
                    static_cast<protocol::OperationResult>(score::crypto::CryptoErrorCode::kOperationTimedOut),
                    {}});
                continue;
            }
            response.operations.push_back(protocol::SingleOperationResponse{
                operation.operationId, protocol::OPERATION_RESULT_SUCCESS, {value.value()}});
        }
        return response;
    }

    std::shared_ptr<HandlerBlocker> m_blocker;
    std::shared_ptr<HandlerBlocker> m_late_response_blocker;
    std::shared_ptr<std::atomic<std::size_t>> m_handler_invocation_count;
};

class EchoHandlerFactory final : public daemon::control_plane::IHandlerChainFactory
{
  public:
    EchoHandlerFactory(std::shared_ptr<HandlerBlocker> blocker,
                       std::shared_ptr<HandlerBlocker> late_response_blocker,
                       std::shared_ptr<std::atomic<std::size_t>> handler_invocation_count)
        : m_blocker(std::move(blocker)),
          m_late_response_blocker(std::move(late_response_blocker)),
          m_handler_invocation_count(std::move(handler_invocation_count))
    {
    }

    std::unique_ptr<daemon::control_plane::IRequestHandler> CreateRequestHandler() override
    {
        return std::make_unique<EchoRequestHandler>(m_blocker, m_late_response_blocker, m_handler_invocation_count);
    }

  private:
    std::shared_ptr<HandlerBlocker> m_blocker;
    std::shared_ptr<HandlerBlocker> m_late_response_blocker;
    std::shared_ptr<std::atomic<std::size_t>> m_handler_invocation_count;
};

std::string MakeServiceIdentifier()
{
    static std::atomic<std::uint64_t> next_identifier{0U};
    const auto timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    return "crypto_adapter_test_" + std::to_string(timestamp) + "_" +
           std::to_string(next_identifier.fetch_add(1U, std::memory_order_relaxed));
}

class RunningServer final
{
  public:
    explicit RunningServer(std::shared_ptr<CleanupObserver> cleanup_observer = {},
                           AuthorizationCallback authorization_callback = {})
        : m_service_identifier(MakeServiceIdentifier()),
          m_handler_blocker(std::make_shared<HandlerBlocker>()),
          m_late_response_blocker(std::make_shared<HandlerBlocker>()),
          m_handler_invocation_count(std::make_shared<std::atomic<std::size_t>>(0U)),
          m_cleanup_observer(std::move(cleanup_observer)),
          m_authorization_callback(std::move(authorization_callback))
    {
        m_ipc_config.SetEndpoint(m_service_identifier);
    }

    ~RunningServer()
    {
        StopAndJoin();
    }

    RunningServer(const RunningServer&) = delete;
    RunningServer& operator=(const RunningServer&) = delete;

    bool Start()
    {
        DisconnectCleanupCallback cleanup_callback{};
        if (m_cleanup_observer != nullptr)
        {
            cleanup_callback = [observer = m_cleanup_observer](const protocol::ClientId) {
                observer->Record();
                return score::crypto::Expected<std::monostate, DaemonErrorCode>{std::monostate{}};
            };
        }

        if (!m_authorization_callback)
        {
            m_authorization_callback = [](const auto, const auto) -> score::crypto::Expected<bool, DaemonErrorCode> {
                return score::crypto::Expected<bool, DaemonErrorCode>{true};
            };
        }

        auto created_server = MessagePassingControlServer::Create(
            std::make_unique<EchoHandlerFactory>(
                m_handler_blocker, m_late_response_blocker, m_handler_invocation_count),
            m_ipc_config,
            m_authorization_callback,
            std::move(cleanup_callback));
        if (!created_server.has_value())
        {
            return false;
        }
        m_server = std::move(created_server).value();

        std::promise<bool> startup_promise;
        auto startup_future = startup_promise.get_future();
        m_server_thread = std::thread([this, startup_promise = std::move(startup_promise)]() mutable {
            const auto start_result = m_server->Start();
            startup_promise.set_value(start_result.has_value());
            if (!start_result.has_value())
            {
                return;
            }

            std::unique_lock<std::mutex> lock(m_stop_mutex);
            m_stop_condition.wait(lock, [this] {
                return m_stop_requested;
            });
            lock.unlock();

            m_server->Stop();
            m_server->WaitForTermination();
        });

        if (startup_future.wait_for(std::chrono::seconds{5}) != std::future_status::ready)
        {
            StopAndJoin();
            return false;
        }
        return startup_future.get();
    }

    const std::string& service_identifier() const noexcept
    {
        return m_service_identifier;
    }

    HandlerBlocker& handler_blocker() noexcept
    {
        return *m_handler_blocker;
    }

    HandlerBlocker& late_response_blocker() noexcept
    {
        return *m_late_response_blocker;
    }

    std::size_t handler_invocation_count() const noexcept
    {
        return m_handler_invocation_count->load(std::memory_order_relaxed);
    }

    void StopServer() noexcept
    {
        if (m_server != nullptr)
        {
            m_server->Stop();
        }
    }

    void StopAndJoin() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(m_stop_mutex);
            m_stop_requested = true;
        }
        m_stop_condition.notify_all();
        if (m_server_thread.joinable())
        {
            m_server_thread.join();
        }
    }

  private:
    std::string m_service_identifier;
    score::crypto::daemon::config::IPCConfig m_ipc_config;
    std::shared_ptr<HandlerBlocker> m_handler_blocker;
    std::shared_ptr<HandlerBlocker> m_late_response_blocker;
    std::shared_ptr<std::atomic<std::size_t>> m_handler_invocation_count;
    std::shared_ptr<CleanupObserver> m_cleanup_observer;
    AuthorizationCallback m_authorization_callback;
    std::unique_ptr<MessagePassingControlServer> m_server{};
    std::mutex m_stop_mutex{};
    std::condition_variable m_stop_condition{};
    bool m_stop_requested{false};
    std::thread m_server_thread{};
};

protocol::ControlRequest MakeEchoRequest(const std::uint64_t value)
{
    protocol::ControlRequest request{};
    request.data_node_id = 1U;
    request.operations.push_back(protocol::SingleOperationRequest{kEchoOperationId, {value}});
    return request;
}

void ExpectEchoResponse(const ClientResult& response, const std::uint64_t expected_value)
{
    ASSERT_TRUE(response.has_value());
    ASSERT_EQ(response->operations.size(), 1U);
    const auto& operation = response->operations.front();
    EXPECT_EQ(operation.operationId.operationActor, kEchoOperationId.operationActor);
    EXPECT_EQ(operation.operationId.operationAction, kEchoOperationId.operationAction);
    ASSERT_EQ(operation.result, protocol::OPERATION_RESULT_SUCCESS);
    const auto returned_value = operation.getParameter<std::uint64_t>(0U);
    ASSERT_TRUE(returned_value.has_value());
    EXPECT_EQ(returned_value.value(), expected_value);
}

TEST(MessagePassingAdapterIntegrationTest, OneClientOneServerEchoesValue)
{
    RunningServer server;
    ASSERT_TRUE(server.Start());

    std::promise<ClientResult> response_promise;
    auto response_future = response_promise.get_future();
    const auto service_identifier = server.service_identifier();
    std::thread client_thread([service_identifier, &response_promise] {
        auto created_client = MessagePassingControlClient::Create(service_identifier);
        if (!created_client.has_value())
        {
            response_promise.set_value(score::crypto::make_unexpected(created_client.error()));
            return;
        }
        auto client = std::move(created_client).value();
        auto request = MakeEchoRequest(kPayload);
        response_promise.set_value(client->SendRequest(request, std::chrono::milliseconds{2000}));
    });

    const auto response_ready = response_future.wait_for(std::chrono::seconds{5}) == std::future_status::ready;
    if (!response_ready)
    {
        ADD_FAILURE() << "The client request did not complete before the test deadline";
    }
    client_thread.join();
    if (!response_ready)
    {
        return;
    }

    auto response = response_future.get();
    ExpectEchoResponse(response, kPayload);
}

TEST(MessagePassingAdapterIntegrationTest, FreshClientConnectsAfterServerBecomesAvailable)
{
    RunningServer server;

    auto unavailable_client_result = MessagePassingControlClient::Create(server.service_identifier());
    ASSERT_TRUE(unavailable_client_result.has_value());
    auto unavailable_client = std::move(unavailable_client_result).value();
    auto unavailable_request = MakeEchoRequest(kPayload);
    const auto unavailable_response =
        unavailable_client->SendRequest(unavailable_request, std::chrono::milliseconds{250});
    ASSERT_FALSE(unavailable_response.has_value());
    EXPECT_EQ(unavailable_response.error(), score::crypto::CryptoErrorCode::kConnectionFailed);
    unavailable_client.reset();

    ASSERT_TRUE(server.Start());
    auto recovered_client_result = MessagePassingControlClient::Create(server.service_identifier());
    ASSERT_TRUE(recovered_client_result.has_value());
    auto recovered_client = std::move(recovered_client_result).value();
    auto recovered_request = MakeEchoRequest(kPayload + 1U);
    const auto recovered_response = recovered_client->SendRequest(recovered_request, std::chrono::milliseconds{2000});

    ExpectEchoResponse(recovered_response, kPayload + 1U);
}

TEST(MessagePassingAdapterIntegrationTest, DeniedClientCannotInvokeHandler)
{
    auto cleanup_observer = std::make_shared<CleanupObserver>();
    RunningServer server{cleanup_observer,
                         [](const auto, const auto) -> score::crypto::Expected<bool, DaemonErrorCode> {
                             return score::crypto::Expected<bool, DaemonErrorCode>{false};
                         }};
    ASSERT_TRUE(server.Start());

    auto created_client = MessagePassingControlClient::Create(server.service_identifier());
    auto observed_error = score::crypto::CryptoErrorCode::kInternalError;
    bool request_failed{false};
    // Due to the async nature of the connection establishment
    // we may be able to create the client successfully
    // and only upon sending a request will the access denial be observed.
    if (!created_client.has_value())
    {
        observed_error = created_client.error();
        request_failed = true;
    }
    else
    {
        auto client = std::move(created_client).value();
        auto request = MakeEchoRequest(kPayload);
        const auto result = client->SendRequest(request, std::chrono::milliseconds{1000});
        request_failed = !result.has_value();
        if (request_failed)
        {
            observed_error = result.error();
        }
    }

    EXPECT_TRUE(request_failed);
#if defined(__QNX__)
    EXPECT_EQ(observed_error, score::crypto::CryptoErrorCode::kAccessDenied);
#else
    // On Linux, com message_passing does not properly report the concrete reason.
    // We only get a connection closed on the client.
    EXPECT_EQ(observed_error, score::crypto::CryptoErrorCode::kConnectionFailed);
#endif
    EXPECT_EQ(server.handler_invocation_count(), 0U);
    EXPECT_EQ(cleanup_observer->count(), 0U);
}

TEST(MessagePassingAdapterIntegrationTest, MultipleOperationsInSingleInteraction)
{
    RunningServer server;
    ASSERT_TRUE(server.Start());

    const std::array<protocol::OperationIdentifier, 3U> operation_ids{{
        {21U, 1U},
        {21U, 2U},
        {22U, 1U},
    }};
    const std::array<std::uint64_t, 3U> values{{0x101U, 0x202U, 0x303U}};
    protocol::ControlRequest request{};
    request.data_node_id = 7U;
    for (std::size_t operation_index = 0U; operation_index < operation_ids.size(); ++operation_index)
    {
        request.operations.push_back(
            protocol::SingleOperationRequest{operation_ids[operation_index], {values[operation_index]}});
    }

    auto created_client = MessagePassingControlClient::Create(server.service_identifier());
    ASSERT_TRUE(created_client.has_value());
    auto client = std::move(created_client).value();
    const auto response = client->SendRequest(request, std::chrono::milliseconds{2000});

    ASSERT_TRUE(response.has_value());
    ASSERT_EQ(response->operations.size(), operation_ids.size());
    for (std::size_t operation_index = 0U; operation_index < operation_ids.size(); ++operation_index)
    {
        const auto& operation = response->operations[operation_index];
        EXPECT_EQ(operation.operationId.operationActor, operation_ids[operation_index].operationActor);
        EXPECT_EQ(operation.operationId.operationAction, operation_ids[operation_index].operationAction);
        ASSERT_EQ(operation.result, protocol::OPERATION_RESULT_SUCCESS);
        const auto returned_value = operation.getParameter<std::uint64_t>(0U);
        ASSERT_TRUE(returned_value.has_value());
        EXPECT_EQ(returned_value.value(), values[operation_index]);
    }
}

TEST(MessagePassingAdapterIntegrationTest, PerConnectionOutstandingCallLimitRejectsExcessCall)
{
    RunningServer server;
    ASSERT_TRUE(server.Start());

    constexpr auto call_limit = static_cast<std::size_t>(::score::crypto::ipc::kMaxOutstandingOperationsPerConnection);
    auto created_client = MessagePassingControlClient::Create(server.service_identifier());
    ASSERT_TRUE(created_client.has_value());
    auto client = std::move(created_client).value();

    std::promise<void> start_promise;
    const auto start_signal = start_promise.get_future().share();
    std::vector<std::future<ClientResult>> response_futures;
    std::vector<std::thread> request_threads;
    response_futures.reserve(call_limit);
    request_threads.reserve(call_limit);

    for (std::size_t call_index = 0U; call_index < call_limit; ++call_index)
    {
        std::promise<ClientResult> response_promise;
        response_futures.push_back(response_promise.get_future());
        auto request_client = client;
        request_threads.emplace_back([request_client = std::move(request_client),
                                      start_signal,
                                      response_promise = std::move(response_promise)]() mutable {
            start_signal.wait();
            auto request = MakeEchoRequest(kBlockedPayload);
            response_promise.set_value(request_client->SendRequest(request, std::chrono::milliseconds{5000}));
        });
    }

    start_promise.set_value();
    const bool all_calls_entered = server.handler_blocker().WaitUntilEnteredCount(call_limit, std::chrono::seconds{5});

    auto excess_request = MakeEchoRequest(kPayload + 0x99U);
    const auto excess_result = client->SendRequest(excess_request, std::chrono::milliseconds{1000});
    const bool excess_call_rejected = !excess_result.has_value();
    const auto excess_error =
        excess_call_rejected ? excess_result.error() : score::crypto::CryptoErrorCode::kInternalError;

    server.handler_blocker().Release();
    const auto result_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{8};
    for (auto& response_future : response_futures)
    {
        if (response_future.wait_until(result_deadline) != std::future_status::ready)
        {
            ADD_FAILURE() << "An admitted request did not finish after the handler gate was released";
        }
    }
    for (auto& request_thread : request_threads)
    {
        request_thread.join();
    }

    EXPECT_TRUE(all_calls_entered) << "The test did not fill the configured per-connection capacity";
    EXPECT_TRUE(excess_call_rejected) << "The call beyond the configured capacity was accepted";
    EXPECT_EQ(excess_error, score::crypto::CryptoErrorCode::kProviderBusy);
    for (auto& response_future : response_futures)
    {
        ASSERT_EQ(response_future.wait_for(std::chrono::milliseconds{0}), std::future_status::ready);
        const auto response = response_future.get();
        ExpectEchoResponse(response, kBlockedPayload);
    }
}

TEST(MessagePassingAdapterIntegrationTest, OversizedRequestIsRejectedAndConnectionRemainsUsable)
{
    RunningServer server;
    ASSERT_TRUE(server.Start());

    auto created_client = MessagePassingControlClient::Create(server.service_identifier());
    ASSERT_TRUE(created_client.has_value());
    auto client = std::move(created_client).value();

    const std::string oversized_value(static_cast<std::size_t>(::score::crypto::ipc::kMaxPayloadBytes) + 256U, 'x');
    protocol::ControlRequest oversized_request{};
    oversized_request.data_node_id = 1U;
    oversized_request.operations.push_back(
        protocol::SingleOperationRequest{kEchoOperationId, {std::string_view{oversized_value}}});

    const auto oversized_result = client->SendRequest(oversized_request, std::chrono::milliseconds{1000});
    ASSERT_FALSE(oversized_result.has_value());
    EXPECT_EQ(oversized_result.error(), score::crypto::CryptoErrorCode::kInsufficientBufferSize);
    EXPECT_EQ(server.handler_invocation_count(), 0U);

    auto valid_request = MakeEchoRequest(kPayload);
    const auto valid_result = client->SendRequest(valid_request, std::chrono::milliseconds{2000});
    ExpectEchoResponse(valid_result, kPayload);
    EXPECT_EQ(server.handler_invocation_count(), 1U);
}

TEST(MessagePassingAdapterIntegrationTest, ThreeClientsReceiveTheirOwnPayloads)
{
    RunningServer server;
    ASSERT_TRUE(server.Start());

    constexpr std::size_t client_count{3U};
    std::promise<void> start_promise;
    const auto start_signal = start_promise.get_future().share();
    std::array<std::promise<ClientResult>, client_count> response_promises{};
    std::array<std::future<ClientResult>, client_count> response_futures{};
    std::array<std::thread, client_count> client_threads{};
    std::array<std::uint64_t, client_count> payloads{};
    const auto service_identifier = server.service_identifier();

    for (std::size_t client_index = 0U; client_index < client_count; ++client_index)
    {
        payloads[client_index] = kPayload + static_cast<std::uint64_t>(client_index + 1U);
        response_futures[client_index] = response_promises[client_index].get_future();
        client_threads[client_index] = std::thread([service_identifier,
                                                    start_signal,
                                                    expected_payload = payloads[client_index],
                                                    &response_promise = response_promises[client_index]]() mutable {
            start_signal.wait();
            auto created_client = MessagePassingControlClient::Create(service_identifier);
            if (!created_client.has_value())
            {
                response_promise.set_value(score::crypto::make_unexpected(created_client.error()));
                return;
            }
            auto client = std::move(created_client).value();
            auto request = MakeEchoRequest(expected_payload);
            response_promise.set_value(client->SendRequest(request, std::chrono::milliseconds{3000}));
        });
    }

    start_promise.set_value();
    for (std::size_t client_index = 0U; client_index < client_count; ++client_index)
    {
        if (response_futures[client_index].wait_for(std::chrono::seconds{6}) != std::future_status::ready)
        {
            ADD_FAILURE() << "Client " << client_index << " did not complete before the test deadline";
        }
    }
    for (auto& client_thread : client_threads)
    {
        client_thread.join();
    }

    for (std::size_t client_index = 0U; client_index < client_count; ++client_index)
    {
        if (response_futures[client_index].wait_for(std::chrono::milliseconds{0}) != std::future_status::ready)
        {
            ADD_FAILURE() << "Client " << client_index << " did not publish a result";
            continue;
        }
        const auto response = response_futures[client_index].get();
        ExpectEchoResponse(response, payloads[client_index]);
    }
}

TEST(MessagePassingAdapterIntegrationTest, RepeatedClientSetsReconnectWhileServerRemainsActive)
{
    RunningServer server;
    ASSERT_TRUE(server.Start());

    constexpr std::size_t iteration_count{8U};
    constexpr std::size_t client_count{8U};
    constexpr std::size_t requests_per_client{8U};
    constexpr std::size_t total_request_count{client_count * requests_per_client};
    constexpr std::size_t max_in_flight_requests{static_cast<std::size_t>(::score::crypto::ipc::kWorkerThreads / 2U)};
    const auto service_identifier = server.service_identifier();
    RequestConcurrencyGate request_gate{max_in_flight_requests};

    for (std::size_t iteration = 0U; iteration < iteration_count; ++iteration)
    {
        std::promise<void> start_promise;
        const auto start_signal = start_promise.get_future().share();
        std::vector<std::promise<ClientResult>> response_promises(total_request_count);
        std::vector<std::future<ClientResult>> response_futures;
        std::array<std::thread, client_count> client_threads{};
        std::vector<std::uint64_t> payloads(total_request_count);
        response_futures.reserve(total_request_count);
        for (auto& response_promise : response_promises)
        {
            response_futures.push_back(response_promise.get_future());
        }

        for (std::size_t client_index = 0U; client_index < client_count; ++client_index)
        {
            const auto first_request_index = client_index * requests_per_client;
            for (std::size_t request_index = 0U; request_index < requests_per_client; ++request_index)
            {
                const auto absolute_request_index = first_request_index + request_index;
                payloads[absolute_request_index] =
                    kPayload +
                    static_cast<std::uint64_t>(iteration * total_request_count + absolute_request_index + 1U);
            }
            client_threads[client_index] = std::thread([service_identifier,
                                                        start_signal,
                                                        &request_gate,
                                                        &response_promises,
                                                        &payloads,
                                                        first_request_index,
                                                        requests_per_client]() mutable {
                start_signal.wait();
                auto created_client = MessagePassingControlClient::Create(service_identifier);
                if (!created_client.has_value())
                {
                    for (std::size_t request_index = 0U; request_index < requests_per_client; ++request_index)
                    {
                        response_promises[first_request_index + request_index].set_value(
                            score::crypto::make_unexpected(created_client.error()));
                    }
                    return;
                }
                auto client = std::move(created_client).value();
                std::vector<std::thread> request_threads;
                request_threads.reserve(requests_per_client);
                for (std::size_t request_index = 0U; request_index < requests_per_client; ++request_index)
                {
                    const auto response_index = first_request_index + request_index;
                    auto request_client = client;
                    request_threads.emplace_back([request_client = std::move(request_client),
                                                  &request_gate,
                                                  &response_promises,
                                                  &payloads,
                                                  response_index]() mutable {
                        auto request = MakeEchoRequest(payloads[response_index]);
                        request_gate.Acquire();
                        auto response = request_client->SendRequest(request, std::chrono::milliseconds{5000});
                        request_gate.Release();
                        response_promises[response_index].set_value(std::move(response));
                    });
                }
                for (auto& request_thread : request_threads)
                {
                    request_thread.join();
                }
                client.reset();
            });
        }

        start_promise.set_value();
        const auto result_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
        for (std::size_t request_index = 0U; request_index < total_request_count; ++request_index)
        {
            if (response_futures[request_index].wait_until(result_deadline) != std::future_status::ready)
            {
                ADD_FAILURE() << "Iteration " << iteration << ", request " << request_index
                              << " did not finish before its client connection closed";
            }
        }
        for (auto& client_thread : client_threads)
        {
            client_thread.join();
        }

        for (std::size_t request_index = 0U; request_index < total_request_count; ++request_index)
        {
            if (response_futures[request_index].wait_for(std::chrono::milliseconds{0}) != std::future_status::ready)
            {
                ADD_FAILURE() << "Iteration " << iteration << ", request " << request_index
                              << " did not publish a result";
                continue;
            }
            const auto response = response_futures[request_index].get();
            ExpectEchoResponse(response, payloads[request_index]);
        }
    }
}

TEST(MessagePassingAdapterIntegrationTest, DisconnectRunsCleanupExactlyOnce)
{
    auto cleanup_observer = std::make_shared<CleanupObserver>();
    RunningServer server{cleanup_observer};
    ASSERT_TRUE(server.Start());

    auto created_client = MessagePassingControlClient::Create(server.service_identifier());
    ASSERT_TRUE(created_client.has_value());
    auto client = std::move(created_client).value();
    auto request = MakeEchoRequest(kPayload);
    const auto response = client->SendRequest(request, std::chrono::milliseconds{2000});
    ExpectEchoResponse(response, kPayload);

    client.reset();
    ASSERT_TRUE(cleanup_observer->WaitForCount(1U, std::chrono::seconds{5}))
        << "Disconnect cleanup did not run after the client connection closed";

    server.StopAndJoin();
    EXPECT_EQ(cleanup_observer->count(), 1U);
}

TEST(MessagePassingAdapterIntegrationTest, CleanupWaitsUntilLastWorkItemCompletes)
{
    auto cleanup_observer = std::make_shared<CleanupObserver>();
    RunningServer server{cleanup_observer};
    ASSERT_TRUE(server.Start());

    auto created_client = MessagePassingControlClient::Create(server.service_identifier());
    ASSERT_TRUE(created_client.has_value());
    auto client = std::move(created_client).value();

    std::promise<ClientResult> blocked_response_promise;
    auto blocked_response_future = blocked_response_promise.get_future();
    auto blocked_client = client;
    std::thread blocked_request_thread([client = std::move(blocked_client), &blocked_response_promise]() mutable {
        auto request = MakeEchoRequest(kBlockedPayload);
        auto response = client->SendRequest(request, std::chrono::milliseconds{5000});
        blocked_response_promise.set_value(std::move(response));
    });

    std::promise<ClientResult> completed_response_promise;
    auto completed_response_future = completed_response_promise.get_future();
    auto completed_client = client;
    std::thread completed_request_thread([client = std::move(completed_client), &completed_response_promise]() mutable {
        auto request = MakeEchoRequest(kPayload + 1U);
        completed_response_promise.set_value(client->SendRequest(request, std::chrono::milliseconds{5000}));
    });
    client.reset();

    const bool blocked_handler_entered = server.handler_blocker().WaitUntilEntered(std::chrono::seconds{3});
    const bool completed_response_ready =
        completed_response_future.wait_for(std::chrono::seconds{3}) == std::future_status::ready;
    if (completed_response_ready)
    {
        const auto response = completed_response_future.get();
        ExpectEchoResponse(response, kPayload + 1U);
    }
    else
    {
        ADD_FAILURE() << "The unblocked WorkItem did not complete before the test deadline";
    }

    server.StopServer();
    const bool cleanup_ran_before_last_work_item = cleanup_observer->WaitForCount(1U, std::chrono::milliseconds{100});
    EXPECT_FALSE(cleanup_ran_before_last_work_item) << "Disconnect cleanup ran while a WorkItem was still blocked";

    server.handler_blocker().Release();
    const bool blocked_response_ready =
        blocked_response_future.wait_for(std::chrono::seconds{6}) == std::future_status::ready;
    if (!blocked_response_ready)
    {
        ADD_FAILURE() << "The blocked WorkItem did not finish after the handler was released";
    }
    blocked_request_thread.join();
    completed_request_thread.join();
    server.StopAndJoin();

    EXPECT_TRUE(blocked_handler_entered) << "The blocked WorkItem never reached the server handler";
    EXPECT_EQ(cleanup_observer->count(), 1U);
}

TEST(MessagePassingAdapterIntegrationTest, ServerShutdownDropsNewRequestsWhileDrainingPendingWorkAndWaitsBeforeCleanup)
{
    auto cleanup_observer = std::make_shared<CleanupObserver>();
    RunningServer server{cleanup_observer};
    ASSERT_TRUE(server.Start());

    auto created_client = MessagePassingControlClient::Create(server.service_identifier());
    ASSERT_TRUE(created_client.has_value());
    auto client = std::move(created_client).value();
    std::promise<ClientResult> response_promise;
    auto response_future = response_promise.get_future();
    auto blocked_client = client;
    std::thread client_thread([client = std::move(blocked_client), &response_promise]() mutable {
        auto request = MakeEchoRequest(kBlockedPayload);
        response_promise.set_value(client->SendRequest(request, std::chrono::milliseconds{5000}));
    });

    const bool handler_entered = server.handler_blocker().WaitUntilEntered(std::chrono::seconds{3});
    server.StopServer();
    const bool cleanup_ran_before_release = cleanup_observer->WaitForCount(1U, std::chrono::milliseconds{100});

    // Requests from existing clients should be dropped after server shutdown
    auto existing_client_request = MakeEchoRequest(kPayload + 2U);
    const auto existing_client_response = client->SendRequest(existing_client_request, std::chrono::milliseconds{250});
    ASSERT_FALSE(existing_client_response.has_value()) << "A new request on an existing client was not dropped";
    EXPECT_EQ(existing_client_response.error(), score::crypto::CryptoErrorCode::kConnectionFailed);

    // Requests connection attempts from new clients should be dropped,
    auto new_client_result = MessagePassingControlClient::Create(server.service_identifier());
#if defined(__QNX__)
    EXPECT_EQ(new_client_result.error(), score::crypto::CryptoErrorCode::kConnectionFailed);
#else
    // On Linux, due to the underlying message passing, a new client may still be able to connect
    // briefly after server shutdown, but any requests it sends should fail.
    if (new_client_result.has_value())
    {
        auto new_client = std::move(new_client_result).value();
        auto new_client_request = MakeEchoRequest(kPayload + 3U);
        const auto new_client_response = new_client->SendRequest(new_client_request, std::chrono::milliseconds{250});
        ASSERT_FALSE(new_client_response.has_value()) << "A new client connected after server shutdown";
        EXPECT_EQ(new_client_response.error(), score::crypto::CryptoErrorCode::kConnectionFailed);
    }
    else
    {
        EXPECT_EQ(new_client_result.error(), score::crypto::CryptoErrorCode::kConnectionFailed);
    };
#endif

    // Ensure, that only one request was handled before server shutdown
    EXPECT_EQ(server.handler_invocation_count(), 1U) << "A request was handled after server shutdown";

    server.handler_blocker().Release();
    const bool client_call_finished = response_future.wait_for(std::chrono::seconds{8}) == std::future_status::ready;
    client_thread.join();
    client.reset();
    server.StopAndJoin();

    EXPECT_TRUE(handler_entered) << "The active request did not reach the daemon handler";
    EXPECT_FALSE(cleanup_ran_before_release) << "Cleanup ran before the active WorkItem completed";
    ASSERT_TRUE(client_call_finished) << "The client call did not finish after releasing the handler";
    const auto pending_response = response_future.get();
    ASSERT_FALSE(pending_response.has_value());
    EXPECT_EQ(pending_response.error(), score::crypto::CryptoErrorCode::kConnectionFailed);
    EXPECT_EQ(cleanup_observer->count(), 1U);
}

TEST(MessagePassingAdapterIntegrationTest, ClientTimesOutBeforeHandlerReturnsResponse)
{
    RunningServer server;
    ASSERT_TRUE(server.Start());

    std::promise<ClientResult> response_promise;
    auto response_future = response_promise.get_future();
    const auto service_identifier = server.service_identifier();
    std::thread client_thread([service_identifier, &response_promise] {
        auto created_client = MessagePassingControlClient::Create(service_identifier);
        if (!created_client.has_value())
        {
            response_promise.set_value(score::crypto::make_unexpected(created_client.error()));
            return;
        }
        auto client = std::move(created_client).value();
        auto request = MakeEchoRequest(kBlockedPayload);
        response_promise.set_value(client->SendRequest(request, std::chrono::milliseconds{250}));
    });

    const bool handler_entered = server.handler_blocker().WaitUntilEntered(std::chrono::seconds{3});
    const bool client_finished = response_future.wait_for(std::chrono::seconds{3}) == std::future_status::ready;
    server.handler_blocker().Release();
    client_thread.join();

    ASSERT_TRUE(handler_entered) << "The server handler was not reached";
    ASSERT_TRUE(client_finished) << "The client did not finish before the test deadline";
    const auto response = response_future.get();
    ASSERT_FALSE(response.has_value());
    EXPECT_EQ(response.error(), score::crypto::CryptoErrorCode::kOperationResponseTimedOut);
}

TEST(MessagePassingAdapterIntegrationTest, LateResponseDoesNotCompleteNextRequest)
{
    RunningServer server;
    ASSERT_TRUE(server.Start());

    auto created_client = MessagePassingControlClient::Create(server.service_identifier());
    ASSERT_TRUE(created_client.has_value());
    auto client = std::move(created_client).value();

    std::promise<ClientResult> timed_out_promise;
    auto timed_out_future = timed_out_promise.get_future();
    auto first_client = client;
    std::thread first_request_thread([client = std::move(first_client), &timed_out_promise]() mutable {
        auto request = MakeEchoRequest(kBlockedPayload);
        timed_out_promise.set_value(client->SendRequest(request, std::chrono::milliseconds{250}));
    });

    const bool first_handler_entered = server.handler_blocker().WaitUntilEntered(std::chrono::seconds{3});
    const bool first_call_finished = timed_out_future.wait_for(std::chrono::seconds{3}) == std::future_status::ready;
    if (!first_handler_entered || !first_call_finished)
    {
        server.handler_blocker().Release();
        first_request_thread.join();
        ADD_FAILURE() << "The first request did not reach the handler and time out";
        return;
    }
    first_request_thread.join();
    const auto timed_out_result = timed_out_future.get();
    ASSERT_FALSE(timed_out_result.has_value());
    EXPECT_EQ(timed_out_result.error(), score::crypto::CryptoErrorCode::kOperationResponseTimedOut);

    std::promise<ClientResult> follow_up_promise;
    auto follow_up_future = follow_up_promise.get_future();
    auto follow_up_client = client;
    std::thread follow_up_thread([client = std::move(follow_up_client), &follow_up_promise]() mutable {
        auto request = MakeEchoRequest(kLateResponseGuardPayload);
        follow_up_promise.set_value(client->SendRequest(request, std::chrono::milliseconds{5000}));
    });

    const bool follow_up_handler_entered = server.late_response_blocker().WaitUntilEntered(std::chrono::seconds{3});
    server.handler_blocker().Release();
    const bool timed_out_handler_resumed = server.handler_blocker().WaitUntilHandlerResumed(std::chrono::seconds{3});
    const bool follow_up_completed_while_blocked =
        follow_up_future.wait_for(std::chrono::milliseconds{150}) == std::future_status::ready;
    server.late_response_blocker().Release();

    const bool follow_up_call_finished =
        follow_up_future.wait_for(std::chrono::seconds{6}) == std::future_status::ready;
    follow_up_thread.join();

    EXPECT_TRUE(follow_up_handler_entered) << "The follow-up request did not reach its handler gate";
    EXPECT_TRUE(timed_out_handler_resumed) << "The timed-out request handler did not resume";
    EXPECT_FALSE(follow_up_completed_while_blocked)
        << "The late response incorrectly completed the pending follow-up call";
    ASSERT_TRUE(follow_up_call_finished) << "The follow-up request did not finish after release";
    const auto follow_up_result = follow_up_future.get();
    ExpectEchoResponse(follow_up_result, kLateResponseGuardPayload);
}

TEST(MessagePassingAdapterIntegrationTest, ParallelClientsCompleteAllRequests)
{
    RunningServer server;
    ASSERT_TRUE(server.Start());

    constexpr std::size_t client_count{4U};
    constexpr std::size_t requests_per_client{6U};
    constexpr std::size_t total_request_count{client_count * requests_per_client};

    std::vector<std::shared_ptr<MessagePassingControlClient>> clients;
    clients.reserve(client_count);
    for (std::size_t client_index = 0U; client_index < client_count; ++client_index)
    {
        auto created_client = MessagePassingControlClient::Create(server.service_identifier());
        ASSERT_TRUE(created_client.has_value());
        clients.push_back(std::move(created_client).value());
    }

    std::promise<void> start_promise;
    const auto start_signal = start_promise.get_future().share();
    std::vector<std::future<ClientResult>> response_futures;
    std::vector<std::thread> request_threads;
    std::vector<std::uint64_t> expected_payloads;
    response_futures.reserve(total_request_count);
    request_threads.reserve(total_request_count);
    expected_payloads.reserve(total_request_count);

    for (std::size_t client_index = 0U; client_index < client_count; ++client_index)
    {
        for (std::size_t request_index = 0U; request_index < requests_per_client; ++request_index)
        {
            const auto payload = kPayload + static_cast<std::uint64_t>(client_index * 100U + request_index + 1U);
            expected_payloads.push_back(payload);
            std::promise<ClientResult> response_promise;
            response_futures.push_back(response_promise.get_future());
            auto client = clients[client_index];
            request_threads.emplace_back([client = std::move(client),
                                          start_signal,
                                          payload,
                                          response_promise = std::move(response_promise)]() mutable {
                start_signal.wait();
                auto request = MakeEchoRequest(payload);
                response_promise.set_value(client->SendRequest(request, std::chrono::milliseconds{5000}));
            });
        }
    }

    start_promise.set_value();
    const auto result_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    for (std::size_t request_index = 0U; request_index < total_request_count; ++request_index)
    {
        if (response_futures[request_index].wait_until(result_deadline) != std::future_status::ready)
        {
            ADD_FAILURE() << "Request " << request_index << " did not complete before the test deadline";
        }
    }
    for (auto& request_thread : request_threads)
    {
        request_thread.join();
    }

    for (std::size_t request_index = 0U; request_index < total_request_count; ++request_index)
    {
        if (response_futures[request_index].wait_for(std::chrono::milliseconds{0}) != std::future_status::ready)
        {
            ADD_FAILURE() << "Request " << request_index << " did not publish a result";
            continue;
        }
        const auto response = response_futures[request_index].get();
        ExpectEchoResponse(response, expected_payloads[request_index]);
    }
}

}  // namespace
}  // namespace score::crypto::ipc::message_passing
