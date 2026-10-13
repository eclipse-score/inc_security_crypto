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

#include "score/crypto/src/ipc/message_passing_adapter/tests/message_passing_adapter_integration_test_process_separation_common.h"

#include "score/crypto/src/ipc/message_passing_adapter/client/message_passing_control_client.h"
#include "score/crypto/src/ipc/message_passing_adapter/ipc_config.h"

#include <gtest/gtest.h>
#include <unistd.h>
#include <signal.h>

#include <charconv>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <future>
#include <iostream>
#include <memory>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace
{

namespace process_test = score::crypto::ipc::message_passing::process_test;
namespace protocol = process_test::protocol;
using ClientResult = score::crypto::Expected<protocol::ControlResponse, score::crypto::CryptoErrorCode>;
using ClientResult = score::crypto::Expected<protocol::ControlResponse, score::crypto::CryptoErrorCode>;

}  // namespace

TEST(MessagePassingClientProcessTest, CompletesTwoHundredRequestsAcrossFourThreads)
{
    const char* service_identifier_env = std::getenv("MESSAGE_PASSING_SERVICE_ID");
    const std::string_view service_identifier = (service_identifier_env == nullptr)
                                                    ? process_test::kServiceIdentifier
                                                    : std::string_view{service_identifier_env};
    ASSERT_FALSE(service_identifier.empty());

    const char* client_index_env = std::getenv("MESSAGE_PASSING_CLIENT_INDEX");
    ASSERT_NE(client_index_env, nullptr) << "MESSAGE_PASSING_CLIENT_INDEX is not set";
    const std::string_view client_index_text{client_index_env};
    std::size_t client_index{0U};
    const auto parse_result =
        std::from_chars(client_index_text.data(), client_index_text.data() + client_index_text.size(), client_index);
    ASSERT_EQ(parse_result.ec, std::errc{});
    ASSERT_EQ(parse_result.ptr, client_index_text.data() + client_index_text.size());

    constexpr std::size_t thread_count{4U};
    constexpr std::size_t requests_per_thread{50U};
    constexpr std::size_t requests_per_process{thread_count * requests_per_thread};
    constexpr auto request_timeout = std::chrono::seconds{5};

    auto client_result = score::crypto::ipc::message_passing::MessagePassingControlClient::Create(service_identifier);
    ASSERT_TRUE(client_result.has_value()) << "Failed to create client " << client_index;
    auto client = std::move(client_result).value();

    std::promise<void> start_promise;
    const auto start_signal = start_promise.get_future().share();
    std::array<std::vector<ClientResult>, thread_count> responses{};
    std::array<std::vector<std::uint64_t>, thread_count> request_ids{};
    std::array<std::thread, thread_count> request_threads{};
    for (std::size_t thread_index = 0U; thread_index < thread_count; ++thread_index)
    {
        responses[thread_index].reserve(requests_per_thread);
        request_ids[thread_index].reserve(requests_per_thread);
        request_threads[thread_index] = std::thread(
            [client, client_index, thread_index, start_signal, request_timeout, &responses, &request_ids]() {
                start_signal.wait();
                for (std::size_t request_index = 0U; request_index < requests_per_thread; ++request_index)
                {
                    const auto process_request_index = thread_index * requests_per_thread + request_index;
                    const auto expected_payload =
                        static_cast<std::uint64_t>(client_index * requests_per_process + process_request_index + 1U);
                    protocol::ControlRequest request{};
                    request.operation.operations.push_back(
                        protocol::SingleOperationRequest{process_test::kEchoOperationId, {expected_payload}});
                    responses[thread_index].push_back(client->SendRequest(request, request_timeout));
                    request_ids[thread_index].push_back(request.request_id);
                }
            });
    }

    start_promise.set_value();
    for (auto& request_thread : request_threads)
    {
        request_thread.join();
    }

    for (std::size_t thread_index = 0U; thread_index < thread_count; ++thread_index)
    {
        ASSERT_EQ(responses[thread_index].size(), requests_per_thread) << "Thread " << thread_index;
        ASSERT_EQ(request_ids[thread_index].size(), requests_per_thread) << "Thread " << thread_index;
        for (std::size_t request_index = 0U; request_index < requests_per_thread; ++request_index)
        {
            const auto& response = responses[thread_index][request_index];
            ASSERT_TRUE(response.has_value()) << "Thread " << thread_index << ", request " << request_index
                                              << " failed with error " << static_cast<std::uint32_t>(response.error());
            EXPECT_EQ(response->request_id, request_ids[thread_index][request_index]);
            ASSERT_EQ(response->operation.operations.size(), 1U);

            const auto process_request_index = thread_index * requests_per_thread + request_index;
            const auto expected_payload =
                static_cast<std::uint64_t>(client_index * requests_per_process + process_request_index + 1U);
            const auto& operation = response->operation.operations.front();
            EXPECT_EQ(operation.operationId.operationActor, process_test::kEchoOperationId.operationActor);
            EXPECT_EQ(operation.operationId.operationAction, process_test::kEchoOperationId.operationAction);
            ASSERT_EQ(operation.result, protocol::OPERATION_RESULT_SUCCESS);
            const auto echoed_value = operation.getParameter<std::uint64_t>(0U);
            ASSERT_TRUE(echoed_value.has_value());
            EXPECT_EQ(echoed_value.value(), expected_payload);
        }
    }
}

TEST(MessagePassingClientProcessTest, IsDeniedByServerUidAuthorization)
{
    const char* service_identifier_env = std::getenv("MESSAGE_PASSING_SERVICE_ID");
    const std::string_view service_identifier = (service_identifier_env == nullptr)
                                                    ? process_test::kServiceIdentifier
                                                    : std::string_view{service_identifier_env};
    ASSERT_FALSE(service_identifier.empty());

    auto observed_error = score::crypto::CryptoErrorCode::kInternalError;
    auto client_result = score::crypto::ipc::message_passing::MessagePassingControlClient::Create(service_identifier);
    if (!client_result.has_value())
    {
        observed_error = client_result.error();
    }
    else
    {
        auto client = std::move(client_result).value();
        protocol::ControlRequest request{};
        request.operation.operations.push_back(
            protocol::SingleOperationRequest{process_test::kEchoOperationId, {process_test::kEchoValue}});
        const auto response = client->SendRequest(request, std::chrono::milliseconds{1000});
        ASSERT_FALSE(response.has_value()) << "UID-authorized server accepted the client request";
        observed_error = response.error();
    }

#if defined(__QNX__)
    EXPECT_EQ(observed_error, score::crypto::CryptoErrorCode::kAccessDenied);
#else
    EXPECT_EQ(observed_error, score::crypto::CryptoErrorCode::kConnectionFailed);
#endif
}

TEST(MessagePassingClientProcessTest, ReturnsAfterRequestTimeoutAndGracePeriod)
{
    const char* service_identifier_env = std::getenv("MESSAGE_PASSING_SERVICE_ID");
    const std::string_view service_identifier = (service_identifier_env == nullptr)
                                                    ? process_test::kServiceIdentifier
                                                    : std::string_view{service_identifier_env};
    ASSERT_FALSE(service_identifier.empty());

    auto client_result = score::crypto::ipc::message_passing::MessagePassingControlClient::Create(service_identifier);
    ASSERT_TRUE(client_result.has_value()) << "Failed to create message-passing client";
    auto client = std::move(client_result).value();

    constexpr auto request_timeout = std::chrono::milliseconds{300};
    protocol::ControlRequest request{};
    request.operation.operations.push_back(protocol::SingleOperationRequest{
        process_test::kEchoOperationId, {process_test::kBlockUntilServerShutdownValue}});

    const auto start_time = std::chrono::steady_clock::now();
    const auto response = client->SendRequest(request, request_timeout);
    const auto elapsed = std::chrono::steady_clock::now() - start_time;

    ASSERT_FALSE(response.has_value());
    EXPECT_EQ(response.error(), score::crypto::CryptoErrorCode::kOperationResponseTimedOut);
    EXPECT_GE(elapsed, request_timeout);
    EXPECT_LE(elapsed, request_timeout + score::crypto::ipc::kTimeoutGracePeriod + std::chrono::milliseconds{1000});
    std::cout << "CLIENT_TIMEOUT_ELAPSED_MS=" << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
              << '\n';
}

TEST(MessagePassingClientProcessTest, CancellationTokenIsObservedByServer)
{
    const char* service_identifier_env = std::getenv("MESSAGE_PASSING_SERVICE_ID");
    const std::string_view service_identifier = (service_identifier_env == nullptr)
                                                    ? process_test::kServiceIdentifier
                                                    : std::string_view{service_identifier_env};
    ASSERT_FALSE(service_identifier.empty());

    const char* cancellation_marker = std::getenv("MESSAGE_PASSING_CANCELLATION_MARKER");
    ASSERT_NE(cancellation_marker, nullptr) << "MESSAGE_PASSING_CANCELLATION_MARKER is not set";

    auto client_result = score::crypto::ipc::message_passing::MessagePassingControlClient::Create(service_identifier);
    ASSERT_TRUE(client_result.has_value()) << "Failed to create message-passing client";
    auto client = std::move(client_result).value();
    score::crypto::ipc::message_passing::CancellationSource cancellation_source{};
    const auto cancellation_token = cancellation_source.GetToken();
    using ClientResult = score::crypto::Expected<protocol::ControlResponse, score::crypto::CryptoErrorCode>;
    std::promise<ClientResult> response_promise;
    auto response_future = response_promise.get_future();

    std::thread request_thread([client, cancellation_token, &response_promise]() mutable {
        protocol::ControlRequest request{};
        request.operation.operations.push_back(protocol::SingleOperationRequest{
            process_test::kEchoOperationId, {process_test::kWaitForClientCancellationValue}});
        response_promise.set_value(client->SendRequest(request, std::chrono::seconds{8}, cancellation_token));
    });

    bool server_handler_entered{false};
    const auto handler_start_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (std::chrono::steady_clock::now() < handler_start_deadline)
    {
        std::ifstream marker_file{cancellation_marker};
        if (marker_file.good())
        {
            server_handler_entered = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }

    cancellation_source.RequestCancellation();
    const auto response_ready = response_future.wait_for(std::chrono::seconds{10}) == std::future_status::ready;
    request_thread.join();

    ASSERT_TRUE(server_handler_entered) << "The server handler did not start before cancellation";
    ASSERT_TRUE(response_ready) << "The client request did not finish after cancellation";
    const auto response = response_future.get();
    ASSERT_TRUE(response.has_value()) << "Client request failed with error "
                                      << static_cast<std::uint32_t>(response.error());
    ASSERT_EQ(response->operation.operations.size(), 1U);
    EXPECT_EQ(response->operation.operations.front().result,
              static_cast<protocol::OperationResult>(score::crypto::CryptoErrorCode::kOperationCancelled));
}

TEST(MessagePassingClientProcessTest, CrashesAfterSuccessfulRequest)
{
    const char* service_identifier_env = std::getenv("MESSAGE_PASSING_SERVICE_ID");
    const std::string_view service_identifier = (service_identifier_env == nullptr)
                                                    ? process_test::kServiceIdentifier
                                                    : std::string_view{service_identifier_env};
    ASSERT_FALSE(service_identifier.empty());

    auto client_result = score::crypto::ipc::message_passing::MessagePassingControlClient::Create(service_identifier);
    ASSERT_TRUE(client_result.has_value()) << "Failed to create message-passing client";
    auto client = std::move(client_result).value();

    protocol::ControlRequest request{};
    request.operation.operations.push_back(
        protocol::SingleOperationRequest{process_test::kEchoOperationId, {process_test::kEchoValue}});
    const auto response = client->SendRequest(request, std::chrono::seconds{5});
    ASSERT_TRUE(response.has_value()) << "Failed to complete request before simulated client crash";
    ASSERT_EQ(response->operation.operations.size(), 1U);
    ASSERT_EQ(response->operation.operations.front().result, protocol::OPERATION_RESULT_SUCCESS);

    std::cout << "CLIENT_CRASHING\n" << std::flush;
    ASSERT_EQ(::kill(::getpid(), SIGKILL), 0);
    FAIL() << "SIGKILL returned instead of terminating the client process";
}
