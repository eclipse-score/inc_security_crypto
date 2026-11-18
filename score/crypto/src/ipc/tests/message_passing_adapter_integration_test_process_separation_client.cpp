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

#include "score/crypto/src/daemon/control_plane/control_protocol.h"
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
namespace protocol = score::crypto::daemon::control_plane::protocol;
using ClientResult = score::crypto::Expected<protocol::ControlResponse, score::crypto::CryptoErrorCode>;
using ClientResult = score::crypto::Expected<protocol::ControlResponse, score::crypto::CryptoErrorCode>;

class ScopedEffectiveUid final
{
  public:
    ScopedEffectiveUid() noexcept : m_original_effective_uid(::geteuid()) {}

    ~ScopedEffectiveUid() noexcept
    {
        static_cast<void>(RestoreOriginal());
    }

    bool SwitchTo(const uid_t effective_uid) noexcept
    {
        return ::seteuid(effective_uid) == 0;
    }

    bool RestoreOriginal() noexcept
    {
        return ::seteuid(m_original_effective_uid) == 0;
    }

  private:
    const uid_t m_original_effective_uid;
};

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
                    request.operations.push_back(
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
            ASSERT_EQ(response->operations.size(), 1U);

            const auto process_request_index = thread_index * requests_per_thread + request_index;
            const auto expected_payload =
                static_cast<std::uint64_t>(client_index * requests_per_process + process_request_index + 1U);
            const auto& operation = response->operations.front();
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
        request.operations.push_back(
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

TEST(MessagePassingClientProcessTest, AuthorizationUsesEffectiveUidFromConnectionTime)
{
    if (::geteuid() != 0)
    {
        GTEST_SKIP() << "Changing effective UID requires a privileged test process";
    }

    const char* service_identifier_env = std::getenv("MESSAGE_PASSING_SERVICE_ID");
    const std::string_view service_identifier = (service_identifier_env == nullptr)
                                                    ? process_test::kServiceIdentifier
                                                    : std::string_view{service_identifier_env};
    ASSERT_FALSE(service_identifier.empty());

    // Connecting to the service with the allowed non-root UID
    ScopedEffectiveUid effective_uid{};
    ASSERT_TRUE(effective_uid.SwitchTo(static_cast<uid_t>(process_test::kAllowedNonRootUid)))
        << "Failed to switch to the allowed non-root UID";

    auto client_result = score::crypto::ipc::message_passing::MessagePassingControlClient::Create(service_identifier);
    ASSERT_TRUE(client_result.has_value()) << "Failed to connect with the initial effective UID";
    auto client = std::move(client_result).value();

    // Ensure connection is authorized for the allowed non-root UID
    protocol::ControlRequest allowed_connection_request{};
    allowed_connection_request.operations.push_back(
        protocol::SingleOperationRequest{process_test::kEchoOperationId, {process_test::kEchoValue}});
    const auto allowed_connection_response = client->SendRequest(allowed_connection_request, std::chrono::seconds{5});
    ASSERT_TRUE(allowed_connection_response.has_value()) << "The server rejected the allowed non-root UID";
    ASSERT_EQ(allowed_connection_response->operations.size(), 1U);
    EXPECT_EQ(allowed_connection_response->operations.front().result, protocol::OPERATION_RESULT_SUCCESS);

    // Switching to the denied non-root UID and verifying the existing connection remains authorized
    ASSERT_TRUE(effective_uid.RestoreOriginal()) << "Failed to restore the privileged effective UID";
    ASSERT_TRUE(effective_uid.SwitchTo(static_cast<uid_t>(process_test::kDeniedNonRootUid)))
        << "Failed to switch to the denied non-root UID";
    protocol::ControlRequest request_after_uid_change{};
    request_after_uid_change.operations.push_back(
        protocol::SingleOperationRequest{process_test::kEchoOperationId, {process_test::kEchoValue + 1U}});
    const auto response_after_uid_change = client->SendRequest(request_after_uid_change, std::chrono::seconds{5});
    ASSERT_TRUE(response_after_uid_change.has_value())
        << "The existing connection lost its authorization after the UID change";
    ASSERT_EQ(response_after_uid_change->operations.size(), 1U);
    EXPECT_EQ(response_after_uid_change->operations.front().result, protocol::OPERATION_RESULT_SUCCESS);

    // Attempting to establish a new connection with the denied non-root UID
    auto denied_uid_connection_result =
        score::crypto::ipc::message_passing::MessagePassingControlClient::Create(service_identifier);
    auto denied_uid_error = score::crypto::CryptoErrorCode::kInternalError;
    if (!denied_uid_connection_result.has_value())
    {
        denied_uid_error = denied_uid_connection_result.error();
    }
    else
    {
        auto denied_uid_client = std::move(denied_uid_connection_result).value();
        protocol::ControlRequest denied_uid_request{};
        denied_uid_request.operations.push_back(
            protocol::SingleOperationRequest{process_test::kEchoOperationId, {process_test::kEchoValue + 2U}});
        const auto denied_uid_response = denied_uid_client->SendRequest(denied_uid_request, std::chrono::seconds{5});
        ASSERT_FALSE(denied_uid_response.has_value()) << "A new connection with the denied UID was authorized";
        denied_uid_error = denied_uid_response.error();
    }

#if defined(__QNX__)
    EXPECT_EQ(denied_uid_error, score::crypto::CryptoErrorCode::kAccessDenied);
#else
    EXPECT_EQ(denied_uid_error, score::crypto::CryptoErrorCode::kConnectionFailed);
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
    request.operations.push_back(
        protocol::SingleOperationRequest{process_test::kEchoOperationId, {process_test::kLongRunningOperationValue}});

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
    request.operations.push_back(
        protocol::SingleOperationRequest{process_test::kEchoOperationId, {process_test::kEchoValue}});
    const auto response = client->SendRequest(request, std::chrono::seconds{5});
    ASSERT_TRUE(response.has_value()) << "Failed to complete request before simulated client crash";
    ASSERT_EQ(response->operations.size(), 1U);
    ASSERT_EQ(response->operations.front().result, protocol::OPERATION_RESULT_SUCCESS);

    std::cout << "CLIENT_CRASHING\n" << std::flush;
    ASSERT_EQ(::kill(::getpid(), SIGKILL), 0);
    FAIL() << "SIGKILL returned instead of terminating the client process";
}
