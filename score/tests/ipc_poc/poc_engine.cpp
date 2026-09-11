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

// =============================================================================
// WARNING: EXPERIMENTAL REFERENCE CODE - DO NOT USE IN PRODUCTION
//
// This POC demonstrates a bootstrap connection that creates one on-demand
// message_passing endpoint/Engine session per client thread. Each server Engine
// performs the operation in its callback and returns the complete FlatBuffer
// response with Reply(). No application worker thread or Notify() path is used.
// =============================================================================

/// Usage:
///   bazel run //tests/score_com_poc:poc_engine
///   bazel run //tests/score_com_poc:poc_engine -- --call_count=5
///   bazel run //tests/score_com_poc:poc_engine -- --client_threads=3 --call_count=5
///   bazel run //tests/score_com_poc:poc_engine -- --call_count=3 --sleep_milliseconds=10

#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <numeric>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "score/message_passing/client_factory.h"
#include "score/message_passing/i_client_connection.h"
#include "score/message_passing/i_server_connection.h"
#include "score/message_passing/server_factory.h"
#include "score/message_passing/service_protocol_config.h"
#include "score/tests/utility/runtime_measurement.hpp"
#include "score/tests/ipc_poc/ipc_buffer.h"
#include "score/tests/ipc_poc/poc_helper.hpp"
#include "score/tests/utility/process_resource_measurement.hpp"

namespace score::crypto::ipc::control
{

namespace helper = score::crypto::ipc::poc_helper;

static constexpr std::string_view kBootstrapServiceIdentifier{"score_crypto_poc_engine_bootstrap"};

static helper::PocArguments g_arguments{};  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static std::mutex g_log_mutex;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static std::atomic<std::uint64_t> g_session_counter{0U};
static constexpr bool kEnableVerboseOutput{false};
static constexpr bool kEnableLatencyVerbose{false};

static void Log(const std::string& line)
{
    if (!kEnableVerboseOutput)
    {
        return;
    }
    std::lock_guard<std::mutex> lock{g_log_mutex};
    std::cout << line << "\n";
}

static void LogErr(const std::string& line)
{
    std::lock_guard<std::mutex> lock{g_log_mutex};
    std::cerr << "[ERROR] " << line << "\n";
}

static std::string MakeSessionServiceIdentifier()
{
    const auto session_number = g_session_counter.fetch_add(1U, std::memory_order_relaxed);
    return std::string{kBootstrapServiceIdentifier} + "_session_" + std::to_string(session_number);
}

static score::message_passing::ServiceProtocolConfig MakeProtocolConfig(const std::string_view service_identifier)
{
    return score::message_passing::ServiceProtocolConfig{
        service_identifier,
        /*max_send_size=*/static_cast<std::uint32_t>(sizeof(IpcBuffer)),
        /*max_reply_size=*/static_cast<std::uint32_t>(sizeof(IpcBuffer)),
        /*max_notify_size=*/static_cast<std::uint32_t>(sizeof(IpcBuffer)),
    };
}

static score::message_passing::IServerFactory::ServerConfig MakeBootstrapServerConfig(const int client_threads)
{
    return score::message_passing::IServerFactory::ServerConfig{
        /*max_queued_sends=*/static_cast<std::uint32_t>(client_threads),
        /*pre_alloc_connections=*/0U,
        /*max_queued_notifies=*/0U,
    };
}

static score::message_passing::IServerFactory::ServerConfig MakeSessionServerConfig()
{
    return score::message_passing::IServerFactory::ServerConfig{
        /*max_queued_sends=*/1U,
        /*pre_alloc_connections=*/0U,
        /*max_queued_notifies=*/0U,
    };
}

static score::message_passing::IClientFactory::ClientConfig MakeClientConfig()
{
    return score::message_passing::IClientFactory::ClientConfig{
        /*max_async_replies=*/1U,
        /*max_queued_sends=*/1U,
        /*fully_ordered=*/true,
        /*truly_async=*/true,
        /*sync_first_connect=*/false,
    };
}

struct EngineSession
{
    explicit EngineSession(std::string identifier) : endpoint_identifier{std::move(identifier)} {}

    std::string endpoint_identifier;
    std::unique_ptr<score::message_passing::ServerFactory> server_factory;
    score::cpp::pmr::unique_ptr<score::message_passing::IServer> server;
};

struct BootstrapState
{
    explicit BootstrapState(const int maximum_sessions) : maximum_sessions{maximum_sessions} {}

    const int maximum_sessions;
    std::mutex sessions_mutex;
    std::condition_variable sessions_condition;
    std::size_t ready_sessions{0U};
    std::vector<std::shared_ptr<EngineSession>> sessions;
};

static bool StartEngineSession(const std::shared_ptr<EngineSession>& session)
{
    const auto connect_callback = [](score::message_passing::IServerConnection& connection)
        -> score::cpp::expected<score::message_passing::UserData, score::os::Error> {
        std::ostringstream log;
        log << "[server] accepted uid=" << connection.GetClientIdentity().uid;
        Log(log.str());
        return score::message_passing::UserData{static_cast<void*>(nullptr)};
    };

    const auto disconnect_callback = [](score::message_passing::IServerConnection& connection) {
        Log("[server] client disconnected uid=" + std::to_string(connection.GetClientIdentity().uid));
    };

    // This callback is executed by the server's message_passing Engine thread.
    // Deliberately doing the operation here demonstrates the requested model:
    // there is no POC-owned work queue and no application worker thread.
    const auto request_callback = [](score::message_passing::IServerConnection& connection,
                                     score::cpp::span<const std::uint8_t> message)
        -> score::cpp::expected_blank<score::os::Error> {
        helper::Response response;
        if (!helper::ProcessRequestBytes(message.data(), message.size(), response))
        {
            LogErr("[server/engine] request validation or processing failed");
            return score::cpp::make_unexpected(score::os::Error::createFromErrno(EINVAL));
        }

        const auto response_bytes = helper::BuildResponseBytes(response);

        if (g_arguments.sleep_milliseconds > 0)
        {
            Log("[server/engine] simulating work for " + std::to_string(g_arguments.sleep_milliseconds) + " ms");
            std::this_thread::sleep_for(std::chrono::milliseconds(g_arguments.sleep_milliseconds));
        }

        Log("[server/engine] processed request_id=" + std::to_string(response.request_id) +
            ", replying with FlatBuffer");
        return connection.Reply(score::cpp::span<const std::uint8_t>{response_bytes.data(), response_bytes.size()});
    };

    session->server_factory = std::make_unique<score::message_passing::ServerFactory>();
    session->server = session->server_factory->Create(
        MakeProtocolConfig(session->endpoint_identifier), MakeSessionServerConfig());
    if (!session->server)
    {
        LogErr("[server] failed to create endpoint " + session->endpoint_identifier);
        return false;
    }

    const auto start_result = session->server->StartListening(
        connect_callback, disconnect_callback, /*sent_callback=*/{}, request_callback);
    if (!start_result.has_value())
    {
        LogErr("[server] failed to start endpoint " + session->endpoint_identifier);
        return false;
    }

    Log("[server] started endpoint " + session->endpoint_identifier);
    return true;
}

static bool RunServer(const pid_t client_pid, const int thread_count)
{
    const auto resources_before_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    score::crypto::daemon::common::RuntimeMeasurement setup_measurement{kEnableLatencyVerbose};
    auto bootstrap_state = std::make_shared<BootstrapState>(thread_count);
    bootstrap_state->sessions.reserve(static_cast<std::size_t>(thread_count));

    const auto connect_callback = [](score::message_passing::IServerConnection& connection)
        -> score::cpp::expected<score::message_passing::UserData, score::os::Error> {
        Log("[bootstrap] accepted uid=" + std::to_string(connection.GetClientIdentity().uid));
        return score::message_passing::UserData{static_cast<void*>(nullptr)};
    };

    const auto disconnect_callback = [](score::message_passing::IServerConnection& connection) {
        Log("[bootstrap] client disconnected uid=" + std::to_string(connection.GetClientIdentity().uid));
    };

    const auto request_callback = [bootstrap_state](
                                     score::message_passing::IServerConnection& connection,
                                     score::cpp::span<const std::uint8_t> message)
        -> score::cpp::expected_blank<score::os::Error> {
        helper::Request request;
        if (!helper::ParseRequestBytes(message.data(), message.size(), request))
        {
            LogErr("[bootstrap] invalid session request");
            return score::cpp::make_unexpected(score::os::Error::createFromErrno(EINVAL));
        }

        auto session = std::make_shared<EngineSession>(MakeSessionServiceIdentifier());
        {
            std::lock_guard<std::mutex> lock{bootstrap_state->sessions_mutex};
            if (bootstrap_state->sessions.size() >= static_cast<std::size_t>(bootstrap_state->maximum_sessions))
            {
                LogErr("[bootstrap] session limit reached");
                return score::cpp::make_unexpected(score::os::Error::createFromErrno(EBUSY));
            }
            bootstrap_state->sessions.push_back(session);
        }

        if (!StartEngineSession(session))
        {
            LogErr("[bootstrap] Engine session failed to start");
            return score::cpp::make_unexpected(score::os::Error::createFromErrno(EIO));
        }

        {
            std::lock_guard<std::mutex> lock{bootstrap_state->sessions_mutex};
            ++bootstrap_state->ready_sessions;
        }
        bootstrap_state->sessions_condition.notify_one();

        const helper::Response response{request.request_id, session->endpoint_identifier};
        const auto response_bytes = helper::BuildResponseBytes(response);
        return connection.Reply(score::cpp::span<const std::uint8_t>{response_bytes.data(), response_bytes.size()});
    };

    auto bootstrap_factory = std::make_unique<score::message_passing::ServerFactory>();
    auto bootstrap_server = bootstrap_factory->Create(
        MakeProtocolConfig(kBootstrapServiceIdentifier), MakeBootstrapServerConfig(thread_count));
    if (!bootstrap_server)
    {
        LogErr("[bootstrap] failed to create endpoint");
        return false;
    }

    const auto start_result = bootstrap_server->StartListening(
        connect_callback, disconnect_callback, /*sent_callback=*/{}, request_callback);
    if (!start_result.has_value())
    {
        LogErr("[bootstrap] failed to start endpoint");
        return false;
    }
    Log("[bootstrap] started endpoint " + std::string{kBootstrapServiceIdentifier});

    {
        std::unique_lock<std::mutex> lock{bootstrap_state->sessions_mutex};
        if (!bootstrap_state->sessions_condition.wait_for(lock, std::chrono::seconds(30), [&] {
            return bootstrap_state->ready_sessions == static_cast<std::size_t>(thread_count);
            }))
        {
            LogErr("[server] timed out waiting for all Engine sessions to start");
        }
    }

    const auto resources_after_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta(
        "poc_engine_server_thread_creation", resources_before_thread_creation, resources_after_thread_creation);

    int wait_status = 0;
    const auto waited_pid = waitpid(client_pid, &wait_status, 0);
    const bool client_ok = waited_pid == client_pid && WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0;
    if (client_ok)
    {
        Log("[server] client exited OK");
    }
    else
    {
        LogErr("[server] client failed");
    }

    const auto resources_after_workload = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta(
        "poc_engine_server_workload", resources_after_thread_creation, resources_after_workload);
    bootstrap_server->StopListening();
    for (const auto& session : bootstrap_state->sessions)
    {
        if (session->server)
        {
            session->server->StopListening();
        }
    }
    Log("[server] shutdown complete");
    return client_ok;
}

struct ResponseState
{
    std::mutex mutex;
    std::condition_variable condition;
    bool ready{false};
    bool ok{false};
    std::string value;
};

static void SetResponse(ResponseState& state, const bool ok, std::string value)
{
    {
        std::lock_guard<std::mutex> lock{state.mutex};
        state.ok = ok;
        state.value = std::move(value);
        state.ready = true;
    }
    state.condition.notify_one();
}

static bool RunBootstrapHandshake(const int thread_index, std::string& endpoint_identifier)
{
    score::message_passing::ClientFactory client_factory;
    auto client = client_factory.Create(MakeProtocolConfig(kBootstrapServiceIdentifier), MakeClientConfig());
    if (!client)
    {
        LogErr("[client " + std::to_string(thread_index) + "] failed to create bootstrap connection");
        return false;
    }

    struct ConnectionState
    {
        std::mutex mutex;
        std::condition_variable condition;
        bool ready{false};
        bool stopped{false};
    } connection_state;

    client->Start(
        [&connection_state](score::message_passing::IClientConnection::State state) {
            std::lock_guard<std::mutex> lock{connection_state.mutex};
            if (state == score::message_passing::IClientConnection::State::kReady)
            {
                connection_state.ready = true;
            }
            else if (state == score::message_passing::IClientConnection::State::kStopped)
            {
                connection_state.stopped = true;
            }
            connection_state.condition.notify_one();
        },
        /*notify_callback=*/{});

    {
        std::unique_lock<std::mutex> lock{connection_state.mutex};
        if (!connection_state.condition.wait_for(lock, std::chrono::seconds(30), [&] {
                return connection_state.ready;
            }))
        {
            LogErr("[client " + std::to_string(thread_index) + "] bootstrap connection timed out");
            client->Stop();
            return false;
        }
    }

    auto response_state = std::make_shared<ResponseState>();
    const auto request = helper::CreateRequest(0, thread_index, 0);
    const auto request_bytes = helper::BuildRequestBytes(request);
    {
        const auto send_result = client->SendWithCallback(
            score::cpp::span<const std::uint8_t>{request_bytes.data(), request_bytes.size()},
            [response_state, request_id = request.request_id](
                score::cpp::expected<score::cpp::span<const std::uint8_t>, score::os::Error> response) {
                if (!response.has_value())
                {
                    SetResponse(*response_state, false, {});
                    return;
                }
                helper::Response parsed_response;
                if (!helper::ParseResponseBytes(response->data(), response->size(), parsed_response) ||
                    parsed_response.request_id != request_id)
                {
                    SetResponse(*response_state, false, {});
                    return;
                }
                SetResponse(*response_state, true, std::move(parsed_response.string_value));
            });
        if (!send_result.has_value())
        {
            LogErr("[client " + std::to_string(thread_index) + "] bootstrap request failed");
            client->Stop();
            return false;
        }
    }

    {
        std::unique_lock<std::mutex> lock{response_state->mutex};
        if (!response_state->condition.wait_for(lock, std::chrono::seconds(30), [&] {
                return response_state->ready;
            }) || !response_state->ok)
        {
            LogErr("[client " + std::to_string(thread_index) + "] bootstrap response timed out");
            client->Stop();
            return false;
        }
        endpoint_identifier = response_state->value;
    }

    client->Stop();
    {
        std::unique_lock<std::mutex> lock{connection_state.mutex};
        if (!connection_state.condition.wait_for(lock, std::chrono::seconds(30), [&] {
                return connection_state.stopped;
            }))
        {
            LogErr("[client " + std::to_string(thread_index) + "] bootstrap shutdown timed out");
            return false;
        }
    }
    return true;
}

static bool RunClientThread(const int thread_index,
                            const int call_count,
                            score::crypto::daemon::common::RuntimeMeasurement& latency_measurement,
                            helper::ThreadStartBarrier& bootstrap_ready_barrier,
                            helper::ThreadStartBarrier& connection_ready_barrier)
{
    std::string endpoint_identifier;
    {
        score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement setup_scope{
            latency_measurement, "POC::Engine::ClientThreadCreationAndBootstrapHandshake"};
        if (!RunBootstrapHandshake(thread_index, endpoint_identifier))
        {
            bootstrap_ready_barrier.ArriveAndWait();
            connection_ready_barrier.ArriveAndWait();
            return false;
        }
        bootstrap_ready_barrier.ArriveAndWait();
    }

    score::message_passing::ClientFactory client_factory;
    decltype(client_factory.Create(MakeProtocolConfig(endpoint_identifier), MakeClientConfig())) client;

    struct ConnectionState
    {
        std::mutex mutex;
        std::condition_variable condition;
        bool ready{false};
        bool stopped{false};
    } connection_state;

    {
        score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement setup_scope{
            latency_measurement, "POC::Engine::ClientConnectionSetup"};
        client = client_factory.Create(MakeProtocolConfig(endpoint_identifier), MakeClientConfig());
        if (!client)
        {
            LogErr("[client " + std::to_string(thread_index) + "] failed to create connection");
            connection_ready_barrier.ArriveAndWait();
            return false;
        }

        client->Start(
            [&connection_state, thread_index](score::message_passing::IClientConnection::State state) {
                std::lock_guard<std::mutex> lock{connection_state.mutex};
                if (state == score::message_passing::IClientConnection::State::kReady)
                {
                    connection_state.ready = true;
                    connection_state.condition.notify_one();
                    Log("[client " + std::to_string(thread_index) + "] connection ready");
                }
                else if (state == score::message_passing::IClientConnection::State::kStopped)
                {
                    connection_state.stopped = true;
                    connection_state.condition.notify_one();
                }
            },
            // The response callback also runs on the client Engine thread.
            [](score::cpp::span<const std::uint8_t>) {});

        std::unique_lock<std::mutex> lock{connection_state.mutex};
        if (!connection_state.condition.wait_for(lock, std::chrono::seconds(30), [&] {
                return connection_state.ready;
            }))
        {
            LogErr("[client " + std::to_string(thread_index) + "] timed out waiting for connection");
            client->Stop();
            connection_ready_barrier.ArriveAndWait();
            return false;
        }
    }

    connection_ready_barrier.ArriveAndWait();

    bool success = true;
    for (int call = 0; call < call_count; ++call)
    {
        {
            score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement latency_scope{
                latency_measurement, "POC::Engine::RoundTrip"};

        const auto workload_request = helper::CreateRequest(0, thread_index, call);
        const auto request_id = workload_request.request_id;
        const auto request_bytes = helper::BuildRequestBytes(workload_request);
        auto response_state = std::make_shared<ResponseState>();

            Log("[client] SendWithCallback request_id=" + std::to_string(request_id));
            const auto send_result = client->SendWithCallback(
                score::cpp::span<const std::uint8_t>{request_bytes.data(), request_bytes.size()},
                [response_state, request_id](
                    score::cpp::expected<score::cpp::span<const std::uint8_t>, score::os::Error> response) {
                    if (!response.has_value())
                    {
                        SetResponse(*response_state, false, {});
                        LogErr("[client/engine] ReplyCallback failed for request_id=" + std::to_string(request_id));
                        return;
                    }

                    helper::Response parsed_response;
                    if (!helper::ParseResponseBytes(response->data(), response->size(), parsed_response) ||
                        parsed_response.request_id != request_id)
                    {
                        SetResponse(*response_state, false, {});
                        LogErr("[client/engine] response string missing for request_id=" +
                               std::to_string(request_id));
                        return;
                    }
                    SetResponse(*response_state, true, std::move(parsed_response.string_value));
                });

            if (!send_result.has_value())
            {
                LogErr("[client " + std::to_string(thread_index) + "] SendWithCallback failed for request_id=" +
                       std::to_string(request_id));
                success = false;
                break;
            }

            std::unique_lock<std::mutex> lock{response_state->mutex};
            const bool received = response_state->condition.wait_for(lock, std::chrono::seconds(30), [&] {
                return response_state->ready;
            });
            if (!received || !response_state->ok ||
                !helper::Matches(workload_request, helper::Response{request_id, response_state->value}))
            {
                LogErr("[client " + std::to_string(thread_index) + "] response mismatch or timeout for request_id=" +
                       std::to_string(request_id));
                success = false;
                break;
            }
        }

        helper::WaitAfterCall(g_arguments.random_wait);
    }

    client->Stop();
    {
        std::unique_lock<std::mutex> lock{connection_state.mutex};
        if (!connection_state.condition.wait_for(lock, std::chrono::seconds(30), [&] {
                return connection_state.stopped;
            }))
        {
            LogErr("[client] timed out waiting for connection shutdown");
            success = false;
        }
    }
    return success;
}

static bool RunClient(const int thread_count)
{
    const auto resources_before_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    score::crypto::daemon::common::RuntimeMeasurement latency_measurement{kEnableLatencyVerbose};
    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(thread_count));
    helper::ThreadStartBarrier thread_start_barrier{static_cast<std::size_t>(thread_count)};
    helper::ThreadStartBarrier bootstrap_ready_barrier{static_cast<std::size_t>(thread_count)};
    helper::ThreadStartBarrier connection_ready_barrier{static_cast<std::size_t>(thread_count)};

    for (int thread_index = 0; thread_index < thread_count; ++thread_index)
    {
        threads.emplace_back([&, thread_index] {
            thread_start_barrier.ArriveAndWait();
            if (!RunClientThread(thread_index,
                                 g_arguments.call_count,
                                 latency_measurement,
                                 bootstrap_ready_barrier,
                                 connection_ready_barrier))
            {
                failures.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    thread_start_barrier.WaitForAll();
    thread_start_barrier.Release();
    bootstrap_ready_barrier.WaitForAll();
    bootstrap_ready_barrier.Release();

    connection_ready_barrier.WaitForAll();
    const auto resources_after_connection_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta("poc_engine_client_connection_thread_creation",
                                              resources_before_thread_creation,
                                              resources_after_connection_thread_creation);
    connection_ready_barrier.Release();

    for (auto& thread : threads)
    {
        thread.join();
    }
    const auto resources_after_workload = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta(
        "poc_engine_client_workload", resources_after_connection_thread_creation, resources_after_workload);
    return failures.load(std::memory_order_relaxed) == 0;
}

}  // namespace score::crypto::ipc::control

int main(int argc, char** argv)
{
    std::string parse_error;
    const auto parsed_arguments = score::crypto::ipc::poc_helper::ParseArguments(argc, argv, parse_error);
    if (!parsed_arguments.has_value())
    {
        score::crypto::ipc::control::LogErr("[main] " + parse_error);
        return 1;
    }
    score::crypto::ipc::control::g_arguments = *parsed_arguments;

    std::cout << score::crypto::ipc::poc_helper::SettingsSummary(
                     "poc_engine",
                     1,
                     score::crypto::ipc::control::g_arguments.call_count,
                     score::crypto::ipc::control::g_arguments.client_threads,
                     score::crypto::ipc::control::g_arguments.client_threads,
                     score::crypto::ipc::control::g_arguments.random_wait)
              << '\n'
              << std::flush;
    const auto client_pid = ::fork();
    if (client_pid < 0)
    {
        std::perror("[main] fork");
        return 1;
    }
    if (client_pid == 0)
    {
        return score::crypto::ipc::control::RunClient(score::crypto::ipc::control::g_arguments.client_threads) ? 0 : 1;
    }
    return score::crypto::ipc::control::RunServer(client_pid, score::crypto::ipc::control::g_arguments.client_threads) ? 0 : 1;
}
