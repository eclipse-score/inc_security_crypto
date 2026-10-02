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
// This POC mirrors poc_engine, but uses a raw Unix-domain SOCK_STREAM socket
// instead of score::message_passing. The server accepts multiple connections
// on one endpoint and performs each connection's operations on its own thread.
// =============================================================================

/// Usage:
///   bazel run //tests/score_com_poc:poc_unix_socket
///   bazel run //tests/score_com_poc:poc_unix_socket -- --call_count=5
///   bazel run //tests/score_com_poc:poc_unix_socket -- --client_threads=3 --call_count=5
///   bazel run //tests/score_com_poc:poc_unix_socket -- --call_count=3 --sleep_milliseconds=10

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <numeric>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "score/tests/utility/runtime_measurement.hpp"
#include "score/tests/ipc_poc/ipc_buffer.h"
#include "score/tests/ipc_poc/poc_helper.hpp"
#include "score/tests/utility/process_resource_measurement.hpp"

namespace score::crypto::ipc::control
{

namespace helper = score::crypto::ipc::poc_helper;

static int g_call_count = 1000;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_client_threads = 1;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_sleep_milliseconds = 0;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static bool g_random_wait = false;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static std::mutex g_log_mutex;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
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

static std::string SocketPath(const pid_t server_pid)
{
    return " score_crypto_poc_socket_" + std::to_string(server_pid) + ".sock";
}

static bool MakeAddress(const std::string& path, sockaddr_un& address)
{
    if (path.size() >= sizeof(address.sun_path))
    {
        return false;
    }
    address = sockaddr_un{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1U);
    return true;
}

static bool SendAll(const int socket_fd, const std::uint8_t* data, const std::size_t size)
{
    std::size_t sent = 0U;
    while (sent < size)
    {
        const auto result = ::send(socket_fd, data + sent, size - sent, MSG_NOSIGNAL);
        if (result <= 0)
        {
            return false;
        }
        sent += static_cast<std::size_t>(result);
    }
    return true;
}

static bool ReceiveExact(const int socket_fd, std::uint8_t* data, const std::size_t size)
{
    std::size_t received = 0U;
    while (received < size)
    {
        const auto result = ::recv(socket_fd, data + received, size - received, 0);
        if (result <= 0)
        {
            return false;
        }
        received += static_cast<std::size_t>(result);
    }
    return true;
}

static bool SendFrame(const int socket_fd, const std::vector<std::uint8_t>& frame)
{
    if (frame.empty() || frame.size() > kMaxIpcBufferSize)
    {
        return false;
    }
    return SendAll(socket_fd, frame.data(), frame.size());
}

static bool ReceiveFrame(const int socket_fd, std::vector<std::uint8_t>& frame)
{
    std::array<std::uint8_t, sizeof(std::uint32_t)> size_prefix{};
    if (!ReceiveExact(socket_fd, size_prefix.data(), size_prefix.size()))
    {
        return false;
    }

    std::uint32_t payload_size = 0U;
    std::memcpy(&payload_size, size_prefix.data(), sizeof(payload_size));
    if (payload_size == 0U || payload_size > kMaxIpcBufferSize - size_prefix.size())
    {
        return false;
    }

    frame.resize(size_prefix.size() + payload_size);
    std::memcpy(frame.data(), size_prefix.data(), size_prefix.size());
    return ReceiveExact(socket_fd, frame.data() + size_prefix.size(), payload_size);
}

static bool RunServerPerClient(const int client_fd, const int client_index)
{
    bool success = true;
    for (int call = 0; call < g_call_count; ++call)
    {
        std::vector<std::uint8_t> request;
        if (!ReceiveFrame(client_fd, request))
        {
            LogErr("[server client " + std::to_string(client_index) + "] failed to receive request");
            success = false;
            break;
        }

        helper::Response response;
        if (!helper::ProcessRequestBytes(request.data(), request.size(), response))
        {
            LogErr("[server client " + std::to_string(client_index) + "] failed to process request");
            success = false;
            break;
        }
        request = helper::BuildResponseBytes(response);

        if (g_sleep_milliseconds > 0)
        {
            Log("[server client " + std::to_string(client_index) + "] simulating work for " +
                std::to_string(g_sleep_milliseconds) + " ms");
            std::this_thread::sleep_for(std::chrono::milliseconds(g_sleep_milliseconds));
        }
        Log("[server client " + std::to_string(client_index) + "] processed request_id=" +
            std::to_string(response.request_id) + ", sending FlatBuffer response");
        if (!SendFrame(client_fd, request))
        {
            LogErr("[server client " + std::to_string(client_index) + "] failed to send response");
            success = false;
            break;
        }
    }

    ::close(client_fd);
    return success;
}

static bool RunServer(const pid_t client_pid, const int client_thread_count)
{
    const auto resources_before_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    score::crypto::daemon::common::RuntimeMeasurement setup_measurement{kEnableLatencyVerbose};
    const auto socket_path = SocketPath(::getpid());
    const auto listen_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        LogErr("[server] socket() failed: " + std::string{std::strerror(errno)});
        return false;
    }

    sockaddr_un address{};
    if (!MakeAddress(socket_path, address))
    {
        LogErr("[server] socket path is too long");
        ::close(listen_fd);
        return false;
    }
    ::unlink(socket_path.c_str());
    if (::bind(listen_fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0)
    {
        LogErr("[server] bind() failed: " + std::string{std::strerror(errno)});
        ::close(listen_fd);
        ::unlink(socket_path.c_str());
        return false;
    }
    if (::listen(listen_fd, std::max(client_thread_count, 1)) < 0)
    {
        LogErr("[server] listen() failed: " + std::string{std::strerror(errno)});
        ::close(listen_fd);
        ::unlink(socket_path.c_str());
        return false;
    }
    Log("[server] listening on one Unix-domain endpoint: " + socket_path);

    std::vector<std::thread> client_threads;
    client_threads.reserve(static_cast<std::size_t>(client_thread_count));
    std::atomic<int> failures{0};
    bool success = true;
    for (int client_index = 0; client_index < client_thread_count; ++client_index)
    {
        int client_fd = -1;
        {
            score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement connection_scope{
                setup_measurement, "POC::UnixSocket::ServerConnectionSetup"};
            client_fd = ::accept(listen_fd, nullptr, nullptr);
        }
        if (client_fd < 0)
        {
            LogErr("[server] accept() failed: " + std::string{std::strerror(errno)});
            success = false;
            break;
        }
        Log("[server] accepted client connection " + std::to_string(client_index));
        client_threads.emplace_back([client_fd, client_index, &failures] {
            if (!RunServerPerClient(client_fd, client_index))
            {
                failures.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    const auto resources_after_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta("poc_unix_socket_server_thread_creation",
                                              resources_before_thread_creation,
                                              resources_after_thread_creation);

    for (auto& client_thread : client_threads)
    {
        client_thread.join();
    }
    success = success && client_threads.size() == static_cast<std::size_t>(client_thread_count) &&
              failures.load(std::memory_order_relaxed) == 0;

    ::close(listen_fd);
    ::unlink(socket_path.c_str());

    int wait_status = 0;
    const auto waited_pid = waitpid(client_pid, &wait_status, 0);
    const bool client_ok = waited_pid == client_pid && WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0;
    if (client_ok && success)
    {
        Log("[server] client exited OK");
    }
    else
    {
        LogErr("[server] client failed");
    }
    const auto resources_after_workload = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta(
        "poc_unix_socket_server_workload", resources_after_thread_creation, resources_after_workload);
    Log("[server] shutdown complete");
    return success && client_ok;
}

static int ConnectToServer(const std::string& socket_path)
{
    sockaddr_un address{};
    if (!MakeAddress(socket_path, address))
    {
        return -1;
    }

    for (int attempt = 0; attempt < 300; ++attempt)
    {
        const auto socket_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd >= 0 && ::connect(socket_fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0)
        {
            return socket_fd;
        }
        if (socket_fd >= 0)
        {
            ::close(socket_fd);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return -1;
}

static bool RunClientThread(const pid_t server_pid,
                            const int client_index,
                            score::crypto::daemon::common::RuntimeMeasurement& latency_measurement)
{
    int socket_fd = -1;
    {
        score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement connection_scope{
            latency_measurement, "POC::UnixSocket::ClientConnectionSetup"};
        socket_fd = ConnectToServer(SocketPath(server_pid));
    }
    if (socket_fd < 0)
    {
        LogErr("[client] failed to connect to Unix-domain socket");
        return false;
    }
    Log("[client " + std::to_string(client_index) + "] connected to the Unix-domain endpoint");

    bool success = true;
    for (int call = 0; call < g_call_count; ++call)
    {
        {
            score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement latency_scope{
                latency_measurement, "POC::UnixSocket::RoundTrip"};
            const auto workload_request = helper::CreateRequest(0, client_index, call);
            const auto request_id = workload_request.request_id;
            auto request = helper::BuildRequestBytes(workload_request);

            Log("[client " + std::to_string(client_index) + "] sending request_id=" + std::to_string(request_id));
            if (!SendFrame(socket_fd, request))
            {
                LogErr("[client " + std::to_string(client_index) + "] failed to send request");
                success = false;
                break;
            }

            std::vector<std::uint8_t> response;
            helper::Response parsed_response;
            if (!ReceiveFrame(socket_fd, response) ||
                !helper::ParseResponseBytes(response.data(), response.size(), parsed_response) ||
                !helper::Matches(workload_request, parsed_response))
            {
                  LogErr("[client " + std::to_string(client_index) + "] invalid or unexpected response for request_id=" +
                      std::to_string(request_id));
                success = false;
                break;
            }
        }
        helper::WaitAfterCall(g_random_wait);
    }

    ::shutdown(socket_fd, SHUT_RDWR);
    ::close(socket_fd);
    return success;
}

static bool RunClient(const pid_t server_pid, const int client_thread_count)
{
    const auto resources_before_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    score::crypto::daemon::common::RuntimeMeasurement latency_measurement{kEnableLatencyVerbose};
    std::atomic<int> failures{0};
    std::vector<std::thread> client_threads;
    client_threads.reserve(static_cast<std::size_t>(client_thread_count));
    helper::ThreadStartBarrier thread_start_barrier{static_cast<std::size_t>(client_thread_count)};

    for (int client_index = 0; client_index < client_thread_count; ++client_index)
    {
        score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement thread_scope{
            latency_measurement, "POC::UnixSocket::ClientThreadCreation"};
        client_threads.emplace_back([&, client_index] {
            thread_start_barrier.ArriveAndWait();
            if (!RunClientThread(server_pid, client_index, latency_measurement))
            {
                failures.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    thread_start_barrier.WaitForAll();
    const auto resources_after_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta("poc_unix_socket_client_thread_creation",
                                              resources_before_thread_creation,
                                              resources_after_thread_creation);
    thread_start_barrier.Release();

    for (auto& client_thread : client_threads)
    {
        client_thread.join();
    }
    const auto resources_after_workload = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta(
        "poc_unix_socket_client_workload", resources_after_thread_creation, resources_after_workload);
    return failures.load(std::memory_order_relaxed) == 0;
}

}  // namespace score::crypto::ipc::control

int main(int argc, char** argv)
{
    score::crypto::ipc::poc_helper::PocArguments defaults;
    defaults.call_count = score::crypto::ipc::control::g_call_count;
    defaults.sleep_milliseconds = score::crypto::ipc::control::g_sleep_milliseconds;
    std::string parse_error;
    const auto parsed_arguments = score::crypto::ipc::poc_helper::ParseArguments(argc, argv, parse_error, defaults);
    if (!parsed_arguments.has_value())
    {
        score::crypto::ipc::control::LogErr("[main] " + parse_error);
        return 1;
    }
    score::crypto::ipc::control::g_call_count = parsed_arguments->call_count;
    score::crypto::ipc::control::g_client_threads = parsed_arguments->client_threads;
    score::crypto::ipc::control::g_sleep_milliseconds = parsed_arguments->sleep_milliseconds;
    score::crypto::ipc::control::g_random_wait = parsed_arguments->random_wait;

    std::cout << score::crypto::ipc::poc_helper::SettingsSummary(
                     "poc_unix_socket",
                     1,
                     score::crypto::ipc::control::g_call_count,
                     score::crypto::ipc::control::g_client_threads,
                     score::crypto::ipc::control::g_client_threads,
                     score::crypto::ipc::control::g_random_wait)
              << '\n'
              << std::flush;
    const auto server_pid = ::fork();
    if (server_pid < 0)
    {
        std::perror("[main] fork");
        return 1;
    }
    if (server_pid == 0)
    {
        return score::crypto::ipc::control::RunClient(::getppid(),
                                                      score::crypto::ipc::control::g_client_threads)
                   ? 0
                   : 1;
    }
    return score::crypto::ipc::control::RunServer(server_pid, score::crypto::ipc::control::g_client_threads) ? 0 : 1;
}
