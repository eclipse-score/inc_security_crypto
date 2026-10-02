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

// =============================================================================
// WARNING: EXPERIMENTAL REFERENCE CODE - DO NOT USE IN PRODUCTION
//
// This POC mirrors poc_unix_socket, but uses native QNX message passing:
// ChannelCreate(), ConnectAttach(), MsgSend(), MsgReceive(), and MsgReply().
// Multiple client threads attach to one channel. The server dispatches each
// sending thread's requests to one worker thread before replying.
// =============================================================================

/// Usage:
///   bazel run //tests/score_com_poc:poc_qnx_message_passing --config=x86_64-qnx
///   bazel run //tests/score_com_poc:poc_qnx_message_passing --config=x86_64-qnx -- --call_count=5
///   bazel run //tests/score_com_poc:poc_qnx_message_passing --config=x86_64-qnx -- --client_threads=3 --call_count=5
///   bazel run //tests/score_com_poc:poc_qnx_message_passing --config=x86_64-qnx -- --call_count=3 --sleep_milliseconds=10

#include <sys/neutrino.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "score/tests/utility/runtime_measurement.hpp"
#include "score/tests/ipc_poc/ipc_buffer.h"
#include "score/tests/ipc_poc/poc_helper.hpp"
#include "score/tests/utility/process_resource_measurement.hpp"

namespace score::crypto::ipc::control
{

namespace helper = score::crypto::ipc::poc_helper;

static int g_call_count = 100;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_client_threads = 4;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
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

static bool ProcessRequestBytes(const std::uint8_t* message_data,
                                const std::size_t message_size,
                                std::uint64_t& request_id,
                                std::vector<std::uint8_t>& response)
{
    helper::Response workload_response;
    if (!helper::ProcessRequestBytes(message_data, message_size, workload_response))
    {
        return false;
    }
    request_id = workload_response.request_id;
    response = helper::BuildResponseBytes(workload_response);
    return response.size() <= kMaxIpcBufferSize;
}

static bool GetResponseSize(const std::array<std::uint8_t, kMaxIpcBufferSize>& response,
                            std::size_t& response_size)
{
    std::uint32_t payload_size = 0U;
    std::memcpy(&payload_size, response.data(), sizeof(payload_size));
    if (payload_size == 0U || payload_size > kMaxIpcBufferSize - sizeof(payload_size))
    {
        return false;
    }
    response_size = sizeof(payload_size) + static_cast<std::size_t>(payload_size);
    return true;
}

using ReceiveId = decltype(::MsgReceive(0, nullptr, 0, nullptr));

static bool RunServerRequest(const ReceiveId rcvid,
                             std::vector<std::uint8_t> request,
                             const int client_index)
{
    std::uint64_t request_id = 0U;
    std::vector<std::uint8_t> response;
    if (!ProcessRequestBytes(request.data(), request.size(), request_id, response))
    {
        LogErr("[server worker " + std::to_string(client_index) + "] invalid request message");
        if (::MsgError(static_cast<int>(rcvid), EINVAL) == -1)
        {
            LogErr("[server worker " + std::to_string(client_index) + "] MsgError() failed: " +
                   std::string{std::strerror(errno)});
        }
        return false;
    }

    if (g_sleep_milliseconds > 0)
    {
        Log("[server worker " + std::to_string(client_index) + "] simulating work for " +
            std::to_string(g_sleep_milliseconds) + " ms");
        std::this_thread::sleep_for(std::chrono::milliseconds(g_sleep_milliseconds));
    }

    Log("[server worker " + std::to_string(client_index) + "] processed request_id=" +
        std::to_string(request_id) + ", sending FlatBuffer response");
    if (::MsgReply(static_cast<int>(rcvid), EOK, response.data(), response.size()) == -1)
    {
        LogErr("[server worker " + std::to_string(client_index) + "] MsgReply() failed: " +
               std::string{std::strerror(errno)});
        return false;
    }
    return true;
}

static void RunServerWorker(const int chid,
                            const int worker_index,
                            std::atomic<bool>& stopping,
                            std::atomic<std::size_t>& received_request_count,
                            std::atomic<int>& failures)
{
    while (!stopping.load(std::memory_order_acquire))
    {
        std::array<std::uint8_t, kMaxIpcBufferSize> request_buffer{};
        _msg_info message_info{};
        const auto rcvid = ::MsgReceive(chid, request_buffer.data(), request_buffer.size(), &message_info);
        if (rcvid == 0)
        {
            const auto* pulse = reinterpret_cast<const _pulse*>(request_buffer.data());
            if (pulse->code == _PULSE_CODE_DISCONNECT)
            {
                Log("[server worker " + std::to_string(worker_index) + "] client disconnected");
                continue;
            }
            Log("[server] ignored pulse code=" + std::to_string(pulse->code));
            continue;
        }
        if (rcvid < 0)
        {
            if (!stopping.load(std::memory_order_acquire))
            {
                LogErr("[server worker " + std::to_string(worker_index) + "] MsgReceive() failed: " +
                       std::string{std::strerror(errno)});
                failures.fetch_add(1, std::memory_order_relaxed);
            }
            return;
        }

        const auto message_size = static_cast<std::size_t>(message_info.msglen);
        received_request_count.fetch_add(1U, std::memory_order_relaxed);
        if (message_size == 0U || message_size > request_buffer.size())
        {
            LogErr("[server worker " + std::to_string(worker_index) + "] invalid request message");
            if (::MsgError(static_cast<int>(rcvid), EINVAL) == -1)
            {
                LogErr("[server worker " + std::to_string(worker_index) + "] MsgError() failed: " +
                       std::string{std::strerror(errno)});
            }
            failures.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        std::vector<std::uint8_t> request{request_buffer.begin(), request_buffer.begin() + message_size};
        if (!RunServerRequest(rcvid, std::move(request), worker_index))
        {
            failures.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

static bool RunServer(const int chid, const pid_t client_pid, const int server_thread_count)
{
    const auto resources_before_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    score::crypto::daemon::common::RuntimeMeasurement setup_measurement{kEnableLatencyVerbose};
    Log("[server] waiting for QNX message-passing requests on channel " + std::to_string(chid));

    const auto expected_request_count = static_cast<std::size_t>(g_client_threads) *
                                        static_cast<std::size_t>(g_call_count);
    std::atomic<bool> stopping{false};
    std::atomic<std::size_t> received_request_count{0U};
    std::atomic<int> failures{0};
    std::vector<std::thread> server_threads;
    server_threads.reserve(static_cast<std::size_t>(server_thread_count));
    for (int worker_index = 0; worker_index < server_thread_count; ++worker_index)
    {
        score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement thread_scope{
            setup_measurement, "POC::QnxMessagePassing::ServerWorkerThreadCreation"};
        server_threads.emplace_back([&, worker_index] {
            RunServerWorker(chid, worker_index, stopping, received_request_count, failures);
        });
    }

    const auto resources_after_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta("poc_qnx_message_passing_server_thread_creation",
                                              resources_before_thread_creation,
                                              resources_after_thread_creation);

    int wait_status = 0;
    const auto waited_pid = ::waitpid(client_pid, &wait_status, 0);
    const bool client_ok = waited_pid == client_pid && WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0;
    stopping.store(true, std::memory_order_release);
    if (::ChannelDestroy(chid) == -1)
    {
        LogErr("[server] ChannelDestroy() failed: " + std::string{std::strerror(errno)});
    }
    for (auto& server_thread : server_threads)
    {
        server_thread.join();
    }
    const auto resources_after_workload = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta(
        "poc_qnx_message_passing_server_workload", resources_after_thread_creation, resources_after_workload);
    const bool success = client_ok && received_request_count.load(std::memory_order_relaxed) == expected_request_count &&
                         failures.load(std::memory_order_relaxed) == 0;
    if (client_ok && success)
    {
        Log("[server] client exited OK");
    }
    else
    {
        LogErr("[server] client failed");
    }
    Log("[server] shutdown complete");
    return success && client_ok;
}

static int ConnectToServer(const pid_t server_pid, const int chid)
{
    for (int attempt = 0; attempt < 300; ++attempt)
    {
        const auto coid = ::ConnectAttach(0, server_pid, chid, _NTO_SIDE_CHANNEL, 0);
        if (coid >= 0)
        {
            return coid;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return -1;
}

static bool RunClientThread(const pid_t server_pid,
                            const int chid,
                            const int client_index,
                            score::crypto::daemon::common::RuntimeMeasurement& latency_measurement)
{
    int coid = -1;
    {
        score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement connection_scope{
            latency_measurement, "POC::QnxMessagePassing::ClientConnectionSetup"};
        coid = ConnectToServer(server_pid, chid);
    }
    if (coid < 0)
    {
        LogErr("[client " + std::to_string(client_index) + "] ConnectAttach() failed: " +
               std::string{std::strerror(errno)});
        return false;
    }
    Log("[client " + std::to_string(client_index) + "] connected to QNX message-passing channel " +
        std::to_string(chid));

    bool success = true;
    for (int call = 0; call < g_call_count; ++call)
    {
        {
            score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement latency_scope{
                latency_measurement, "POC::QnxMessagePassing::RoundTrip"};
            const auto workload_request = helper::CreateRequest(0, client_index, call);
            const auto request_id = workload_request.request_id;
            const auto request = helper::BuildRequestBytes(workload_request);
            std::array<std::uint8_t, kMaxIpcBufferSize> response{};

            Log("[client " + std::to_string(client_index) + "] sending request_id=" +
                std::to_string(request_id));
            const auto send_status = ::MsgSend(coid,
                                               request.data(),
                                               static_cast<int>(request.size()),
                                               response.data(),
                                               static_cast<int>(response.size()));
            if (send_status != EOK)
            {
                LogErr("[client " + std::to_string(client_index) + "] MsgSend() failed with status=" +
                       std::to_string(send_status));
                success = false;
                break;
            }

            std::size_t response_size = 0U;
            helper::Response parsed_response;
            if (!GetResponseSize(response, response_size) ||
                !helper::ParseResponseBytes(response.data(), response_size, parsed_response) ||
                !helper::Matches(workload_request, parsed_response))
            {
                LogErr("[client " + std::to_string(client_index) +
                       "] invalid or unexpected response for request_id=" + std::to_string(request_id));
                success = false;
                break;
            }
        }
        helper::WaitAfterCall(g_random_wait);
    }

    if (::ConnectDetach(coid) == -1)
    {
        LogErr("[client " + std::to_string(client_index) + "] ConnectDetach() failed: " +
               std::string{std::strerror(errno)});
        success = false;
    }
    return success;
}

static bool RunClient(const pid_t server_pid, const int chid, const int client_thread_count)
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
            latency_measurement, "POC::QnxMessagePassing::ClientThreadCreation"};
        client_threads.emplace_back([&, client_index] {
            thread_start_barrier.ArriveAndWait();
            if (!RunClientThread(server_pid, chid, client_index, latency_measurement))
            {
                failures.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    thread_start_barrier.WaitForAll();
    const auto resources_after_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta("poc_qnx_message_passing_client_thread_creation",
                                              resources_before_thread_creation,
                                              resources_after_thread_creation);
    thread_start_barrier.Release();

    for (auto& client_thread : client_threads)
    {
        client_thread.join();
    }
    const auto resources_after_workload = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta(
        "poc_qnx_message_passing_client_workload", resources_after_thread_creation, resources_after_workload);
    return failures.load(std::memory_order_relaxed) == 0;
}

}  // namespace score::crypto::ipc::control

int main(int argc, char** argv)
{
    score::crypto::ipc::poc_helper::PocArguments defaults;
    defaults.call_count = score::crypto::ipc::control::g_call_count;
    defaults.client_threads = score::crypto::ipc::control::g_client_threads;
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
                     "poc_qnx_message_passing",
                     1,
                     score::crypto::ipc::control::g_call_count,
                     score::crypto::ipc::control::g_client_threads,
                     score::crypto::ipc::control::g_client_threads,
                     score::crypto::ipc::control::g_random_wait)
              << '\n'
              << std::flush;
    const auto chid = ::ChannelCreate(0);
    if (chid < 0)
    {
        score::crypto::ipc::control::LogErr("[main] ChannelCreate() failed: " + std::string{std::strerror(errno)});
        return 1;
    }

    const auto server_pid = ::fork();
    if (server_pid < 0)
    {
        score::crypto::ipc::control::LogErr("[main] fork() failed: " + std::string{std::strerror(errno)});
        ::ChannelDestroy(chid);
        return 1;
    }
    if (server_pid == 0)
    {
        return score::crypto::ipc::control::RunClient(::getppid(),
                                                      chid,
                                                      score::crypto::ipc::control::g_client_threads)
                   ? 0
                   : 1;
    }
    return score::crypto::ipc::control::RunServer(
               chid, server_pid, score::crypto::ipc::control::g_client_threads)
               ? 0
               : 1;
}
