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
// This file exists only to test and understand IPC mechanisms and to guide a
// proper implementation. It is kept temporarily as reference and will be
// removed once confidence has been gained in the proper implementation.
// =============================================================================

/// POC: gRPC round-trip benchmark — standalone, no daemon or crypto specifics
///
/// Mirrors poc_low_level.cpp in structure:
///   - fork model: parent = server, children = clients
///   - same CLI flags:  --client_count, --call_count, --client_threads,
///                      --server_threads (accepted but unused — gRPC controls
///                      its own thread pool), --sleep_milliseconds
///   - same per-thread timings and "SKIP FIRST" summary output
///
/// Communication model:
///   Each client thread calls GrpcControlClient::SendRequest() synchronously.
///   The call is blocking: one request in → one response out.  No ticket map
///   or correlation logic is needed because ordering is guaranteed by gRPC.
///
///   The server's EchoRequestHandler concatenates the two input parameters
///   ("<string>_<uint64>") and returns the result as an OwnedString in the
///   response, mirroring what poc_low_level does with its FlatBuffer echo.
///
/// Handler chain:
///   EchoHandlerFactory → EchoRequestHandler
///   No daemon, no data_manager, no crypto, no config.
///
/// Note on --server_threads:
///   GrpcControlServer currently hard-codes MIN/MAX_POLLERS = 1.  The flag
///   is accepted for CLI parity with the other POCs but has no effect on the
///   actual gRPC thread count.
///
/// Usage:
///   bazel run //tests/score_com_poc:poc_grpc
///   bazel run //tests/score_com_poc:poc_grpc -- --client_count=3 --call_count=5
///   bazel run //tests/score_com_poc:poc_grpc -- --client_count=3 --call_count=5 --client_threads=4
///   bazel run //tests/score_com_poc:poc_grpc -- --sleep_milliseconds=50

#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <variant>
#include <vector>

#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/control_plane/i_handler_chain_factory.hpp"
#include "score/crypto/src/daemon/control_plane/i_request_handler.hpp"
#include "score/crypto/src/ipc/grpc_adapter/grpc_control_client.h"
#include "score/crypto/src/ipc/grpc_adapter/grpc_control_server.h"

// ---------------------------------------------------------------------------
// Global parameters (set before fork; never mutated after)
// ---------------------------------------------------------------------------

static int g_client_count = 20;       // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_call_count = 20;         // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_client_threads = 20;     // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_server_threads = 8;      // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_sleep_milliseconds = 0;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

// ---------------------------------------------------------------------------
// Shared logging helper
// ---------------------------------------------------------------------------

static std::mutex g_log_mutex;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static void Log(const std::string& line)
{
    std::lock_guard<std::mutex> lk(g_log_mutex);
    std::cout << line << "\n";
}

// ---------------------------------------------------------------------------
// Echo handler — concatenates "<string>_<uint64>" and returns it
// No daemon, no data_manager, no config
// ---------------------------------------------------------------------------

namespace score::crypto::poc::grpc
{

namespace proto = daemon::control_plane::protocol;

class EchoRequestHandler : public daemon::control_plane::IRequestHandler
{
  public:
    daemon::control_plane::ControlResponse processRequest(daemon::control_plane::ControlRequest& request) override
    {
        proto::ControlResponse response;
        response.request_id = request.request_id;

        if (request.operation.operations.empty())
        {
            return response;
        }

        const auto& op = request.operation.operations[0];

        // Extract string (arrives as string_view into the FlatBuffer — safe here, we copy it)
        std::string str_value;
        if (!op.parameters.empty() && std::holds_alternative<std::string_view>(op.parameters[0]))
        {
            str_value = std::string(std::get<std::string_view>(op.parameters[0]));
        }

        // Extract uint64
        std::uint64_t uint64_value = 0U;
        if (op.parameters.size() >= 2 && std::holds_alternative<std::uint64_t>(op.parameters[1]))
        {
            uint64_value = std::get<std::uint64_t>(op.parameters[1]);
        }

        if (g_sleep_milliseconds > 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(g_sleep_milliseconds));
        }

        const std::string combined = str_value + "_" + std::to_string(uint64_value);

        {
            std::ostringstream ss;
            ss << "[server/handler] request_id=" << request.request_id << " -> combined=\"" << combined << "\"";
            Log(ss.str());
        }

        // Return combined string as OwnedString and the uint64 echo.
        // OperationResponseBuilder has no return_value_string(), so we push the
        // OwnedString directly into the last operation's parameters after build().
        proto::OperationResponseBuilder builder;
        builder.operation(op.operationId).return_success().return_value_uint64(uint64_value);

        auto built = builder.build();
        if (built.has_value())
        {
            if (!built.value().operations.empty())
            {
                built.value().operations.back().parameters.push_back(proto::OwnedString{combined});
            }
            response.operation = std::move(built.value());
        }

        return response;
    }
};

class EchoHandlerFactory : public daemon::control_plane::IHandlerChainFactory
{
  public:
    std::unique_ptr<daemon::control_plane::IRequestHandler> CreateRequestHandler() override
    {
        return std::make_unique<EchoRequestHandler>();
    }
};

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

static int RunServer(const std::string& socket_path, const std::vector<pid_t>& child_pids)
{
    auto factory = std::make_unique<EchoHandlerFactory>();
    ipc::GrpcControlServer server(std::move(factory));

    std::thread server_thread([&server, &socket_path]() {
        server.Start(socket_path);
        server.WaitForTermination();
    });

    Log("[server] started on " + socket_path + " — waiting for all clients to finish...");

    int overall_status = 0;
    for (std::size_t i = 0U; i < child_pids.size(); ++i)
    {
        int wstatus = 0;
        const pid_t pid = ::waitpid(-1, &wstatus, 0);
        if (pid > 0)
        {
            const bool ok = WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0;
            std::ostringstream ss;
            ss << "[server] child pid=" << pid << (ok ? " exited OK" : " FAILED");
            Log(ss.str());
            if (!ok)
            {
                overall_status = 1;
            }
        }
    }

    server.Stop();
    if (server_thread.joinable())
    {
        server_thread.join();
    }

    Log("[server] shutdown complete.");
    return overall_status;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

static bool RunClient(const std::string& socket_path,
                      const int client_index,
                      const int call_count,
                      const int thread_count)
{
    // Give the server time to bind before the first connection attempt.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // One gRPC channel shared by all threads — gRPC channels are thread-safe.
    // SendRequest() blocks the calling thread until the response arrives;
    // multiple threads can issue concurrent calls without extra synchronization.
    ipc::GrpcControlClient client(socket_path);

    std::atomic<int> total_failures{0};
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(thread_count));

    for (int t = 0; t < thread_count; ++t)
    {
        threads.emplace_back([&, t]() {
            int failures = 0;
            auto times = std::vector<std::chrono::nanoseconds>(call_count);

            for (int c = 0; c < call_count; ++c)
            {
                auto start_time = std::chrono::system_clock::now();

                const std::string str_param = "client" + std::to_string(client_index + 1);
                const std::uint64_t uint64_param = static_cast<std::uint64_t>(c + 1);
                const std::string expected_combined = str_param + "_" + std::to_string(uint64_param);

                // operationActor encodes the client index so the server log is readable.
                const daemon::common::OperationIdentifier opId{
                    /*operationActor=*/static_cast<std::uint16_t>(client_index + 1),
                    /*operationAction=*/1U,
                };

                auto requestResult = proto::ControlRequestBuilder()
                                         .forDataNodeId(0)
                                         .operation(opId)
                                         .with_in_string(str_param)
                                         .with_in_val_uint64(uint64_param)
                                         .build();

                if (!requestResult.has_value())
                {
                    std::ostringstream ss;
                    ss << "[client " << client_index << "/thread " << t << "] build() failed for call " << c;
                    Log(ss.str());
                    ++failures;
                    continue;
                }

                {
                    std::ostringstream ss;
                    ss << "[client " << client_index << "/thread " << t << "] -> SendRequest() str=\"" << str_param
                       << "\" uint64=" << uint64_param;
                    Log(ss.str());
                }

                // Synchronous blocking call — no ticket map needed.
                // GrpcControlClient overwrites request_id internally; the response
                // request_id matches the auto-generated one used on the wire.
                auto responseResult = client.SendRequest(requestResult.value());

                if (!responseResult.has_value())
                {
                    std::ostringstream ss;
                    ss << "[client " << client_index << "/thread " << t << "] SendRequest() failed for call " << c;
                    Log(ss.str());
                    ++failures;
                    continue;
                }

                const auto& resp = responseResult.value();

                // Validate: one operation, success result, uint64 echo matches, combined string matches.
                bool ok = !resp.operation.operations.empty() &&
                          resp.operation.operations[0].result == proto::OPERATION_RESULT_SUCCESS;

                std::string got_combined;
                if (ok)
                {
                    const auto& params = resp.operation.operations[0].parameters;
                    // param[0] = uint64 echo
                    auto u64 = resp.operation.operations[0].getParameter<std::uint64_t>(0);
                    ok = u64.has_value() && (u64.value() == uint64_param);

                    // param[1] = combined OwnedString
                    if (ok && params.size() >= 2)
                    {
                        auto str = resp.operation.operations[0].getParameter<proto::OwnedString>(1);
                        if (str.has_value())
                        {
                            got_combined = str.value();
                            ok = (got_combined == expected_combined);
                        }
                        else
                        {
                            ok = false;
                        }
                    }
                }

                if (!ok)
                {
                    std::ostringstream ss;
                    ss << "[client " << client_index << "/thread " << t << "] MISMATCH or error for call " << c
                       << ": expected combined=\"" << expected_combined << "\" got=\"" << got_combined << "\"";
                    Log(ss.str());
                    ++failures;
                    continue;
                }

                {
                    std::ostringstream ss;
                    ss << "[client " << client_index << "/thread " << t << "] <- OK combined=\"" << got_combined
                       << "\"";
                    Log(ss.str());
                }

                auto end_time = std::chrono::system_clock::now();
                times[c] = end_time - start_time;
            }

            // Per-call timings
            for (int c = 0; c < call_count; ++c)
            {
                std::ostringstream oss;
                oss << "[client " << client_index << "/thread " << t << "] call " << (c + 1) << "/" << call_count
                    << ": " << std::chrono::duration_cast<std::chrono::microseconds>(times[c]).count() << " us";
                Log(oss.str());
            }

            // Summary
            if (failures == 0)
            {
                auto sum = std::chrono::duration<double>::zero();
                for (int c = 0; c < call_count; ++c)
                {
                    sum += times[c];
                }

                std::ostringstream oss;
                oss << "- [client " << client_index << "/thread " << t << "] completed " << call_count << " calls with "
                    << std::chrono::duration_cast<std::chrono::microseconds>(sum).count() << " us elapsed, average "
                    << std::chrono::duration_cast<std::chrono::microseconds>(sum).count() / call_count
                    << " us per call";
                Log(oss.str());

                if (call_count > 1)
                {
                    auto s = sum - times[0];
                    std::ostringstream oss2;
                    oss2 << "SKIP FIRST [client " << client_index << "/thread " << t << "] completed "
                         << (call_count - 1) << " calls with "
                         << std::chrono::duration_cast<std::chrono::microseconds>(s).count() << " us elapsed, average "
                         << std::chrono::duration_cast<std::chrono::microseconds>(s).count() / (call_count - 1)
                         << " us per call";
                    Log(oss2.str());
                }
            }

            total_failures.fetch_add(failures, std::memory_order_relaxed);
        });
    }

    for (auto& th : threads)
    {
        th.join();
    }

    const int total = call_count * thread_count;
    const int failures = total_failures.load();
    const int success = total - failures;
    std::ostringstream ss;
    ss << "[client " << client_index << "] Results: " << success << "/" << total << " calls succeeded, " << failures
       << "/" << total << " calls failed (" << thread_count << " thread(s) x " << call_count << " call(s))";
    Log(ss.str());

    return failures == 0;
}

}  // namespace score::crypto::poc::grpc

// ---------------------------------------------------------------------------
// main — fork before any gRPC setup for a clean per-process state
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    const std::string kClientPrefix{"--client_count="};
    const std::string kCallPrefix{"--call_count="};
    const std::string kClientThreadsPrefix{"--client_threads="};
    const std::string kServerThreadsPrefix{"--server_threads="};
    const std::string kSleepPrefix{"--sleep_milliseconds="};

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg{argv[i]};
        try
        {
            if (arg.rfind(kClientPrefix, 0) == 0)
                g_client_count = std::stoi(arg.substr(kClientPrefix.size()));
            else if (arg.rfind(kCallPrefix, 0) == 0)
                g_call_count = std::stoi(arg.substr(kCallPrefix.size()));
            else if (arg.rfind(kClientThreadsPrefix, 0) == 0)
                g_client_threads = std::stoi(arg.substr(kClientThreadsPrefix.size()));
            else if (arg.rfind(kServerThreadsPrefix, 0) == 0)
                g_server_threads = std::stoi(arg.substr(kServerThreadsPrefix.size()));
            else if (arg.rfind(kSleepPrefix, 0) == 0)
                g_sleep_milliseconds = std::stoi(arg.substr(kSleepPrefix.size()));
        }
        catch (const std::exception& ex)
        {
            std::fprintf(stderr, "[main] invalid argument '%s': %s\n", argv[i], ex.what());
            return 1;
        }
    }

    if (g_client_count < 1)
    {
        std::fprintf(stderr, "[main] --client_count must be >= 1\n");
        return 1;
    }
    if (g_call_count < 1)
    {
        std::fprintf(stderr, "[main] --call_count must be >= 1\n");
        return 1;
    }
    if (g_client_threads < 1)
    {
        std::fprintf(stderr, "[main] --client_threads must be >= 1\n");
        return 1;
    }
    if (g_server_threads < 1)
    {
        std::fprintf(stderr, "[main] --server_threads must be >= 1\n");
        return 1;
    }

    std::printf(
        "[main] client_count=%d  call_count=%d  client_threads=%d"
        "  server_threads=%d (note: gRPC manages its own pool)  sleep_milliseconds=%d\n",
        g_client_count,
        g_call_count,
        g_client_threads,
        g_server_threads,
        g_sleep_milliseconds);

    // Unique socket per run to avoid collisions between concurrent bazel invocations.
    const std::string socket_path = "/tmp/score_poc_grpc_" + std::to_string(::getpid()) + ".sock";

    std::fflush(nullptr);

    std::vector<pid_t> child_pids;
    int my_client_index = -1;

    for (int i = 0; i < g_client_count; ++i)
    {
        const pid_t pid = ::fork();
        if (pid < 0)
        {
            std::perror("[main] fork");
            for (const pid_t cpid : child_pids)
            {
                ::kill(cpid, SIGTERM);
            }
            return 1;
        }
        if (pid == 0)
        {
            my_client_index = i;
            break;
        }
        child_pids.push_back(pid);
    }

    if (my_client_index == -1)
    {
        return score::crypto::poc::grpc::RunServer(socket_path, child_pids);
    }
    else
    {
        const bool ok =
            score::crypto::poc::grpc::RunClient(socket_path, my_client_index, g_call_count, g_client_threads);
        return ok ? 0 : 1;
    }
}
