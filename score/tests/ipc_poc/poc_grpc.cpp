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

/// POC: standalone gRPC round-trip benchmark.
///
/// This POC uses the generated service from poc_control.fbs directly. It does
/// not use the production daemon control-plane adapter or daemon conversions.

#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "flatbuffers/grpc.h"
#include "grpcpp/grpcpp.h"
#include "score/tests/utility/runtime_measurement.hpp"
#include "score/tests/ipc_poc/poc_control.grpc.fb.h"
#include "score/tests/ipc_poc/poc_control_generated.h"
#include "score/tests/ipc_poc/poc_helper.hpp"
#include "score/tests/utility/process_resource_measurement.hpp"

// ---------------------------------------------------------------------------
// Global parameters (set before fork; never mutated after)
// ---------------------------------------------------------------------------

static int g_client_count = 1;       // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_call_count = 1;         // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_client_threads = 1;     // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_server_threads = 1;     // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_sleep_milliseconds = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static bool g_random_wait = false;   // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static std::mutex g_log_mutex; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
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

namespace score::crypto::poc::grpc
{

namespace control = score::crypto::ipc::control;
namespace helper = score::crypto::ipc::poc_helper;

class PocControlService final : public control::PocControlService::Service
{
  public:
    ::grpc::Status Execute(::grpc::ServerContext* /*context*/,
                           const flatbuffers::grpc::Message<control::ControlRequest>* request,
                           flatbuffers::grpc::Message<control::ControlResponse>* response) override
    {
        const auto* request_root = request->GetRoot();
        helper::Request workload_request;
        if (!helper::ParseRequestRoot(request_root, workload_request))
        {
            return ::grpc::Status{::grpc::StatusCode::INVALID_ARGUMENT, "Invalid request"};
        }

        const auto workload_response = helper::ProcessRequest(workload_request);

        if (g_sleep_milliseconds > 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(g_sleep_milliseconds));
        }

        Log("[server] request_id=" + std::to_string(workload_response.request_id) + " -> combined=\"" +
            workload_response.string_value + "\"");

        flatbuffers::grpc::MessageBuilder builder;
        builder.Finish(helper::CreateResponseTable(builder, workload_response));
        *response = builder.GetMessage<control::ControlResponse>();
        return ::grpc::Status::OK;
    }
};

static int RunServer(const std::string& socket_path, const std::vector<pid_t>& child_pids)
{
    const auto resources_before_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    score::crypto::daemon::common::RuntimeMeasurement setup_measurement{kEnableLatencyVerbose};
    ::unlink(socket_path.c_str());

    PocControlService service;
    ::grpc::ServerBuilder builder;
    builder.AddListeningPort("unix:" + socket_path, ::grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    builder.SetSyncServerOption(::grpc::ServerBuilder::SyncServerOption::MIN_POLLERS, g_server_threads);
    builder.SetSyncServerOption(::grpc::ServerBuilder::SyncServerOption::MAX_POLLERS, g_server_threads);
    score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement thread_scope{
        setup_measurement, "POC::Grpc::ServerThreadCreation"};
    auto server = builder.BuildAndStart();
    if (!server)
    {
        LogErr("Failed to start standalone gRPC server on " + socket_path);
        return 1;
    }
    const auto resources_after_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta(
        "poc_grpc_server_thread_creation", resources_before_thread_creation, resources_after_thread_creation);

    Log("[server] started on " + socket_path + " - waiting for all clients to finish...");

    int overall_status = 0;
    for (std::size_t index = 0U; index < child_pids.size(); ++index)
    {
        int wait_status = 0;
        const pid_t pid = ::waitpid(-1, &wait_status, 0);
        if (pid > 0)
        {
            const bool ok = WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0;
            std::ostringstream message;
            message << "[server] child pid=" << pid << (ok ? " exited OK" : " FAILED");
            (ok ? Log : LogErr)(message.str());
            if (!ok)
            {
                overall_status = 1;
            }
        }
    }

    const auto resources_after_workload = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta(
        "poc_grpc_server_workload", resources_after_thread_creation, resources_after_workload);
    server->Shutdown();
    server->Wait();
    ::unlink(socket_path.c_str());
    Log("[server] shutdown complete.");
    return overall_status;
}

static bool RunClient(const std::string& socket_path,
                      const int client_index,
                      const int call_count,
                      const int thread_count)
{
    const auto resources_before_thread_creation = tests::utility::CaptureProcessResourceSnapshot();

    score::crypto::daemon::common::RuntimeMeasurement latency_measurement{kEnableLatencyVerbose};
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    std::unique_ptr<control::PocControlService::Stub> stub;
    {
        score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement connection_scope{
            latency_measurement, "POC::Grpc::ClientConnectionSetup"};
        const auto channel = ::grpc::CreateChannel("unix:" + socket_path, ::grpc::InsecureChannelCredentials());
        stub = control::PocControlService::NewStub(channel);
    }
    std::atomic<int> total_failures{0};
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(thread_count));

    helper::ThreadStartBarrier thread_start_barrier{static_cast<std::size_t>(thread_count)};

    for (int thread_index = 0; thread_index < thread_count; ++thread_index)
    {
        score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement thread_scope{
            latency_measurement, "POC::Grpc::ClientThreadCreation"};
        threads.emplace_back([&, thread_index]() {
            thread_start_barrier.ArriveAndWait();
            int failures = 0;
            for (int call = 0; call < call_count; ++call)
            {
                bool valid = false;
                {
                score::crypto::daemon::common::RuntimeMeasurement::ScopedMeasurement latency_scope{
                    latency_measurement, "POC::Grpc::RoundTrip"};

                const auto workload_request = helper::CreateRequest(client_index, thread_index, call);

                flatbuffers::grpc::MessageBuilder builder;
                builder.Finish(helper::CreateRequestTable(builder, workload_request));
                const auto request = builder.GetMessage<control::ControlRequest>();

                ::grpc::ClientContext context;
                flatbuffers::grpc::Message<control::ControlResponse> response;
                const auto status = stub->Execute(&context, request, &response);
                if (!status.ok())
                {
                    LogErr("[client " + std::to_string(client_index) + "/thread " + std::to_string(thread_index) +
                           "] Execute() failed: " + status.error_message());
                    ++failures;
                    continue;
                }

                const auto* response_root = response.GetRoot();
                std::string received;
                helper::Response workload_response;
                valid = helper::ParseResponseRoot(response_root, workload_response) &&
                    workload_response.request_id == workload_request.request_id &&
                    workload_response.string_value == helper::ProcessRequest(workload_request).string_value;
                if (valid)
                {
                    received = workload_response.string_value;
                }

                if (!valid || !helper::Matches(workload_request, workload_response))
                {
                    LogErr("[client " + std::to_string(client_index) + "/thread " + std::to_string(thread_index) +
                           "] response mismatch: expected=\"" + helper::ProcessRequest(workload_request).string_value +
                           "\" got=\"" + received + "\"");
                    ++failures;
                }
                }
                helper::WaitAfterCall(g_random_wait && valid);
            }
            total_failures.fetch_add(failures, std::memory_order_relaxed);
        });
    }

    thread_start_barrier.WaitForAll();
    const auto resources_after_thread_creation = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta(
        "poc_grpc_client_thread_creation", resources_before_thread_creation, resources_after_thread_creation);
    thread_start_barrier.Release();

    for (auto& thread : threads)
    {
        thread.join();
    }
    const auto resources_after_workload = tests::utility::CaptureProcessResourceSnapshot();
    tests::utility::PrintProcessResourceDelta(
        "poc_grpc_client_workload", resources_after_thread_creation, resources_after_workload);

    const int total = call_count * thread_count;
    const int failures = total_failures.load();
    const int success = total - failures;
    Log("[client " + std::to_string(client_index) + "] Results: " + std::to_string(success) + "/" +
        std::to_string(total) + " calls succeeded, " + std::to_string(failures) + "/" + std::to_string(total) +
        " calls failed");
    return failures == 0;
}

} // namespace score::crypto::poc::grpc

int main(int argc, char** argv)
{
    score::crypto::ipc::poc_helper::PocArguments defaults;
    defaults.client_count = g_client_count;
    defaults.call_count = g_call_count;
    defaults.client_threads = g_client_threads;
    defaults.server_threads = g_server_threads;
    defaults.sleep_milliseconds = g_sleep_milliseconds;
    std::string parse_error;
    const auto parsed_arguments = score::crypto::ipc::poc_helper::ParseArguments(argc, argv, parse_error, defaults);
    if (!parsed_arguments.has_value())
    {
        std::fprintf(stderr, "[main] %s\n", parse_error.c_str());
        return 1;
    }
    g_client_count = parsed_arguments->client_count;
    g_call_count = parsed_arguments->call_count;
    g_client_threads = parsed_arguments->client_threads;
    g_server_threads = parsed_arguments->server_threads;
    g_sleep_milliseconds = parsed_arguments->sleep_milliseconds;
    g_random_wait = parsed_arguments->random_wait;

    std::cout << score::crypto::ipc::poc_helper::SettingsSummary(
                     "poc_grpc",
                     g_client_count,
                     g_call_count,
                     g_client_threads,
                     g_server_threads,
                     g_random_wait)
              << '\n'
              << std::flush;
    const std::string socket_path = " score_poc_grpc_" + std::to_string(::getpid()) + ".sock";
    std::vector<pid_t> child_pids;
    int client_index = -1;
    for (int index = 0; index < g_client_count; ++index)
    {
        const pid_t pid = ::fork();
        if (pid < 0)
        {
            std::perror("[main] fork");
            return 1;
        }
        if (pid == 0)
        {
            client_index = index;
            break;
        }
        child_pids.push_back(pid);
    }

    if (client_index < 0)
    {
        return score::crypto::poc::grpc::RunServer(socket_path, child_pids);
    }
    const bool ok = score::crypto::poc::grpc::RunClient(socket_path, client_index, g_call_count, g_client_threads);
    return ok ? 0 : 1;
}
