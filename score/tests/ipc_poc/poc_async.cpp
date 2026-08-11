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

/// POC: Short-Lived Async Method Call + Event Response + Single-Binary Fork Model
///
/// Communication model (two phases):
///
///   Phase 1 — Short-lived Method call
///     The client builds a ControlRequest FlatBuffer and embeds a self-chosen
///     request_id (the "ticket number").  It calls AsyncControlProxy::request(),
///     which blocks only until the server enqueues the work and returns the
///     ticket.  No real processing happens on the method-handler thread.
///
///   Phase 2 — Event-based response
///     A server background worker dequeues each request, does the actual work,
///     and calls AsyncControlSkeleton::response.Send().  The ControlResponse
///     FlatBuffer in the event payload carries the original request_id so every
///     subscribing client can match the event to its outstanding ticket.
///
/// Process model:
///   A single binary is forked before InitializeRuntime is called so every
///   child process starts with a clean mw::com runtime state.
///
///     Parent process → server  (skeleton + thread pool of worker threads)
///     Child  process → client  (proxy + event subscriber)
///
///   The parent waits for all children via waitpid before stopping the service.
///
/// Usage:
///   bazel run //tests/score_com_poc:poc_async
///   bazel run //tests/score_com_poc:poc_async -- --client_count=3 --call_count=5
///   bazel run //tests/score_com_poc:poc_async -- --client_count=3 --call_count=5
///   bazel run //tests/score_com_poc:poc_async -- --client_count=3 --call_count=5 --client_threads=4
///   bazel run //tests/score_com_poc:poc_async -- --client_count=3 --call_count=5 --server_threads=2
///   bazel run //tests/score_com_poc:poc_async -- --client_count=3 --call_count=5 --client_threads=4 --server_threads=2
///   bazel run //tests/score_com_poc:poc_async -- --sleep_milliseconds=500

#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "flatbuffers/flatbuffers.h"
#include "score/mw/com/impl/proxy_base.h"
#include "score/mw/com/runtime.h"
#include "score/mw/com/runtime_configuration.h"
#include "score/mw/com/types.h"
#include "score/tests/ipc_poc/async_control_interface.h"
#include "score/tests/ipc_poc/ipc_buffer.h"
#include "score/tests/ipc_poc/poc_control_generated.h"

// ---------------------------------------------------------------------------
// Global parameters (set before fork; never mutated after)
// ---------------------------------------------------------------------------

static int g_client_count = 2;        // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_call_count = 2;          // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_client_threads = 2;      // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_server_threads = 8;      // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_sleep_milliseconds = 0;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

namespace score::crypto::ipc::control
{

/// Returns the shared "serviceTypes" JSON block (without trailing comma).
static std::string ServiceTypesJson()
{
    return
        R"(    "serviceTypes": [
        {
            "serviceTypeName": "/score/crypto/poc/AsyncControlService",
            "version": { "major": 1, "minor": 0 },
            "bindings": [
                {
                    "binding": "SHM",
                    "serviceId": 0,
                    "methods": [
                        { "methodName": "Request", "methodId": 1 }
                    ],
                    "events": [
                        { "eventName": "Response", "eventId": 2 }
                    ]
                }
            ]
        }
    ])";
}

/// Returns a single "serviceInstances" entry JSON block for the given instance_id.
static std::string ServiceInstanceJson(const int instance_id)
{
    // It seems the queueSize of the method shall match the numberOfSampleSlots of the event
    // considering we have only one subscriber.

    std::ostringstream ss;
    ss << "        {\n"
       << "            \"instanceSpecifier\": \"poc/AsyncControlPort_" << instance_id << "\",\n"
       << "            \"serviceTypeName\": \"/score/crypto/poc/AsyncControlService\",\n"
       << "            \"version\": { \"major\": 1, \"minor\": 0 },\n"
       << "            \"instances\": [\n"
       << "                {\n"
       << "                    \"instanceId\": " << instance_id << ",\n"
       << "                    \"asil-level\": \"QM\",\n"
       << "                    \"binding\": \"SHM\",\n"
       << "                    \"methods\": [\n"
       << "                        { \"methodName\": \"Request\", \"queueSize\": "
       << std::max(8, 2 * g_call_count * g_client_threads) << " }\n"
       << "                    ],\n"
       << "                    \"events\": [\n"
       << "                        {\n"
       << "                            \"eventName\": \"Response\",\n"
       << "                            \"numberOfSampleSlots\": " << std::max(8, 2 * 100 * g_client_threads)
       << ",\n"
       // This even accounts for multiple threads per client
       // Thus if we want 2 threads waiting "method results", we need to allow at least 2 subsribers
       << "                            \"maxSubscribers\": " << g_client_threads << "\n"
       << "                        }\n"
       << "                    ]\n"
       << "                }\n"
       << "            ]\n"
       << "        }";
    return ss.str();
}

/// Generates and writes all mw::com JSON config files needed for client_count consumers.
///
/// Producer config (score/tests/ipc_poc/mw_com_config_async_producer.json):
///   Contains all client_count service instances.  applicationID = 1000.
///
/// Consumer config i (score/tests/ipc_poc/mw_com_config_async_consumer_<i>.json):
///   Contains only service instance i.  applicationID = 1001 + i.
static void SetupConfigs(const int client_count)
{
    // --- Producer config (all instances) ---
    {
        std::ostringstream instances;
        for (int i = 0; i < client_count; ++i)
        {
            if (i > 0)
            {
                instances << ",\n";
            }
            instances << ServiceInstanceJson(i);
        }

        std::ostringstream json;
        json << "{\n"
             << ServiceTypesJson() << ",\n"
             << "    \"serviceInstances\": [\n"
             << instances.str() << "\n"
             << "    ],\n"
             << "    \"global\": {\n"
             << "        \"asil-level\": \"QM\",\n"
             << "        \"applicationID\": 1000\n"
             << "    }\n"
             << "}\n";

        std::ofstream f("score/tests/ipc_poc/mw_com_config_async_producer.json");
        if (!f.is_open())
        {
            std::cerr << "[SetupConfigs] Failed to open producer config for writing\n";
            return;
        }
        f << json.str();
    }

    // --- Per-consumer configs (one service instance each) ---
    for (int i = 0; i < client_count; ++i)
    {
        std::ostringstream json;
        json << "{\n"
             << ServiceTypesJson() << ",\n"
             << "    \"serviceInstances\": [\n"
             << ServiceInstanceJson(i) << "\n"
             << "    ],\n"
             << "    \"global\": {\n"
             << "        \"asil-level\": \"QM\",\n"
             << "        \"applicationID\": " << (1001 + i) << "\n"
             << "    }\n"
             << "}\n";

        const std::string path = "score/tests/ipc_poc/mw_com_config_async_consumer_" + std::to_string(i) + ".json";
        std::ofstream f(path);
        if (!f.is_open())
        {
            std::cerr << "[SetupConfigs] Failed to open consumer config " << i << " for writing\n";
            return;
        }
        f << json.str();
    }

    std::printf("[SetupConfigs] wrote producer + %d consumer config(s)\n", client_count);
}

}  // namespace score::crypto::ipc::control

// ---------------------------------------------------------------------------
// Shared logging helper (mutex protects stdout across threads)
// ---------------------------------------------------------------------------

static std::mutex g_log_mutex;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static void Log(const std::string& line)
{
    std::lock_guard<std::mutex> lk(g_log_mutex);
    std::cout << line << "\n";
}

// ---------------------------------------------------------------------------
// FlatBuffer helpers (shared between server and client)
// ---------------------------------------------------------------------------

namespace score::crypto::ipc::control
{

/// Serialise a ControlResponse carrying a single String result.
static IpcBuffer BuildControlResponse(const std::uint64_t request_id, const std::string& combined)
{
    flatbuffers::FlatBufferBuilder fbb(512);

    auto str_val = fbb.CreateString(combined);
    auto str_tbl = CreateString(fbb, str_val);

    std::vector<uint8_t> resp_param_types{OperationParameter_String};
    std::vector<flatbuffers::Offset<void>> resp_param_values{str_tbl.Union()};

    auto resp_op = CreateSingleOperationResponse(fbb,
                                                 CreateOperationIdentifier(fbb, 0U, 0U),
                                                 CreateOperationResult(fbb, 0U),
                                                 fbb.CreateVector(resp_param_types),
                                                 fbb.CreateVector(resp_param_values));

    auto resp_batch = CreateOperationResponseBatch(fbb, fbb.CreateVector({resp_op}));
    fbb.FinishSizePrefixed(CreateControlResponse(fbb, request_id, resp_batch));
    return PackFlatBuffer(fbb.GetBufferPointer(), fbb.GetSize());
}

/// Deserialise a ControlRequest and produce a ControlResponse: result = "<str>_<uint64>".
static IpcBuffer ProcessRequest(const IpcBuffer& request_buf)
{
    flatbuffers::Verifier verifier{reinterpret_cast<const uint8_t*>(request_buf.payload.data()),
                                   GetPayloadSize(request_buf)};

    if (!VerifySizePrefixedControlRequestBuffer(verifier))
    {
        std::cerr << "[server/worker] FlatBuffer verification failed\n";
        return IpcBuffer{};
    }

    const auto* req = flatbuffers::GetSizePrefixedRoot<ControlRequest>(request_buf.payload.data());
    if (req == nullptr || req->operation_batch() == nullptr || req->operation_batch()->operations() == nullptr ||
        req->operation_batch()->operations()->size() == 0U)
    {
        return IpcBuffer{};
    }

    const auto* op = req->operation_batch()->operations()->Get(0U);
    if (op == nullptr || op->parameter() == nullptr)
    {
        return IpcBuffer{};
    }

    std::string str_value;
    std::uint64_t uint64_value = 0U;

    for (flatbuffers::uoffset_t i = 0U; i < op->parameter()->size(); ++i)
    {
        const auto ptype = static_cast<OperationParameter>(op->parameter_type()->Get(i));
        if (ptype == OperationParameter_String)
        {
            const auto* s = reinterpret_cast<const String*>(op->parameter()->Get(i));
            if (s != nullptr && s->val() != nullptr)
            {
                str_value = s->val()->str();
            }
        }
        else if (ptype == OperationParameter_ValueUint64)
        {
            const auto* v = reinterpret_cast<const ValueUint64*>(op->parameter()->Get(i));
            if (v != nullptr)
            {
                uint64_value = v->val();
            }
        }
    }

    const std::string combined = str_value + "_" + std::to_string(uint64_value);

    {
        std::stringstream ss;
        ss << "[server/worker] ticket=" << req->request_id() << " -> combined=\"" << combined << "\"";
        Log(ss.str());
    }

    return BuildControlResponse(req->request_id(), combined);
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Work item pushed to the background worker queue.
struct WorkItem
{
    std::uint64_t ticket;
    IpcBuffer request;
    std::size_t skeleton_index;  ///< Which service instance this request came from
};

/// Runs the server: skeleton + background worker.
/// Blocks until all client processes have exited (waitpid).
static int RunServer(const std::vector<pid_t>& child_pids)
{
    using score::mw::com::InstanceSpecifier;

    const int client_count = static_cast<int>(child_pids.size());

    score::mw::com::runtime::InitializeRuntime(score::mw::com::runtime::RuntimeConfiguration{
        score::filesystem::Path{"score/tests/ipc_poc/mw_com_config_async_producer.json"}});

    // Create skeletons for both service instances (0 and 1).
    std::vector<AsyncControlSkeleton> skeletons;
    for (int instance_id = 0; instance_id < client_count; ++instance_id)
    {
        const auto instance_spec =
            InstanceSpecifier::Create(std::string{"poc/AsyncControlPort_" + std::to_string(instance_id)}).value();

        auto skel_result = AsyncControlSkeleton::Create(instance_spec);
        if (!skel_result.has_value())
        {
            std::stringstream ss;
            ss << "[server] AsyncControlSkeleton::Create failed for instance " << instance_id;
            std::cerr << ss.str() << "\n";
            return 1;
        }
        skeletons.push_back(std::move(skel_result.value()));

        std::stringstream ss;
        ss << "[server] created skeleton for poc/AsyncControlPort_" << instance_id;
        Log(ss.str());
    }

    // ------------------------------------------------------------------
    // Thread pool: g_server_threads workers dequeue requests, perform work,
    // and fire response events.
    // ------------------------------------------------------------------
    std::mutex queue_mutex;
    std::condition_variable queue_cv;
    std::queue<WorkItem> work_queue;
    std::atomic<bool> stop_worker{false};

    // One mutex per skeleton: response.Send() is not thread-safe when called
    // concurrently on the same skeleton instance from different worker threads.
    // Workers for different skeletons can still proceed in parallel.
    std::vector<std::unique_ptr<std::mutex>> send_mutexes;
    send_mutexes.reserve(skeletons.size());
    for (std::size_t idx = 0; idx < skeletons.size(); ++idx)
    {
        send_mutexes.push_back(std::make_unique<std::mutex>());
    }

    const int worker_count = g_server_threads;
    std::vector<std::thread> workers;
    workers.reserve(static_cast<std::size_t>(worker_count));
    for (int widx = 0; widx < worker_count; ++widx)
    {
        workers.emplace_back([&, widx]() {
            while (true)
            {
                std::unique_lock<std::mutex> lk(queue_mutex);
                queue_cv.wait(lk, [&] {
                    return !work_queue.empty() || stop_worker.load();
                });

                if (stop_worker.load() && work_queue.empty())
                {
                    break;
                }

                WorkItem item = std::move(work_queue.front());
                work_queue.pop();
                lk.unlock();

                IpcBuffer resp_buf = ProcessRequest(item.request);
                if (!IsValid(resp_buf))
                {
                    std::cerr << "[server/worker " << widx << "] ProcessRequest returned invalid buffer "
                              << "for ticket=" << item.ticket << "\n";
                    continue;
                }

                // Simulate processing time (configurable via --sleep_milliseconds).
                if (g_sleep_milliseconds > 0)
                {
                    Log("[server/worker " + std::to_string(widx) + "] simulating work by sleeping for " +
                        std::to_string(g_sleep_milliseconds) + " ms");
                    std::this_thread::sleep_for(std::chrono::milliseconds(g_sleep_milliseconds));
                }

                // Send the response to subscriber via the event of the correct instance.
                // Serialise concurrent Sends on the same skeleton (response.Send is not
                // thread-safe when called from multiple workers for the same instance).
                auto send_result = [&]() {
                    std::lock_guard<std::mutex> send_lk(*send_mutexes[item.skeleton_index]);
                    return skeletons[item.skeleton_index].response.Send(resp_buf);
                }();
                if (!send_result.has_value())
                {
                    std::stringstream ss;
                    ss << "[server/worker " << widx << "] response.Send() failed on skeleton " << item.skeleton_index
                       << " for ticket=" << item.ticket;
                    Log(ss.str());
                }
                else
                {
                    std::stringstream ss;
                    ss << "[server/worker " << widx << "] response event fired on skeleton " << item.skeleton_index
                       << " for ticket=" << item.ticket;
                    Log(ss.str());
                }
            }
        });
    }
    Log("[server] started " + std::to_string(worker_count) + " worker thread(s)");

    // ------------------------------------------------------------------
    // Register the Method handler on all skeletons: enqueue work, return ticket immediately.
    // ------------------------------------------------------------------
    for (std::size_t skel_idx = 0; skel_idx < skeletons.size(); ++skel_idx)
    {
        // Capture skel_idx by value so each handler knows its instance index.
        auto reg_result = skeletons[skel_idx].request.RegisterHandler([&, skel_idx](std::uint64_t& result,
                                                                                    const IpcBuffer& req_buf) {
            const auto* req = flatbuffers::GetSizePrefixedRoot<ControlRequest>(req_buf.payload.data());

            std::stringstream ss1;
            ss1 << "[server/handler] instance=" << skel_idx << " req ptr=" << req;
            Log(ss1.str());

            const std::uint64_t ticket = (req != nullptr) ? req->request_id() : 0U;

            if (req == nullptr || ticket == 0U)
            {
                std::stringstream ss_err;
                ss_err << "[server/handler] instance=" << skel_idx << " WARNING: req=" << req << " ticket=" << ticket
                       << " — FlatBuffer parse failed or zero request_id;"
                          " response will never match a pending client call";
                Log(ss_err.str());
            }

            {
                std::lock_guard<std::mutex> lk(queue_mutex);
                work_queue.push({ticket, req_buf, skel_idx});
            }
            queue_cv.notify_one();

            std::stringstream ss;
            ss << "[server/handler] instance=" << skel_idx << " queued ticket=" << ticket << " (returning immediately)";
            Log(ss.str());

            result = ticket;  // Phase 1 return: the ticket number.
        });

        if (!reg_result.has_value())
        {
            std::stringstream ss;
            ss << "[server] RegisterHandler failed for skeleton " << skel_idx;
            std::cerr << ss.str() << "\n";
            stop_worker.store(true);
            queue_cv.notify_all();
            for (auto& worker_thread : workers)
            {
                worker_thread.join();
            }
            return 1;
        }
    }

    // Offer service on all skeletons
    for (std::size_t i = 0; i < skeletons.size(); ++i)
    {
        if (!skeletons[i].OfferService().has_value())
        {
            std::stringstream ss;
            ss << "[server] OfferService failed for skeleton " << i;
            std::cerr << ss.str() << "\n";
            stop_worker.store(true);
            queue_cv.notify_all();
            for (auto& worker_thread : workers)
            {
                worker_thread.join();
            }
            return 1;
        }
    }

    Log("[server] service offered — waiting for all clients to finish...");

    // ------------------------------------------------------------------
    // Wait for every child process to terminate.
    // ------------------------------------------------------------------
    int overall_status = 0;
    for (std::size_t i = 0U; i < child_pids.size(); ++i)
    {
        int wstatus = 0;
        pid_t pid = waitpid(-1, &wstatus, 0);
        if (pid > 0)
        {
            const bool ok = WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0;
            std::stringstream ss;
            ss << "[server] child pid=" << pid << (ok ? " exited OK" : " FAILED");
            Log(ss.str());
            if (!ok)
            {
                overall_status = 1;
            }
        }
    }

    // ------------------------------------------------------------------
    // Graceful shutdown.
    // ------------------------------------------------------------------
    {
        std::lock_guard<std::mutex> lk(queue_mutex);
        stop_worker.store(true);
    }
    queue_cv.notify_all();
    for (auto& worker_thread : workers)
    {
        worker_thread.join();
    }

    for (std::size_t i = 0; i < skeletons.size(); ++i)
    {
        skeletons[i].StopOfferService();
    }
    Log("[server] shutdown complete.");
    return overall_status;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Per-call wait state shared between the issuing thread and the receive handler.
struct PendingCall
{
    std::uint64_t ticket{0};   ///< Ticket we are currently waiting for.
    bool ready{false};         ///< Set to true when the matching event arrives.
    bool ok{false};            ///< Whether the response was valid.
    std::string result_value;  ///< Extracted combined string from the response.
    std::mutex mutex;
    std::condition_variable cv;
};

static bool RunClient(const int client_index, const int call_count, const int thread_count)
{
    using score::mw::com::InstanceSpecifier;
    using score::mw::com::SamplePtr;
    using score::mw::com::impl::ProxyBase;

    // Small delay so the server has time to offer the service.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Per client config to provide applicationIds
    std::string config_path =
        "score/tests/ipc_poc/mw_com_config_async_consumer_" + std::to_string(client_index) + ".json";
    score::mw::com::runtime::InitializeRuntime(
        score::mw::com::runtime::RuntimeConfiguration{score::filesystem::Path{config_path}});

    const auto instance_spec =
        InstanceSpecifier::Create(std::string{"poc/AsyncControlPort_" + std::to_string(client_index)}).value();

    // Wait until the server has offered the service.
    score::Result<score::mw::com::ServiceHandleContainer<score::mw::com::HandleType>> handles;
    while (true)
    {
        handles = ProxyBase::FindService(instance_spec);
        if (handles.has_value() && !handles->empty())
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::stringstream ss_found;
    ss_found << "[client " << client_index << "] service found";
    Log(ss_found.str());

    // ------------------------------------------------------------------
    // Spawn thread_count worker threads.
    //
    // IMPORTANT: Each thread owns its own AsyncControlProxy instance.
    // The proxy-side call-queue is hardcoded to size 1 in the mw::com
    // implementation (ProxyMethodBase::kCallQueueSize = 1, see
    // score/mw/com/impl/methods/proxy_method_base.h).  Concurrent calls
    // from multiple threads on a single proxy would race on that slot and
    // one thread's Allocate() would always fail with kCallQueueFull.
    // Creating one proxy per thread avoids this limitation completely.
    //
    // Ticket scheme: (client+1)*100_000 + (thread+1)*1_000 + (call+1)
    // Supports up to 99 clients, 99 threads/client, 999 calls/thread.
    // ------------------------------------------------------------------
    const std::size_t kMaxSamples = static_cast<std::size_t>(call_count * 2);

    std::atomic<int> total_failures{0};

    // [LoLa framework limitation — see TODO item 9]
    // LoLa does not support truly concurrent in-flight method calls from
    // different proxy instances to the same skeleton instance.
    //
    // Root cause: ClientConnection::SendWaitReply serialises outgoing messages
    // on a single per-process POSIX socket.  When two proxy threads call
    // DoCall() simultaneously, the second message is queued; when the first
    // reply arrives, ProcessInputEvent() sends the queued message to the server
    // AND fires the first reply callback in that order.  The server can begin
    // writing the return value to the second proxy's SHM buffer before the
    // first proxy has read from its buffer, leaving a zero-initialised slot and
    // yielding ticket=0 back to the caller.
    //
    // Workaround: serialise Phase 1 (the blocking RPC) across all threads of
    // this client with phase1_mutex.  Phase 2 (event wait) runs concurrently.
    std::mutex phase1_mutex;

    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(thread_count));

    // [LoLa framework limitation — see TODO item 8]
    // AsyncControlProxy::Create() must complete for ALL threads before any
    // thread may issue a method call.
    //
    // Root cause: Create() calls SetupMethods() → SubscribeServiceMethod()
    // → ClientConnection::SendWaitReply().  This subscribe IPC message
    // (sizeof = 12 bytes) travels over the exact same POSIX socket as method
    // calls (sizeof = 24 bytes).  If a concurrent thread is mid-call when
    // Create() runs, the two messages interleave in the send queue; the server
    // then receives the wrong payload size, logs:
    //   "Wrong payload size, got 12, expected 24"
    // and tears down the connection, killing the whole client process.
    //
    // Workaround: create and subscribe all proxies here, sequentially, before
    // any worker thread is spawned.
    std::vector<AsyncControlProxy> proxies;
    proxies.reserve(static_cast<std::size_t>(thread_count));
    for (int t = 0; t < thread_count; ++t)
    {
        auto proxy_result = AsyncControlProxy::Create(handles.value()[0]);
        if (!proxy_result.has_value())
        {
            Log("[client " + std::to_string(client_index) + "/thread " + std::to_string(t) +
                "] AsyncControlProxy::Create failed (pre-create)");
            total_failures.fetch_add((thread_count - t) * call_count, std::memory_order_relaxed);
            break;
        }
        if (!proxy_result.value().response.Subscribe(kMaxSamples).has_value())
        {
            Log("[client " + std::to_string(client_index) + "/thread " + std::to_string(t) +
                "] Subscribe failed (pre-create)");
            total_failures.fetch_add((thread_count - t) * call_count, std::memory_order_relaxed);
            break;
        }
        proxies.push_back(std::move(proxy_result.value()));
    }

    for (int t = 0; t < static_cast<int>(proxies.size()); ++t)
    {
        threads.emplace_back([&, t]() {
            auto& proxy = proxies[static_cast<std::size_t>(t)];

            // Within a single thread calls are sequential, so at most one
            // PendingCall is in-flight at a time — no map needed.
            PendingCall pending;

            // Bundle state for the receive handler lambda (must fit ≤32 bytes).
            struct HandlerState
            {
                AsyncControlProxy& proxy;
                PendingCall& pending;
                std::size_t max_samples;
            };
            HandlerState handler_state{proxy, pending, kMaxSamples};

            auto set_handler_result = proxy.response.SetReceiveHandler([hs = &handler_state]() {
                auto get_result = hs->proxy.response.GetNewSamples(
                    [hs](SamplePtr<IpcBuffer> sample) noexcept {
                        if (!IsValid(*sample))
                        {
                            // Silent failure: zero-filled or oversized slot — pending.ready
                            // would never be set, causing a 30 s timeout with no prior log.
                            std::cerr << "[receive handler] discarding invalid (empty/oversized) sample"
                                         " — pending call will time out\n";
                            return;
                        }

                        const auto* resp = flatbuffers::GetSizePrefixedRoot<ControlResponse>(sample->payload.data());
                        if (resp == nullptr)
                        {
                            std::cerr << "[receive handler] GetSizePrefixedRoot returned nullptr"
                                         " — pending call will time out\n";
                            return;
                        }

                        const std::uint64_t ticket = resp->request_id();

                        // Extract the result BEFORE taking the lock so the critical
                        // section stays short.
                        std::string result_value;
                        bool ok = false;
                        if (resp->operation_batch() != nullptr && resp->operation_batch()->operations() != nullptr &&
                            resp->operation_batch()->operations()->size() > 0U)
                        {
                            const auto* op = resp->operation_batch()->operations()->Get(0U);
                            if (op != nullptr && op->parameter() != nullptr && op->parameter()->size() > 0U &&
                                op->parameter_type() != nullptr &&
                                static_cast<OperationParameter>(op->parameter_type()->Get(0U)) ==
                                    OperationParameter_String)
                            {
                                const auto* str = reinterpret_cast<const String*>(op->parameter()->Get(0U));
                                if (str != nullptr && str->val() != nullptr)
                                {
                                    result_value = str->val()->str();
                                    ok = true;
                                }
                            }
                        }

                        if (!ok)
                        {
                            std::cerr << "[receive handler] failed to parse String result from"
                                         " response ticket="
                                      << ticket << "\n";
                        }

                        // Single lock for both the stale-check and the ready-set to
                        // eliminate the race where pending.ticket could advance between
                        // two separate lock acquisitions.
                        PendingCall& pending = hs->pending;
                        std::uint64_t current_pending_ticket = 0U;
                        bool stale = false;
                        {
                            std::unique_lock<std::mutex> lk(pending.mutex);
                            if (ticket != pending.ticket)
                            {
                                current_pending_ticket = pending.ticket;
                                stale = true;
                            }
                            else
                            {
                                pending.result_value = std::move(result_value);
                                pending.ok = ok;
                                pending.ready = true;
                                pending.cv.notify_one();
                            }
                        }
                        if (stale)
                        {
                            // Log outside the lock to keep g_log_mutex and pending.mutex
                            // acquisition order consistent.
                            std::ostringstream oss;
                            oss << "[receive handler] stale event discarded:"
                                << " received ticket=" << ticket << " pending.ticket=" << current_pending_ticket;
                            Log(oss.str());
                        }
                    },
                    hs->max_samples);

                if (!get_result.has_value())
                {
                    std::cerr << "[receive handler] GetNewSamples failed\n";
                }
                else if (*get_result == hs->max_samples)
                {
                    // Buffer saturated: further samples may be queued and will trigger
                    // another receive-handler callback, but if the subscription slot
                    // count equals max_samples the oldest events could have been dropped.
                    std::ostringstream oss;
                    oss << "[receive handler] WARNING: GetNewSamples returned max (" << *get_result
                        << ") samples — subscription buffer may be saturated";
                    Log(oss.str());
                }
            });

            if (!set_handler_result.has_value())
            {
                Log("[client " + std::to_string(client_index) + "/thread " + std::to_string(t) +
                    "] SetReceiveHandler failed");
                proxy.response.Unsubscribe();
                total_failures.fetch_add(call_count, std::memory_order_relaxed);
                return;
            }

            int failures = 0;

            // Wait till setup is done on server side
            // std::this_thread::sleep_for(std::chrono::seconds(3));

            auto times = std::vector<std::chrono::nanoseconds>(call_count);

            for (int c = 0; c < call_count; ++c)
            {
                auto start = std::chrono::system_clock::now();

                const std::string str_param = "client" + std::to_string(client_index + 1);
                const std::uint64_t uint64_param = static_cast<std::uint64_t>(c + 1);
                // Unique ticket encodes client, thread and call indices.
                const std::uint64_t request_id = static_cast<std::uint64_t>(client_index + 1) * 100'000ULL +
                                                 static_cast<std::uint64_t>(t + 1) * 1'000ULL +
                                                 static_cast<std::uint64_t>(c + 1);

                const std::string expected = str_param + "_" + std::to_string(uint64_param);

                // Set up the pending state BEFORE sending so the receive handler
                // can never miss the response even on a very fast server.
                {
                    std::lock_guard<std::mutex> lk(pending.mutex);
                    pending.ticket = request_id;
                    pending.ready = false;
                    pending.ok = false;
                    pending.result_value.clear();
                }

                // --- Phase 1 (serialised across threads — see phase1_mutex comment above) ---
                bool phase1_failed = false;
                std::uint64_t ticket = 0U;
                {
                    std::lock_guard<std::mutex> phase1_lk(phase1_mutex);
                    do  // single-exit wrapper so 'break' acts like a labelled continue
                    {
                        auto alloc_result = proxy.request.Allocate();
                        if (!alloc_result.has_value())
                        {
                            Log("[client " + std::to_string(client_index) + "/thread " + std::to_string(t) +
                                "] request.Allocate() failed");
                            ++failures;
                            phase1_failed = true;
                            break;
                        }
                        auto& arg = std::get<0>(alloc_result.value());

                        // Build the FlatBuffer and write directly into the SHM-backed slot.
                        {
                            flatbuffers::FlatBufferBuilder fbb(512);

                            auto str_val = fbb.CreateString(str_param);
                            auto str_tbl = CreateString(fbb, str_val);
                            auto u64_tbl = CreateValueUint64(fbb, uint64_param);

                            std::vector<uint8_t> param_types{OperationParameter_String, OperationParameter_ValueUint64};
                            std::vector<flatbuffers::Offset<void>> param_values{str_tbl.Union(), u64_tbl.Union()};

                            auto op_id = CreateOperationIdentifier(fbb, /*actor=*/1U, /*action=*/1U);
                            auto single_op = CreateSingleOperationRequest(
                                fbb, op_id, fbb.CreateVector(param_types), fbb.CreateVector(param_values));
                            auto batch = CreateOperationRequestBatch(fbb, fbb.CreateVector({single_op}));
                            fbb.FinishSizePrefixed(CreateControlRequest(fbb,
                                                                        request_id,
                                                                        /*client_id=*/0U,
                                                                        /*data_node_id=*/0U,
                                                                        batch));

                            if (!PackFlatBufferInto(*arg, fbb.GetBufferPointer(), fbb.GetSize()))
                            {
                                Log("[client " + std::to_string(client_index) + "/thread " + std::to_string(t) +
                                    "] PackFlatBufferInto failed");
                                ++failures;
                                phase1_failed = true;
                                break;
                            }
                        }

                        {
                            std::stringstream ss;
                            ss << "[client " << client_index << "/thread " << t << "] -> request_id=" << request_id
                               << " str=\"" << str_param << "\" uint64=" << uint64_param
                               << " (Phase 1: short-lived call)";
                            Log(ss.str());
                        }

                        auto call_result = proxy.request(std::move(arg));
                        if (!call_result.has_value())
                        {
                            std::ostringstream oss;
                            oss << "[client " << client_index << "/thread " << t
                                << "] request() call failed for ticket=" << request_id;
                            Log(oss.str());
                            ++failures;
                            phase1_failed = true;
                            break;
                        }
                        ticket = *call_result.value();

                        if (ticket != request_id)
                        {
                            std::ostringstream oss;
                            oss << "[client " << client_index << "/thread " << t
                                << "] Phase 1 ticket mismatch: sent request_id=" << request_id
                                << " but server returned ticket=" << ticket;
                            Log(oss.str());
                            ++failures;
                            phase1_failed = true;
                            break;
                        }

                        {
                            std::stringstream ss;
                            ss << "[client " << client_index << "/thread " << t << "] <- ticket=" << ticket
                               << " (Phase 1 complete \u2014 now waiting for Phase 2 event)";
                            Log(ss.str());
                        }
                    } while (false);
                }  // phase1_mutex released — Phase 2 runs concurrently

                if (phase1_failed)
                {
                    continue;
                }

                // --- Phase 2: wait for the matching response event ---
                constexpr auto kTimeout = std::chrono::seconds(30);
                bool timed_out = false;
                {
                    std::unique_lock<std::mutex> lk(pending.mutex);
                    timed_out = !pending.cv.wait_for(lk, kTimeout, [&] {
                        return pending.ready;
                    });
                }

                if (timed_out)
                {
                    std::ostringstream oss;
                    oss << "[client " << client_index << "/thread " << t
                        << "] TIMEOUT waiting for event ticket=" << ticket << " (pending.ticket=" << pending.ticket
                        << " pending.ready=" << pending.ready << ")";
                    Log(oss.str());
                    ++failures;
                    continue;
                }

                if (!pending.ok || pending.result_value != expected)
                {
                    std::ostringstream oss;
                    oss << "[client " << client_index << "/thread " << t << "] MISMATCH ticket=" << ticket
                        << ": expected=\"" << expected << "\" got=\"" << pending.result_value << "\"";
                    Log(oss.str());
                    ++failures;
                    continue;
                }

                {
                    std::stringstream ss;
                    ss << "[client " << client_index << "/thread " << t << "] OK ticket=" << ticket << " result=\""
                       << pending.result_value << "\" (Phase 2 complete)";
                    Log(ss.str());
                }

                auto end = std::chrono::system_clock::now();
                auto elapsed = end - start;
                times[c] = elapsed;

                // std::this_thread::sleep_for(std::chrono::milliseconds(5000));
            }

            auto sum = std::accumulate(times.begin(), times.end(), std::chrono::duration<double>::zero());

            for (int c = 0; c < call_count; ++c)
            {
                std::ostringstream oss;
                oss << "[client " << client_index << "/thread " << t << "] call " << (c + 1) << "/" << call_count
                    << ": " << std::chrono::duration_cast<std::chrono::microseconds>(times[c]).count() << " us";
                Log(oss.str());
            }

            if (failures == 0)
            {
                std::ostringstream oss;
                oss << "- [client " + std::to_string(client_index) + "/thread " + std::to_string(t) + "] completed " +
                           std::to_string(call_count) + " calls with " +
                           std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(sum).count()) +
                           " us elapsed, average " +
                           std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(sum).count() /
                                          call_count) +
                           " us per call";
                Log(oss.str());
            }

            if (failures == 0)
            {
                auto c = call_count - 1;
                auto s = sum - times[0];

                std::ostringstream oss;
                oss << "SKIP FIRST [client " + std::to_string(client_index) + "/thread " + std::to_string(t) +
                           "] completed " + std::to_string(c) + " calls with " +
                           std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(s).count()) +
                           " us elapsed, average " +
                           std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(s).count() / c) +
                           " us per call";
                Log(oss.str());
            }

            proxy.response.UnsetReceiveHandler();
            proxy.response.Unsubscribe();

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
    std::stringstream ss_summary;
    ss_summary << "[client " << client_index << "] Results: " << success << "/" << total << " calls succeeded "
               << failures << "/" << total << " calls failed (" << thread_count << " thread(s) x " << call_count
               << " call(s))";
    Log(ss_summary.str());

    return failures == 0;
}

}  // namespace score::crypto::ipc::control

// ---------------------------------------------------------------------------
// main — fork before InitializeRuntime for a clean per-process runtime state
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // Parse optional flags.
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
            {
                g_client_count = std::stoi(arg.substr(kClientPrefix.size()));
            }
            else if (arg.rfind(kCallPrefix, 0) == 0)
            {
                g_call_count = std::stoi(arg.substr(kCallPrefix.size()));
            }
            else if (arg.rfind(kClientThreadsPrefix, 0) == 0)
            {
                g_client_threads = std::stoi(arg.substr(kClientThreadsPrefix.size()));
            }
            else if (arg.rfind(kServerThreadsPrefix, 0) == 0)
            {
                g_server_threads = std::stoi(arg.substr(kServerThreadsPrefix.size()));
            }
            else if (arg.rfind(kSleepPrefix, 0) == 0)
            {
                g_sleep_milliseconds = std::stoi(arg.substr(kSleepPrefix.size()));
            }
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

    std::printf("[main] client_count=%d  call_count=%d  client_threads=%d  server_threads=%d  sleep_milliseconds=%d\n",
                g_client_count,
                g_call_count,
                g_client_threads,
                g_server_threads,
                g_sleep_milliseconds);

    score::crypto::ipc::control::SetupConfigs(g_client_count);

    // Flush before forking so buffered output is not duplicated.
    std::fflush(nullptr);

    // ------------------------------------------------------------------
    // Fork all client processes BEFORE InitializeRuntime so each child
    // gets a completely clean mw::com state.
    // ------------------------------------------------------------------
    std::vector<pid_t> child_pids;
    int my_client_index = -1;  // -1 means "I am the server"

    for (int i = 0; i < g_client_count; ++i)
    {
        pid_t pid = ::fork();
        if (pid < 0)
        {
            std::perror("[main] fork");
            // Kill already-spawned children before exiting.
            for (pid_t cpid : child_pids)
            {
                ::kill(cpid, SIGTERM);
            }
            return 1;
        }
        if (pid == 0)
        {
#if false
            // With configured uniuqe applicationIds
            // we do not necessarily need unique UIDS
            // If applicationId is not set in config, it falls back to UID

            // Child: drop to a per-client UID before touching anything else.
            // Client 0 → UID 1000, client 1 → UID 1001, etc.
            const auto target_uid = static_cast<uid_t>(1000 + i);
            if (::setresuid(target_uid, target_uid, target_uid) != 0)
            {
                std::perror("[child] setresuid");
                return 1;
            }
#endif

            my_client_index = i;
            break;
        }
        // Parent: record the child PID and continue forking.
        child_pids.push_back(pid);
    }

    if (my_client_index == -1)
    {
        // ---- PARENT = SERVER ----
        return score::crypto::ipc::control::RunServer(child_pids);
    }
    else
    {
        // ---- CHILD = CLIENT ----
        const bool ok = score::crypto::ipc::control::RunClient(my_client_index, g_call_count, g_client_threads);
        return ok ? 0 : 1;
    }
}

// clang-format off

// TODO: Issues
// 1. There is some UID / Application ID issue
//    If both clients run unter the same UID, (any no Application ID is set) they seem to conflict with each other
//    We get flatbuffer validation errors, indicating that both may write to the same SHM locations
//    -> Not tested yet.
//    -> But we could assign ApplicationIds in the json. We would however need multiple json files with different
//    ApplicationIds
//    -> See
//    https://github.com/eclipse-score/communication/blob/main/score/mw/com/example/com-api-example/etc/mw_com_config.json#L28
//    -> With dedicated configs and applicationIds, it seems to also work without unique UIDs
//    -> In reality however, we would very likely want unique UIDs
//    -> It is however not very nice, that we just get a very obscure error in this case
//    -> It really seems that the second client does overwrite the request of the first one (ticker 1001 is overwriten to 2001)
// 2. When running without --sleep_milliseconds > 0
//    We get issues while waiting for the response event, leading to timeouts and such
//    -> This actually seems to be caused by a maxSample count of 1 in the Subscribe
//    -> With higher counts we seems to not run into this issue
// 3. With the current config, we publish to each subscriber, I guess that means each Subscriber
//    could read the event and therefore also the operation response of others
//    How to do this, espacailly also the routing to an event from a method call?
//    We could potentially use more service instances, then it would be clear, not sure however how this would look in code and how it would scale
// 4. Occasionally i see the following
// 2026/05/13 13:59:01.741300 258889237 000 ECU1 NONE shm log error verbose 4 LockFile::Create failed to open file:  /tmp/lola-ctl-0000000000000101-00003_lock  | Error:  An OS error has occurred with error code: File exists
//    This however does not seem to cause any issue
// 5. Occasionally, i see the following:
// 2026/05/13 14:19:46.1986422 271340454 000 ECU1 NONE lola log warn verbose 5 MessagePassingService: Received NotifyEventUpdateMessage for event:  ElementFqId{S:101, E:2, I:3, T:1}  from node 187843  although we don't have currently any registered handlers. Might be an acceptable race, if it happens seldom!
//    This however also does not seem to cause any issue
// 6. Multiple threads within one client issuing calls in parallel
//    Some issue with the Allocation, looks like on client side, the queueSize is not used, but hardcoded to 1:
//    See: https://github.com/eclipse-score/communication/blob/7e8cb889e17ba79b1004d6015c6216ceebd38056/score/mw/com/impl/methods/proxy_method_base.h#L71-L73
//    We may be able to get around this by having separate proxy instances
// 7. Also need to test with multiple worker threads on the server
//    Server Worker Thread pool is in use
//
// 8. [LoLa limitation — WORKED AROUND] Proxy creation races with method calls on shared ClientConnection
//    AsyncControlProxy::Create() calls SetupMethods() → SubscribeServiceMethod() →
//    ClientConnection::SendWaitReply().  This subscribe message (12 bytes, SubscribeServiceMethodUnserializedPayload)
//    uses the same POSIX message-passing socket as method calls (24 bytes, MethodCallUnserializedPayload).
//    If a concurrent thread has a method call in-flight, the two messages are serialised by the
//    ClientConnection queue; the server receives the 12-byte payload when it expects 24 bytes,
//    logs "Wrong payload size" and disconnects the client.
//    Workaround: pre-create all proxies sequentially in the main thread before spawning worker threads.
//    See: ClientConnection::TryQueueMessage / ProcessSendQueueUnderLock in score_communication.
//
// 9. [LoLa limitation — WORKED AROUND] Concurrent DoCall from distinct proxy instances to the same skeleton
//    All proxy instances in a process share a single ClientConnection to the skeleton.
//    ClientConnection::ProcessInputEvent fires the queued next message BEFORE returning the current
//    reply to its caller (see the REPLY case in ProcessInputEvent).  This means the server can start
//    processing call N+1 and write to its SHM return buffer before the caller of call N has read its
//    own return value, leaving a zero-initialised slot and yielding ticket=0.
//    Workaround: serialise Phase 1 (the DoCall / SendWaitReply) across all threads with phase1_mutex.
//    See: ClientConnection::ProcessInputEvent → ProcessSendQueueUnderLock in score_communication.
//
// 10. Looks like the current Method call in Lola may not have a timeout, or it is not set.
//     Isn't that a problem considering our use-case for FFI Apps communicating with a QM daemon
//     In case the QM callback "gets stuck", we are also stuck on the client side
// 11. Mit event subsribers > 5 (?), we get
//     2026/06/03 06:42:40.8960242 5665993 000 ECU1 NONE lola log error verbose 4 MessagePassingServiceInstance: NotifyEventLocally failed to call ALL registered event receive handlers for event_id ElementFqId{S:0, E:2, I:1, T:1} , because number is exceeding  5
//     Not sure if this is relevant, both the remote and local notification paths seems to be called
//     (I guess both are needed, since we have 1->n pattern and some receivers could be remote and some local)
//     However, I could not yet increase the number of receptients
//     I gues I need to redesign the client side to have a "engine thread", which solely pull out the events


// Current Problems:
// - Config needed. (We can request some programmatic API for this)
//   Ideally, we should be config-less.
// - Keeping config in sync between Server and Clients. Even if we can inject it programmatically,
//   currently both sides need both ISpec as well as the underlying Ids in their config. This
//   must then also be kept in sync.
//   What's the scope of this?
//   ServiceIds are system-wide? Do we compete with all Services on the system for these?
// - How will this be done if a Client wants to make use of Crypto and "a regular mw com service"?
//   Do we need to sync, merge, resolve conflicts in configs? Do we need to enhance configs, and e.g.
//   delay com runtime init?
// - Even if we could inject the config programmatically, we still need to scale it to the number
//   of users, since we need to separate ServiceInstances to separate return data via events
//   (This we may change with async methods)
// * UID retrieval currently not there (I would assume this can also change in future)
// * Methods do not have a timeout, we can implement a timeout on top, but I do not see that
//   being sufficient for the mixed QM / ASIL / FFI use-case, if our "short lived" enqueue call
//   could already block the FFI Apps (Again, this may change with update of methods)
// - Workarounds needed for desired threading model for method calls (we can work around this)
// - Interference if multiple clients run under the same UID and no ApplicationId
//   (May be changed, to base ApplicationId on PID instead of UID, but interference is surprising)
// - Naming conventions for ISpecs to detect CryptoISpecs
// - Global elements in config but Application specific parts

// Hint //

// Method queue_size does seem to block when full.
// E.g. with queue_size=1, we get the second request only after the send back the ticket of the first one
// The second request is blocked, till the first one is dequeued (and handled ? (just ticketing))
// With queue_size>2, we see both clients sending their request, then first one get its ticket, then the second one.

// OLD //

// TODO: When running this multiple times in parallels, we get broken messages
// Quick look with strace also seems to suggests, that both open the same (two) SHM files
// Two threads in one process seems to be fine (seem's there is some serialization),
// but currently we only have one server thread (???) so it is run in series

// Queue size, on a first glance dos not seem to make a difference

// Multiple instances within one serviceInstance (same ISpec) does not seem to be working
// Got an error "Multi-Binding support right now not supported";
// https://github.com/eclipse-score/communication/blob/main/score/mw/com/impl/configuration/config_parser.cpp#L774
// Even tough, the same binding was used for both

// With multiple ServiceInstances, we should have multiple ISpecs
// Looks like we actually need create another Skeleton Instance for the second instance
// ISpec is passed at Skeleton creation

// Looks like we get into trouble when I register multiple handlers on the same thread
// When using serviceInstanceA and the serviceInstanceB (or vice versa)

// Seems rather related to the UID
// (or the ApplicationId according to Copilot, seems UID is the fallback for ApplicationId)
// https://github.com/eclipse-score/communication/blob/fc50b6ae9801b118810484d0688abf5084096eb5/score/mw/com/impl/bindings/lola/runtime.cpp#L39

// Same as above, but run both client with different UIDs, then both work
// All is done serially, because we only have one server thread tough
// This also does work, if both clients use the same serviceInstance

// clang-format on
