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

/// POC: SendWithCallback-ack + Notify async model — one shared connection per client process
///
/// This replicates the functionality of poc_async.cpp using only the low-level
/// score::message_passing API, without any score::mw elements.
///
/// Communication model (two phases, mirroring poc_async's method+event approach):
///
///   Phase 1 — SendWithCallback for non-blocking acknowledgment:
///     The client thread calls SendWithCallback() with a ControlRequest and a
///     ReplyCallback.  The call enqueues the message and returns immediately
///     (non-blocking, ASIL-B safe).  The server's sent_with_reply_callback
///     enqueues the work, calls Reply() with the client-assigned request_id as an ack,
///     and then returns.  The engine thread fires ReplyCallback
///     on the client side when the ack arrives.  The calling thread waits on an
///     application-level CV with a timeout — if the server stalls, the thread is
///     unblocked by the timeout rather than hanging forever inside the library.
///
///   Phase 2 — Server Notify (analogous to the Response event):
///     A server pool worker dequeues the request, does the work, and calls
///     Notify() on the IServerConnection.  The ControlResponse payload carries
///     the original request_id.  The client's NotifyCallback routes by
///     request_id and wakes the waiting thread.
///
/// Why the two-phase approach is needed:
///   The REQUEST/REPLY protocol serializes per connection: the server does not
///   process the next REQUEST until Reply() has been called on the current one.
///   With multiple threads sharing one connection, their SendWithCallback() calls
///   are serialized at the protocol level.  By calling Reply() immediately in
///   the callback (before the actual work), the serialization window is minimal,
///   By enqueueing the work and then calling Reply() immediately in the callback
///   (before the actual work), the serialization window is minimal,
///   so request throughput is still high while the pool workers run concurrently.
///   NOTIFY messages go from server to client independently, so they do not
///   block incoming requests.
///
/// Why SendWithCallback instead of SendWaitReply:
///   SendWaitReply() blocks the calling thread inside the library with no timeout.
///   A misbehaving QM server (slow callback, scheduling starvation without crash)
///   would hold an ASIL-B thread blocked indefinitely.  SendWithCallback() is
///   non-blocking; the library guarantees the calling thread is never held inside
///   the IPC layer.  The application-level wait_for() provides the safety timeout.
///
/// Connection model:
///   One IClientConnection per client process (shared by all threads).
///   The request_id in the FlatBuffer payload is used to route each Notify
///   back to the thread that issued the corresponding SendWithCallback.
///   Because Notify() is point-to-point (reaches only this connection's client),
///   no cross-client leakage occurs — unlike poc_async's broadcast events which
///   required one skeleton instance per client.
///
/// Process model: same as poc_async — fork before any IPC setup, parent=server,
/// children=clients.
///
/// Usage:
///   bazel run //tests/score_com_poc:poc_low_level
///   bazel run //tests/score_com_poc:poc_low_level -- --client_count=3 --call_count=5
///   bazel run //tests/score_com_poc:poc_low_level -- --client_count=3 --call_count=5 --client_threads=4
///   bazel run //tests/score_com_poc:poc_low_level -- --client_count=3 --call_count=5 --server_threads=2

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <future>
#include <iostream>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "flatbuffers/flatbuffers.h"
#include "score/message_passing/client_factory.h"
#include "score/message_passing/i_client_connection.h"
#include "score/message_passing/i_server_connection.h"
#include "score/message_passing/i_server_factory.h"
#include "score/message_passing/server_factory.h"
#include "score/message_passing/service_protocol_config.h"
#include "score/tests/ipc_poc/ipc_buffer.h"
#include "score/tests/ipc_poc/poc_control_generated.h"

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

static void LogErr(const std::string& line)
{
    std::stringstream ss;
    ss << "[ERROR] " << line << "\n";
    std::lock_guard<std::mutex> lk(g_log_mutex);
    std::cerr << ss.str();
}

// ---------------------------------------------------------------------------
// Protocol config — identifier resolves to an abstract Unix domain socket
// ---------------------------------------------------------------------------

namespace score::crypto::ipc::control
{

static constexpr std::string_view kServiceIdentifier{"score_crypto_poc_ll"};

// ---------------------------------------------------------------------------
// Configuration
//
// All queue sizes derive from two logical inputs:
//
//   N  — number of distinct client processes (== distinct UIDs the server
//         accepts).  Controls how many connections the server manages and
//         sets the capacity of the global server-side receive queue.
//
//   T  — maximum number of threads per client process that may have
//         concurrent in-flight requests at any one time.  Controls the
//         per-connection queue depths.
//
// Payload size M is fixed by the IPC protocol (sizeof(IpcBuffer)).
// ---------------------------------------------------------------------------

/// Parameters shared by both server and client sides.
/// Both sides must be constructed from the same ServiceParams values;
/// a mismatch in any size field causes EMSGSIZE on send or silent
/// truncation on receive.
struct ServiceParams
{
    /// Logical identifier of the service.  Maps to an abstract Unix domain
    /// socket name on Linux and to a QNX resource-manager path on QNX.
    std::string_view identifier;

    /// Maximum byte size of a client→server message (ControlRequest).
    /// Must be >= sizeof(the largest FlatBuffer payload sent by any client).
    std::uint32_t max_payload_bytes;
};

/// Parameters that only the server side needs.
struct ServerParams
{
    /// Number of distinct client processes expected to connect.
    /// Used to:
    ///   - size the global server-side receive queue (N * T slots total)
    ///   - limit accepted connections to at most N (one per UID)
    std::uint32_t max_client_processes;  // N

    /// Maximum number of threads per client process that may have concurrent
    /// in-flight requests.  Used to size per-connection notify queues.
    /// Under-sizing this causes Notify() to return ENOBUFS on QNX (response
    /// lost, client times out) or blocks the engine thread on Linux.
    std::uint32_t max_threads_per_client;  // T

    /// Number of server-side pool threads processing requests.
    std::uint32_t worker_threads;
};

/// Parameters that only the client side needs.
struct ClientParams
{
    /// Maximum number of threads in this process that may have concurrent
    /// in-flight requests.  Sizes both max_async_replies and max_queued_sends
    /// in the client config so that T concurrent SendWithCallback() calls can
    /// be in-flight simultaneously without getting ENOBUFS.
    std::uint32_t max_concurrent_threads;  // T
};

// ---------------------------------------------------------------------------
// Config factory functions
// ---------------------------------------------------------------------------

static score::message_passing::ServiceProtocolConfig MakeProtocolConfig(const ServiceParams& p)
{
    return score::message_passing::ServiceProtocolConfig{
        p.identifier,
        // max_send_size: upper bound for a client→server ControlRequest FlatBuffer.
        /*max_send_size=*/p.max_payload_bytes,
        // max_reply_size: upper bound for the ack ControlResponse sent by Reply().
        // The ack only carries request_id and an empty operation batch, so it is much
        // smaller than max_payload_bytes in practice.  Using the same value keeps both
        // sides in sync without a second size constant; the slight over-allocation in the
        // client receive buffer is acceptable.
        /*max_reply_size=*/p.max_payload_bytes,
        // max_notify_size: upper bound for the full ControlResponse sent by Notify().
        // Must be at least as large as the largest response payload the server produces.
        /*max_notify_size=*/p.max_payload_bytes,
    };
}

static score::message_passing::IServerFactory::ServerConfig MakeServerConfig(const ServerParams& p)
{
    const std::uint32_t n = p.max_client_processes;
    const std::uint32_t t = p.max_threads_per_client;

    // NOTE: ServerConfig is read only by the QNX implementation; the Linux/Unix-domain
    // implementation ignores all three fields and relies on kernel socket buffers instead.
    // The values are set correctly here so that the same code works on QNX without changes.
    return score::message_passing::IServerFactory::ServerConfig{
        // Server-side ring buffer for incoming SEND and REQUEST messages (QNX).
        // The REQUEST/REPLY protocol serializes one REQUEST per connection: the server
        // does not accept the next REQUEST on a connection until Reply() has been called.
        // With one connection per client process we therefore have at most N simultaneous
        // in-flight REQUESTs — one per client — regardless of how many threads each client
        // has.  N slots are sufficient; N*T would be an over-allocation.
        /*max_queued_sends=*/n,

        // Number of ServerConnection objects pre-allocated at startup (QNX).
        // Avoids runtime heap allocation when clients connect, which is required for
        // monotonic/bounded memory in safety contexts.  Set to N (one per expected client).
        /*pre_alloc_connections=*/n,

        // Per-connection NOTIFY queue depth on the server side (QNX).
        // Each in-flight SendWithCallback() on the client side will eventually receive one
        // Notify() from the server.  With T threads sharing one connection, up to T
        // Notify() calls may be queued before the client drains them.
        // If this queue overflows, Notify() returns ENOBUFS on QNX — the response is
        // silently dropped and the client hangs until the 30-second timeout.
        // This is the most critical parameter to size correctly: must be >= T.
        /*max_queued_notifies=*/t,
    };
}

static score::message_passing::IClientFactory::ClientConfig MakeClientConfig(const ClientParams& p)
{
    const std::uint32_t t = p.max_concurrent_threads;

    return score::message_passing::IClientFactory::ClientConfig{
        // One async-reply slot per concurrent thread: each in-flight SendWithCallback()
        // holds one slot until its ReplyCallback fires.  Must be >= T.
        /*max_async_replies=*/t,

        // SendWithCallback() with truly_async=true always queues into the send queue
        // before the engine thread picks it up.  One slot per concurrent thread.
        // Must be >= T; shared pool with max_async_replies.
        /*max_queued_sends=*/t,

        // Serialize SEND (fire-and-forget) delivery relative to REQUEST/REPLY messages.
        // This POC never calls Send(), so ordering across message types is irrelevant.
        /*fully_ordered=*/false,

        // Route SendWithCallback() through the engine's background thread so the
        // calling thread is never held inside the IPC layer (non-blocking guarantee).
        // Required when max_queued_sends > 0.  Mandatory for safety clients sending
        // to QM servers where the server callback duration is not bounded.
        /*truly_async=*/true,

        // Do not block the calling thread on the first connection attempt.
        // Start() is called before the server socket exists (child processes start
        // 300 ms after the fork); the background engine thread retries until the
        // server is ready and fires the kReady state callback.
        /*sync_first_connect=*/false,
    };
}

// ---------------------------------------------------------------------------
// FlatBuffer helpers
// ---------------------------------------------------------------------------

/// Builds a minimal ControlResponse carrying only request_id and no operation
/// payload.  Used as the immediate ack sent by Reply() in the
/// sent_with_reply_callback so the client's ReplyCallback fires quickly.
static std::vector<std::uint8_t> BuildAcknowledgeReply(const std::uint64_t request_id)
{
    flatbuffers::FlatBufferBuilder fbb(128);
    auto empty_batch = CreateOperationResponseBatch(
        fbb, fbb.CreateVector(std::vector<flatbuffers::Offset<SingleOperationResponse>>{}));
    fbb.FinishSizePrefixed(CreateControlResponse(fbb, request_id, empty_batch));
    return std::vector<std::uint8_t>(fbb.GetBufferPointer(), fbb.GetBufferPointer() + fbb.GetSize());
}

static std::vector<std::uint8_t> BuildResponseBytes(const std::uint64_t request_id, const std::string& combined)
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
    return std::vector<std::uint8_t>(fbb.GetBufferPointer(), fbb.GetBufferPointer() + fbb.GetSize());
}

static std::vector<std::uint8_t> ProcessRequestBytes(const std::uint64_t request_id,
                                                     score::cpp::span<const std::uint8_t> message)
{
    flatbuffers::Verifier verifier{message.data(), static_cast<std::size_t>(message.size())};
    if (!VerifySizePrefixedControlRequestBuffer(verifier))
    {
        LogErr("[server/worker] FlatBuffer verification failed");
        return {};
    }

    const auto* req = flatbuffers::GetSizePrefixedRoot<ControlRequest>(message.data());
    if (req == nullptr || req->operation_batch() == nullptr || req->operation_batch()->operations() == nullptr ||
        req->operation_batch()->operations()->size() == 0U)
    {
        return {};
    }

    const auto* op = req->operation_batch()->operations()->Get(0U);
    if (op == nullptr || op->parameter() == nullptr)
    {
        return {};
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
        std::ostringstream ss;
        ss << "[server/worker] request_id=" << request_id << " -> combined=\"" << combined << "\"";
        Log(ss.str());
    }

    return BuildResponseBytes(request_id, combined);
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

struct WorkItem
{
    score::message_passing::IServerConnection* conn;
    std::shared_ptr<bool> alive;  // per-connection lifetime token; set to false by disconnect_cb
    std::uint64_t request_id;
    std::vector<std::uint8_t> request_bytes;
};

static int RunServer(const std::vector<pid_t>& child_pids)
{
    const ServiceParams service_params{
        kServiceIdentifier,
        /*max_payload_bytes=*/static_cast<std::uint32_t>(sizeof(IpcBuffer)),
    };
    const ServerParams server_params{
        /*max_client_processes=*/static_cast<std::uint32_t>(g_client_count),
        /*max_threads_per_client=*/static_cast<std::uint32_t>(g_client_threads),
        /*worker_threads=*/static_cast<std::uint32_t>(g_server_threads),
    };

    score::message_passing::ServerFactory server_factory;
    const auto protocol_config = MakeProtocolConfig(service_params);
    const auto server_config = MakeServerConfig(server_params);

    auto server = server_factory.Create(protocol_config, server_config);
    if (!server)
    {
        LogErr("[server] failed to create server");
        return 1;
    }

    // ------------------------------------------------------------------
    // Live-connection guard via per-connection lifetime token.
    //
    // Worker threads hold a shared_ptr<bool> (alive token) inside WorkItem,
    // captured at enqueue time.  The library destroys a ServerConnection as
    // soon as the client disconnects.  Without coordination, a worker that
    // dequeued a WorkItem before the disconnect fires could call Notify() on
    // a destroyed object — or on a new connection that reused the same address.
    //
    // Fix: each connection gets a shared_ptr<bool> initialised to true.
    // disconnect_cb sets it to false under live_conn->mutex before the library
    // destroys the object.  The worker checks the flag under the same mutex
    // before calling Notify(), so a false flag always wins the race.
    //
    // Aliasing is impossible: the WorkItem holds its own shared_ptr copy whose
    // control block is unique to that connection's lifetime; a new connection
    // that reuses the same address gets a brand-new shared_ptr<bool>(true).
    //
    // Notify() is called while holding live_conn->mutex because the transport
    // does not expose a connection lifetime lease.  This ordering is required:
    // disconnect_cb cannot destroy the connection until a worker has finished
    // using its raw pointer.  It does not make Notify() bounded.  The Unix
    // backend uses a blocking sendmsg(), while the QNX backend takes its own
    // send mutex and can return ENOBUFS when its notify pool is exhausted.
    // Consequently, a blocked Notify() can delay disconnect_cb and therefore
    // client admission.  Production code must provide a bounded/non-blocking
    // Notify() operation or a library-owned connection lease before removing
    // this lock or claiming a bounded disconnect path.
    //
    // Lock order: live_conn->mutex must NOT be taken while holding any
    // score::message_passing internal lock.  Workers take it only around
    // the alive check + Notify(); they release it before touching the work
    // queue again.
    //
    // connect_cb and disconnect_cb use [&] capture and access live_conn directly
    // by reference — no heap allocation needed.  sent_with_reply_cb accesses it
    // via SentWithReplyCtx (a shared_ptr-boxed struct required for the 32-byte
    // callback limit), which holds a LiveConnections& into the same frame.
    // ------------------------------------------------------------------
    struct LiveConnections
    {
        std::mutex mutex;
        // Was facing pointer-reuse issues, when just using the Connection address for alive checks
        // Thus the additional shared_ptr<bool> per connection, used in work_items
        std::unordered_map<score::message_passing::IServerConnection*, std::shared_ptr<bool>> alive_map;
    };
    LiveConnections live_conn;

    // ------------------------------------------------------------------
    // Thread pool: workers dequeue requests, do the work, and call
    // Notify() on the stored IServerConnection*.
    // Notify() is thread-safe and safe to call from a pool thread.
    // Multiple concurrent Notify() calls on the same connection are
    // serialized by the library; the NotifyCallback on the client side
    // routes by request_id so ordering does not matter.
    // ------------------------------------------------------------------
    std::mutex queue_mutex;
    std::condition_variable queue_cv;
    std::queue<WorkItem> work_queue;
    std::atomic<bool> stop_workers{false};

    std::vector<std::thread> workers;
    workers.reserve(server_params.worker_threads);
    for (std::uint32_t w = 0U; w < server_params.worker_threads; ++w)
    {
        workers.emplace_back([&, w]() {
            while (true)
            {
                std::unique_lock<std::mutex> lk(queue_mutex);

                auto start_time = std::chrono::system_clock::now();

                queue_cv.wait(lk, [&] {
                    return !work_queue.empty() || stop_workers.load();
                });

                auto end_time = std::chrono::system_clock::now();
                auto diff = end_time - start_time;
                Log("[server/worker " + std::to_string(w) + "] Took: " +
                    std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(diff).count()) + " us\n");

                if (stop_workers.load() && work_queue.empty())
                {
                    break;
                }

                WorkItem item = std::move(work_queue.front());
                work_queue.pop();
                lk.unlock();

                if (g_sleep_milliseconds > 0)
                {
                    Log("[server/worker " + std::to_string(w) + "] simulating work, sleeping " +
                        std::to_string(g_sleep_milliseconds) + " ms");
                    std::this_thread::sleep_for(std::chrono::milliseconds(g_sleep_milliseconds));
                }

                auto response_bytes = ProcessRequestBytes(
                    item.request_id,
                    score::cpp::span<const std::uint8_t>{item.request_bytes.data(), item.request_bytes.size()});

                // Guard against use-after-free: check the alive token under live_conn->mutex,
                // which disconnect_cb also holds when it flips the flag to false.
                // Notify() is called under the same lock so no window exists between the check
                // and the call.  This protects the raw connection pointer, but the transport
                // call itself is not guaranteed to return within a bounded time; see the
                // LiveConnections note above.
                std::lock_guard<std::mutex> live_lk(live_conn.mutex);
                if (!*item.alive)
                {
                    LogErr("[server/worker " + std::to_string(w) +
                           "] Notify() skipped — connection already disconnected "
                           "(request_id=" +
                           std::to_string(item.request_id) + ")");
                    continue;
                }

                std::ostringstream notify_log;
                notify_log << "[server/worker " << w << "] Calling Notify() for request_id=" << item.request_id
                           << " with " << response_bytes.size() << " bytes";
                Log(notify_log.str());

                auto notify_result = item.conn->Notify(
                    score::cpp::span<const std::uint8_t>{response_bytes.data(), response_bytes.size()});

                if (!notify_result.has_value())
                {
                    // ENOBUFS: max_queued_notifies was too small — response dropped,
                    // client will hang until its timeout expires.
                    LogErr("[server/worker " + std::to_string(w) + "] Notify() failed for request_id=" +
                           std::to_string(item.request_id) + " — check max_queued_notifies >= max_threads_per_client");
                }
                else
                {
                    Log("[server/worker " + std::to_string(w) +
                        "] Notify() succeeded for request_id=" + std::to_string(item.request_id));
                }
            }
        });
    }
    Log("[server] started " + std::to_string(server_params.worker_threads) + " worker thread(s)");

    // ------------------------------------------------------------------
    // UID admission control.
    //
    // The server enforces at most one active connection per UID.  This:
    //   - prevents a single client from starving others by opening N*T
    //     connections and consuming the entire server receive queue;
    //   - binds resource consumption (queue slots, connection objects) to
    //     the number of authenticated client processes, not to thread count.
    //
    // All server callbacks for the same IServer instance are called
    // sequentially on the library's internal thread (doc §Server callbacks),
    // so connected_uids needs no external mutex.
    //
    // Rejection policy:
    //   EAGAIN — the UID is already connected; the library will tell the
    //            client to retry.  Used instead of EACCES so that a client
    //            which reconnects after a crash is not permanently locked out
    //            while the previous disconnect callback has not yet fired.
    //
    // Hint: The idea here is not access control as we did it earlier
    // but to prevent resource starvation, since we pre-allocate x buffer
    // we have a limit on how many simultaneous connections we can handle
    // enforcing one connection per UID is a simple way to prevent a
    // single client from consuming all resources and starving others.
    // ------------------------------------------------------------------
    std::unordered_set<uid_t> connected_uids;

    auto connect_cb = [&](score::message_passing::IServerConnection& conn)
        -> score::cpp::expected<score::message_passing::UserData, score::os::Error> {
        const uid_t uid = conn.GetClientIdentity().uid;
#if ENFORCE_SINGLE_CONNECTION_PER_UID
        if (connected_uids.count(uid) != 0U)
        {
            std::ostringstream ss;
            ss << "[server] rejected connection from uid=" << uid << " (already connected) — client will retry";
            Log(ss.str());
            // EAGAIN: instructs the client library to retry the connection
            // rather than transitioning to kStopped with kPermission reason.
            return score::cpp::make_unexpected(score::os::Error::createFromErrno(EAGAIN));
        }
#endif
        connected_uids.insert(uid);
        {
            std::lock_guard<std::mutex> live_lk(live_conn.mutex);
            live_conn.alive_map[&conn] = std::make_shared<bool>(true);
        }
        std::ostringstream ss;
        ss << "[server] accepted connection from uid=" << uid << " (" << connected_uids.size() << "/"
           << server_params.max_client_processes << " slots used)";
        Log(ss.str());
        return score::message_passing::UserData{static_cast<void*>(nullptr)};
    };

    auto disconnect_cb = [&](score::message_passing::IServerConnection& conn) {
        const uid_t uid = conn.GetClientIdentity().uid;
        connected_uids.erase(uid);
        {
            // Flip the alive token to false before the library destroys the
            // ServerConnection object.  Workers hold a shared_ptr copy of the
            // same token and check it under live_conn->mutex before Notify(),
            // so a false flag always wins the race against pointer reuse.
            std::lock_guard<std::mutex> live_lk(live_conn.mutex);
            auto it = live_conn.alive_map.find(&conn);
            if (it != live_conn.alive_map.end())
            {
                *it->second = false;
                live_conn.alive_map.erase(it);
            }
        }
        std::ostringstream ss;
        ss << "[server] client disconnected uid=" << uid << " (" << connected_uids.size() << "/"
           << server_params.max_client_processes << " slots used)";
        Log(ss.str());
    };

    // Box the captured references into a heap struct so the lambda fits
    // in the 32-byte inline capacity of score::cpp::callback<>.
    struct SentWithReplyCtx
    {
        std::mutex& queue_mutex;
        std::condition_variable& queue_cv;
        std::queue<WorkItem>& work_queue;
        LiveConnections& live_conn;
    };
    auto swr_ctx = std::make_shared<SentWithReplyCtx>(SentWithReplyCtx{queue_mutex, queue_cv, work_queue, live_conn});

    auto sent_with_reply_cb =
        [swr_ctx](score::message_passing::IServerConnection& conn,
                  score::cpp::span<const std::uint8_t> message) -> score::cpp::expected_blank<score::os::Error> {
        // Read the client-assigned request_id from the FlatBuffer.
        // The client guarantees it is non-zero and unique within its process.
        flatbuffers::Verifier verifier{message.data(), static_cast<std::size_t>(message.size())};
        if (!VerifySizePrefixedControlRequestBuffer(verifier))
        {
            LogErr("[server/handler] FlatBuffer verification failed — dropping request");
            return score::cpp::make_unexpected(score::os::Error::createFromErrno(EINVAL));
        }
        const auto* req = flatbuffers::GetSizePrefixedRoot<ControlRequest>(message.data());
        const std::uint64_t request_id = (req != nullptr) ? req->request_id() : 0U;
        if (request_id == 0U)
        {
            LogErr("[server/handler] received request with zero request_id — dropping");
            return score::cpp::make_unexpected(score::os::Error::createFromErrno(EINVAL));
        }

        // Fetch the alive token for this connection.  The connection is guaranteed
        // live at this point (connect_cb has fired, disconnect_cb has not), so the
        // entry must exist in alive_map.
        std::shared_ptr<bool> alive;
        {
            std::lock_guard<std::mutex> live_lk(swr_ctx->live_conn.mutex);
            auto it = swr_ctx->live_conn.alive_map.find(&conn);
            if (it != swr_ctx->live_conn.alive_map.end())
            {
                alive = it->second;
            }
        }
        if (!alive)
        {
            LogErr("[server/handler] alive token missing for request_id=" + std::to_string(request_id) +
                   " — connection not found in alive_map (unexpected)");
            return score::cpp::make_unexpected(score::os::Error::createFromErrno(ENOENT));
        }

        // Enqueue the full work for the pool worker before acknowledging the
        // request.  A successful acknowledgement therefore means the work is
        // admitted to the application queue.
        std::vector<std::uint8_t> bytes(message.begin(), message.end());
        {
            std::lock_guard<std::mutex> lk(swr_ctx->queue_mutex);
            swr_ctx->work_queue.push({&conn, alive, request_id, std::move(bytes)});
        }

        // Reply immediately as ack to end the REQUEST/REPLY window.  The worker
        // is woken only after this call so completion cannot normally race ahead
        // of a successful acknowledgement.
        // This allows the next REQUEST from any thread sharing this connection
        // to be processed without waiting for the actual work to complete.
        // The ack payload is minimal — the client already knows its request_id.
        auto ack_bytes = BuildAcknowledgeReply(request_id);
        auto reply_result = conn.Reply(score::cpp::span<const std::uint8_t>{ack_bytes.data(), ack_bytes.size()});
        if (!reply_result.has_value())
        {
            // We should still wake up the worker
            // TODO: But maybe we need to invalidate the added workqueue element,
            // such that is shall not be processed
            swr_ctx->queue_cv.notify_one();

            LogErr("[server/handler] Reply() (ack) failed for request_id=" + std::to_string(request_id));
            return score::cpp::make_unexpected(reply_result.error());
        }

        swr_ctx->queue_cv.notify_one();

        Log("[server/handler] REQUEST received, ack request_id=" + std::to_string(request_id) +
            " sent, request queued");
        return {};
    };

    // Pass sent_with_reply_cb as the REQUEST/REPLY callback (4th arg).
    // The 3rd (fire-and-forget) arg is left empty — we no longer use Send().
    auto start_result = server->StartListening(connect_cb, disconnect_cb, /*sent_cb=*/{}, sent_with_reply_cb);
    if (!start_result.has_value())
    {
        LogErr("[server] StartListening failed");
        stop_workers.store(true);
        queue_cv.notify_all();
        for (auto& t : workers)
        {
            t.join();
        }
        return 1;
    }

    Log("[server] listening — waiting for all clients to finish...");

    int overall_status = 0;
    for (std::size_t i = 0U; i < child_pids.size(); ++i)
    {
        int wstatus = 0;
        pid_t pid = waitpid(-1, &wstatus, 0);
        if (pid > 0)
        {
            const bool ok = WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0;
            std::ostringstream ss;
            ss << "[server] child pid=" << pid << (ok ? " exited OK" : " FAILED");
            (ok ? Log : LogErr)(ss.str());
            if (!ok)
            {
                overall_status = 1;
            }
        }
    }

    stop_workers.store(true);
    queue_cv.notify_all();
    for (auto& t : workers)
    {
        t.join();
    }

    server->StopListening();
    Log("[server] shutdown complete.");
    return overall_status;
}

// ---------------------------------------------------------------------------
// Client — per-call pending state for notify-based demultiplexing
// ---------------------------------------------------------------------------

struct PendingCall
{
    bool ready{false};
    bool ok{false};
    std::string result_value;
    std::mutex mutex;
    std::condition_variable cv;
};

static bool RunClient(const int client_index, const int call_count, const int thread_count)
{
    const ServiceParams service_params{
        kServiceIdentifier,
        /*max_payload_bytes=*/static_cast<std::uint32_t>(sizeof(IpcBuffer)),
    };
    const ClientParams client_params{
        /*max_concurrent_threads=*/static_cast<std::uint32_t>(thread_count),
    };

    const auto protocol_config = MakeProtocolConfig(service_params);
    const auto client_config = MakeClientConfig(client_params);

    score::message_passing::ClientFactory client_factory;

    // ------------------------------------------------------------------
    // Client-assigned request IDs: pid in the upper 32 bits, per-process
    // counter in the lower 32 bits.  Unique within this client process and
    // distinguishable across processes (different pids), so the server can
    // echo them back without any server-side ID assignment.
    //
    // Pending-call map: each in-flight request inserts its shared PendingCall
    // BEFORE calling SendWithCallback(), keyed by its pre-assigned id.
    // NotifyCallback looks up by id — the entry is always present because
    // the insert happens before the send, eliminating the gap that previously
    // required a generation counter and two-phase wait.
    //
    // Lock order: always pending_map_mutex before PendingCall::mutex.
    // ------------------------------------------------------------------
    const std::uint64_t pid_upper = static_cast<std::uint64_t>(::getpid()) << 32U;
    std::atomic<std::uint32_t> call_counter{1U};
    std::mutex pending_map_mutex;
    std::unordered_map<std::uint64_t, std::shared_ptr<PendingCall>> pending_map;

    // ------------------------------------------------------------------
    // Create ONE shared connection for the whole process.
    // All threads share it — SendWithCallback() is safe to call concurrently
    // because truly_async=true routes all sends through the library's
    // background thread without blocking the caller.
    // ------------------------------------------------------------------
    auto client = client_factory.Create(protocol_config, client_config);
    if (!client)
    {
        LogErr("[client " + std::to_string(client_index) + "] Create failed");
        return false;
    }

    // The state callback is stored in a score::cpp::callback<> with a fixed
    // 32-byte inline capacity.  Capturing four objects (two promises + two
    // atomics) exceeds that limit, so we box them onto the heap and capture
    // a single pointer — sizeof(void*) == 8 bytes.
    struct ConnectionState
    {
        std::promise<void> ready_promise;
        std::promise<void> stopped_promise;
        std::atomic<bool> ready_set{false};
        std::atomic<bool> stopped_set{false};
    };
    auto conn_state = std::make_shared<ConnectionState>();
    auto ready_future = conn_state->ready_promise.get_future();
    auto stopped_future = conn_state->stopped_promise.get_future();

    // Box the NotifyCallback captures into a heap struct so the lambda fits
    // in the 32-byte inline capacity of score::cpp::callback<>.
    struct NotifyCtx
    {
        std::mutex& pending_map_mutex;
        std::unordered_map<std::uint64_t, std::shared_ptr<PendingCall>>& pending_map;
        int client_index;
    };
    // notify_ctx is shared across all calls; the per-call generation guard is
    // stored inside each PendingCall and checked under pending_map_mutex.
    auto notify_ctx = std::make_shared<NotifyCtx>(NotifyCtx{pending_map_mutex, pending_map, client_index});

    client->Start(
        [conn_state, client_index](score::message_passing::IClientConnection::State state) {
            if (state == score::message_passing::IClientConnection::State::kReady)
            {
                if (!conn_state->ready_set.exchange(true))
                {
                    Log("[client " + std::to_string(client_index) + "] connection ready");
                    conn_state->ready_promise.set_value();
                }
            }
            else if (state == score::message_passing::IClientConnection::State::kStopped)
            {
                if (!conn_state->stopped_set.exchange(true))
                {
                    conn_state->stopped_promise.set_value();
                }
            }
        },
        // NotifyCallback — runs on the library's engine thread.
        // Runs sequentially with ReplyCallback, so the PendingCall is always
        // already in pending_map when a Notify arrives (no early-notify map needed).
        // MUST NOT call any blocking message_passing operation (doc §Client
        // Connection callbacks).  Only parse the payload, look up the pending
        // call by request_id, and signal the condition variable.
        [notify_ctx](score::cpp::span<const std::uint8_t> message) {
            auto start_time = std::chrono::system_clock::now();

            // ControlResponse is not root_type in the schema — parse directly.
            const auto* resp = flatbuffers::GetSizePrefixedRoot<ControlResponse>(message.data());
            if (resp == nullptr)
            {
                LogErr("[client " + std::to_string(notify_ctx->client_index) + "] NotifyCallback: null response root");
                return;
            }

            const std::uint64_t request_id = resp->request_id();
            std::string result_value;
            bool parse_ok = false;

            if (resp->operation_batch() != nullptr && resp->operation_batch()->operations() != nullptr &&
                resp->operation_batch()->operations()->size() > 0U)
            {
                const auto* op = resp->operation_batch()->operations()->Get(0U);
                if (op != nullptr && op->parameter() != nullptr && op->parameter()->size() > 0U &&
                    op->parameter_type() != nullptr &&
                    static_cast<OperationParameter>(op->parameter_type()->Get(0U)) == OperationParameter_String)
                {
                    const auto* str = reinterpret_cast<const String*>(op->parameter()->Get(0U));
                    if (str != nullptr && str->val() != nullptr)
                    {
                        result_value = str->val()->str();
                        parse_ok = true;
                    }
                }
            }

            // Look up and signal the waiting thread.
            // The entry was inserted before SendWithCallback() so it is always
            // present when Notify arrives.  A missing entry means the call already
            // timed out and was erased by the calling thread — discard silently.
            std::lock_guard<std::mutex> map_lk(notify_ctx->pending_map_mutex);
            auto it = notify_ctx->pending_map.find(request_id);
            if (it != notify_ctx->pending_map.end())
            {
                const auto pending = it->second;
                {
                    std::lock_guard<std::mutex> call_lk(pending->mutex);
                    pending->result_value = std::move(result_value);
                    pending->ok = parse_ok;
                    pending->ready = true;
                }
                pending->cv.notify_one();
            }
            else
            {
                LogErr("[client " + std::to_string(notify_ctx->client_index) +
                       "] NotifyCallback: late notify for timed-out request_id=" + std::to_string(request_id) +
                       " — discarded");
            }

            auto end_time = std::chrono::system_clock::now();
            auto diff = end_time - start_time;
            Log("[client " + std::to_string(notify_ctx->client_index) +
                "] NotifyCallback request_id=" + std::to_string(request_id) + " took " +
                std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(diff).count()) + " us");
        });

    if (ready_future.wait_for(std::chrono::seconds(120)) != std::future_status::ready)
    {
        LogErr("[client " + std::to_string(client_index) + "] timed out waiting for connection");
        client->Stop();
        return false;
    }

    // ------------------------------------------------------------------
    // Spawn all client threads.  They all share the single connection.
    // ------------------------------------------------------------------
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

                // Build request
                const std::string str_param = "client" + std::to_string(client_index + 1);
                const std::uint64_t uint64_param = static_cast<std::uint64_t>(c + 1);
                const std::string expected = str_param + "_" + std::to_string(uint64_param);

                // Assign the request_id before building the FlatBuffer so it can
                // be embedded in the payload and inserted into the pending_map —
                // all before the send.  Upper 32 bits = pid (process-unique prefix),
                // lower 32 bits = per-process monotonic counter (thread-unique within
                // this process).  Zero is never produced (counter starts at 1).
                const std::uint64_t request_id = pid_upper | call_counter.fetch_add(1U, std::memory_order_relaxed);

                // Build request FlatBuffer with the pre-assigned request_id.
                // Persisted in a shared_ptr so it outlives the async send queue.
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
                fbb.FinishSizePrefixed(
                    CreateControlRequest(fbb, request_id, /*client_id=*/0U, /*data_node_id=*/0U, batch));

                auto request_buffer = std::make_shared<std::vector<std::uint8_t>>(
                    fbb.GetBufferPointer(), fbb.GetBufferPointer() + fbb.GetSize());
                score::cpp::span<const std::uint8_t> request_span{request_buffer->data(), request_buffer->size()};

                // Insert into the pending map BEFORE the send so the entry is
                // guaranteed to exist when NotifyCallback fires.  No generation
                // counter needed: request_ids are never reused within a process.
                auto pending = std::make_shared<PendingCall>();
                {
                    std::lock_guard<std::mutex> map_lk(pending_map_mutex);
                    pending_map[request_id] = pending;
                }

                {
                    std::ostringstream ss;
                    ss << "[client " << client_index << "/thread " << t << "] -> SendWithCallback() str=\"" << str_param
                       << "\" uint64=" << uint64_param << " request_id=" << request_id;
                    Log(ss.str());
                }

                // ReplyCallback is kept minimal: it only signals the waiting thread
                // on send failure.  On success the ack is ignored — the client
                // already knows its request_id and waits only for the Notify.
                // Box captures into a heap struct to stay within the 32-byte inline
                // capacity of score::cpp::callback<>.
                struct ReplyCtx
                {
                    std::shared_ptr<PendingCall> pending;
                    std::shared_ptr<std::vector<std::uint8_t>> request_buffer;  // keep buffer alive
                    int client_index;
                    int thread_index;
                };
                auto reply_ctx = std::make_shared<ReplyCtx>(ReplyCtx{pending, request_buffer, client_index, t});

                auto reply_callback =
                    [reply_ctx](
                        score::cpp::expected<score::cpp::span<const std::uint8_t>, score::os::Error> ack_expected) {
                        if (!ack_expected.has_value())
                        {
                            std::ostringstream ss;
                            ss << "[client " << reply_ctx->client_index << "/thread " << reply_ctx->thread_index
                               << "] ReplyCallback: ack failed: " << ack_expected.error();
                            LogErr(ss.str());
                            std::lock_guard<std::mutex> call_lk(reply_ctx->pending->mutex);
                            reply_ctx->pending->ok = false;
                            reply_ctx->pending->ready = true;
                            reply_ctx->pending->cv.notify_one();
                        }
                    };

                auto send_result = client->SendWithCallback(request_span, std::move(reply_callback));
                if (!send_result.has_value())
                {
                    std::ostringstream ss;
                    ss << "[client " << client_index << "/thread " << t
                       << "] SendWithCallback() failed: " << send_result.error();
                    LogErr(ss.str());
                    std::lock_guard<std::mutex> map_lk(pending_map_mutex);
                    pending_map.erase(request_id);
                    ++failures;
                    continue;
                }

                // Wait for NotifyCallback to signal ready.
                constexpr auto kNotifyTimeout = std::chrono::seconds(300);
                bool timed_out = false;
                {
                    std::unique_lock<std::mutex> call_lk(pending->mutex);
                    timed_out = !pending->cv.wait_for(call_lk, kNotifyTimeout, [&] {
                        return pending->ready;
                    });
                }

                // Retire: erase from map. The shared state remains alive until all
                // deferred ReplyCallback and NotifyCallback instances release it.
                {
                    std::lock_guard<std::mutex> map_lk(pending_map_mutex);
                    pending_map.erase(request_id);
                }

                if (timed_out)
                {
                    std::ostringstream ss;
                    ss << "[client " << client_index << "/thread " << t
                       << "] TIMEOUT waiting for Notify request_id=" << request_id;
                    LogErr(ss.str());
                    ++failures;
                    continue;
                }

                if (!pending->ok || pending->result_value != expected)
                {
                    std::ostringstream ss;
                    ss << "[client " << client_index << "/thread " << t << "] MISMATCH request_id=" << request_id
                       << ": expected=\"" << expected << "\" got=\""
                       << (pending->ok ? pending->result_value : "<parse error>") << "\"";
                    LogErr(ss.str());
                    ++failures;
                    continue;
                }

                {
                    std::ostringstream ss;
                    ss << "[client " << client_index << "/thread " << t << "] <- OK request_id=" << request_id
                       << " result=\"" << pending->result_value << "\" (Phase 2: Notify received, round-trip complete)";
                    Log(ss.str());
                }

                auto end_time = std::chrono::system_clock::now();
                times[c] = end_time - start_time;

                // std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }

            auto sum = std::chrono::duration<double>::zero();
            for (int c = 0; c < call_count; ++c)
            {
                sum += times[c];
                std::ostringstream oss;
                oss << "[client " << client_index << "/thread " << t << "] call " << (c + 1) << "/" << call_count
                    << ": " << std::chrono::duration_cast<std::chrono::microseconds>(times[c]).count() << " us";
                Log(oss.str());
            }

            if (failures == 0)
            {
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

    client->Stop();
    if (stopped_future.wait_for(std::chrono::seconds(30)) != std::future_status::ready)
    {
        LogErr("[client " + std::to_string(client_index) + "] timed out waiting for connection to stop");
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

}  // namespace score::crypto::ipc::control

// ---------------------------------------------------------------------------
// main — fork before any IPC setup for a clean per-process state
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
            LogErr("[main] invalid argument '" + arg + "': " + ex.what());
            return 1;
        }
    }
    if (g_client_count < 1)
    {
        LogErr("[main] --client_count must be >= 1");
        return 1;
    }
    if (g_call_count < 1)
    {
        LogErr("[main] --call_count must be >= 1");
        return 1;
    }
    if (g_client_threads < 1)
    {
        LogErr("[main] --client_threads must be >= 1");
        return 1;
    }
    if (g_server_threads < 1)
    {
        LogErr("[main] --server_threads must be >= 1");
        return 1;
    }

    Log("[main] client_count=" + std::to_string(g_client_count) + "  call_count=" + std::to_string(g_call_count) +
        "  client_threads=" + std::to_string(g_client_threads) + "  server_threads=" +
        std::to_string(g_server_threads) + "  sleep_milliseconds=" + std::to_string(g_sleep_milliseconds));

    std::vector<pid_t> child_pids;
    int my_client_index = -1;

    for (int i = 0; i < g_client_count; ++i)
    {
        pid_t pid = ::fork();
        if (pid < 0)
        {
            std::perror("[main] fork");
            for (pid_t cpid : child_pids)
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
        return score::crypto::ipc::control::RunServer(child_pids);
    }
    else
    {
        const bool ok = score::crypto::ipc::control::RunClient(my_client_index, g_call_count, g_client_threads);
        return ok ? 0 : 1;
    }
}

// clang-format off

// =============================================================================
// Design comparison: per-thread connection (initial) vs. shared connection
// with Send+Notify (this version)
// =============================================================================
//
// APPROACH A — One IClientConnection per thread, SendWaitReply
// -------------------------------------------------------------
// Client threads each own a dedicated connection to the server.
// SendWaitReply() blocks the calling thread until the server calls Reply().
// The server uses sent_with_reply_callback + pool threads that call Reply().
//
//   Max parallel requests from one client process:
//     Exactly thread_count.  Each connection carries at most one in-flight
//     REQUEST at a time (per-connection REQUEST/REPLY serialization).
//     Adding a thread automatically adds a connection and one more parallel
//     slot — no explicit queue configuration needed.
//
//   Memory / configuration (N client processes, T threads each):
//     Server allocates N*T connection objects, each with its own receive
//     buffer, reply slot, and notify queue.  No application-level queue
//     sizing is required beyond the connection count itself — the parallelism
//     limit is implicit in the number of connections.
//     Server max_queued_sends must cover all N*T concurrent sends.
//
//   Pros:
//   - Simple: no ticket tracking, no response routing, no shared state on the
//     client side.  The transport itself matches requests to replies by
//     connection ordering.
//   - Configuration is trivially correct: parallelism = thread count = connection
//     count, with no additional parameters to keep in sync.
//   - reply_buffer can be stack-allocated per thread.
//
//   Cons:
//   - One OS connection (socket fd pair) per thread.  For N client processes
//     each with T threads, the server holds N*T open connections.
//   - The REQUEST/REPLY protocol serializes the server's sent_with_reply
//     callback per connection (doc §Server callbacks): while Reply() has not
//     been called, no further REQUEST from the same connection is processed.
//     This is fine with one connection per thread (each thread sends one
//     request at a time), but it means the connection count cannot be reduced
//     without losing parallelism.
//   - SendWaitReply() blocks the calling thread inside the library during the
//     entire round-trip; there is no built-in timeout.
//
// APPROACH B — One IClientConnection per process, SendWithCallback + Notify  (this file)
// --------------------------------------------------------------------------------------
// One connection is shared by all threads.  Threads call SendWithCallback() with a
// per-call ReplyCallback.  The ReplyCallback (engine thread) parses the ack and inserts
// into the pending_map.  The NotifyCallback (same engine thread) routes by request_id
// and signals the waiting thread.  The caller waits on an application-level CV with a
// timeout — it is never blocked inside the library.
//
//   Max parallel requests from one client process:
//     Bounded by the minimum of four independently configured sizes:
//       client  max_async_replies  (one slot per in-flight SendWithCallback)
//       client  max_queued_sends   (one slot per concurrent enqueue)
//       server  max_queued_sends   (server-side receive queue, shared across clients)
//       server  max_queued_notifies (per-connection notify queue)
//     All must be set to >= thread_count.  If any one is undersized,
//     SendWithCallback() returns ENOBUFS or Notify() is dropped — with no
//     automatic backpressure to the calling thread.
//
//   Memory / configuration (N client processes, T threads each):
//     Server allocates N connection objects (not N*T).  Total queue capacity:
//
//       server max_queued_sends   — shared across ALL connections (QNX).
//                                   At most N simultaneous REQUESTs (one per
//                                   connection), so N slots suffice.
//
//       server max_queued_notifies — per connection (QNX).
//                                   Must hold T responses for that client's
//                                   threads.  Independent of N.
//
//       client max_async_replies  — per connection, per client process.
//                                   Must hold T concurrent in-flight callbacks.
//
//       client max_queued_sends   — per connection, per client process.
//                                   Must hold T concurrent enqueues.
//
//     All four client sizes must be kept in sync with T; the coupling is
//     enforced by convention only, not by the API.
//
//   Pros:
//   - O(clients) connections instead of O(clients * threads).
//   - SendWithCallback() is non-blocking — the calling thread is never held
//     inside the IPC layer regardless of server behavior.
//   - Application-level wait_for() timeout bounds how long the thread can wait,
//     which is a prerequisite for use in safety-relevant contexts.
//   - ReplyCallback and NotifyCallback run sequentially on the engine thread,
//     so the pending_map needs no early-notify buffer: the entry is always
//     present by the time Notify() arrives.
//   - NotifyCallback runs on the library's own thread — no dedicated receive
//     thread is needed on the client side.
//
//   Cons:
//   - Requires ticket tracking (request_id map + mutex) on the client side.
//   - ReplyCallback and NotifyCallback must not call any blocking message_passing
//     operation (doc §Client Connection callbacks); only signal/mutex work is allowed.
//   - Four queue sizes must all be kept >= thread_count.  Getting any one wrong
//     causes ENOBUFS on send or silent response drops rather than a clean error.
//   - The response FlatBuffer (ControlResponse) must carry the request_id
//     for response routing; a simpler protocol without a correlation id could
//     not use this model.
//
// ANALOGY TO poc_async (mw::com):
//   poc_async faced the same root constraint at the higher abstraction level:
//   mw::com methods also serialize the handler per skeleton instance.  The
//   workaround there was identical in spirit — use a short-lived method call
//   (enqueue only) + a separate event channel (broadcast) for the response.
//   The key difference is that mw::com events broadcast to ALL subscribers,
//   requiring one skeleton per client to prevent cross-client leakage and
//   making the ticket essential for routing.  message_passing Notify() is
//   point-to-point per connection, so one connection per process suffices and
//   the ticket is only needed for intra-process thread response routing.
//
// clang-format on
