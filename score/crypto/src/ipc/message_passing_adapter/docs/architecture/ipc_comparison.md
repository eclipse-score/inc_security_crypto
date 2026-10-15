<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# DAR — IPC Mechanism for score-crypto Daemon

| | |
|---|---|
| **Status** | Draft |
| **Date** | 2026-08-13 |
| **Author** | ETAS |
| **Context** | score-crypto daemon IPC transport selection |

---

## 1. Problem Statement

The score-crypto daemon requires an IPC transport to serve cryptographic operations to client processes. The current implementation uses gRPC. The target deployment environment is automotive ECUs with strict functional-safety requirements (ISO 26262), potentially running mixed ASIL-level workloads, possibly across VM boundaries. A replacement or continuation decision is needed.

---

## 2. Requirements

The requirement definitions and exact headings are maintained in the
{doc}`Crypto IPC Requirements <../requirements/requirements>` artifact.

---

## 3. Options Considered

### Option A — gRPC over Unix Domain Socket (current)

gRPC using FlatBuffers serialisation, connected via `unix://` channel. In production use in the repo today via `GrpcControlClient` / `GrpcControlServer`.

### Option B — LoLa Full SOA Abstraction (synchronous Method)

S-CORE `mw::com` LoLa binding, synchronous Method call. Single `Execute(IpcBuffer) → IpcBuffer` method over shared memory. Evaluated in the synchronous LoLa prototype.

### Option C — LoLa Full SOA Abstraction (asynchronous Method + Event)

S-CORE `mw::com` LoLa binding, two-phase protocol: Phase 1 — short blocking Method call returns a ticket; Phase 2 — result delivered via a broadcast Event. Evaluated in the asynchronous LoLa prototype.

### Option D — LoLa Message Passing Abstraction (SendWithCallback + Reply + Notify)

The platform-independent message-passing abstraction uses the S-CORE
`score::message_passing` API with `SendWithCallback` / `Reply` / `Notify`
primitives. The transport backend is OS-specific and provided by the framework:
Unix domain socket on Linux, QNX message passing on QNX. The application code is
OS-agnostic. Evaluated in the low-level message-passing prototype.

### Option E — LoLa Message Passing Abstraction (Send + Notify, no Reply)

The same platform-independent message-passing abstraction, using `Send` for
non-blocking request submission and `Notify` for the operation result. The
server does not send an immediate `Reply`; it copies each request into its
application work queue and a worker sends the terminal response. The client
uses the request ID in the payload to route the point-to-point notification.
Evaluated in `poc_low_level_no_reply.cpp`.

### Option F — Message Passing Engine (bootstrap + per-thread Reply)

The `score::message_passing` Engine model uses a bootstrap endpoint to create
one on-demand service endpoint and server Engine session per client thread.
Each client thread then owns one connection and uses `SendWithCallback`; the
server Engine performs the complete operation in its request callback and
returns the result with `Reply()`. There is no application-owned work queue or
worker pool. Evaluated in `poc_engine.cpp`.

---

## 4. Decision Matrix

Options C, D, and E use an enqueue + asynchronous response protocol. Option F
uses a bootstrap handshake followed by a blocking server callback; R2 applies
to the client submission/wait and the server callback separately. For Options
A and B, which are single-phase, R2 describes a single blocking call.

The matrix describes target library and architecture capabilities, not completed
production guarantees. ``✅`` means the option appears capable of meeting the
requirement architecturally; ``⚠️`` means the result depends on a wrapper,
backend, configuration, or follow-up implementation; ``❌`` means an identified
architectural mismatch; and ``❓`` means it was not evaluated. The POCs provide
feasibility evidence for selected points, while the production implementation
must validate the remaining requirements.

| Requirement | Option A — gRPC | Option B — LoLa Full SOA (sync) | Option C — LoLa Full SOA (async) | Option D — LoLa Message Passing (ack + notify) | Option E — LoLa Message Passing (send + notify) | Option F — Message Passing Engine (per-thread Reply) |
|---|---|---|---|---|---|---|
| **R1** Suitability for ASIL-B use | ❌ general-purpose gRPC uses framework-managed threads and dynamic runtime resources; the library does not provide an ASIL-oriented deterministic resource profile or safety qualification artifacts | ✅ the LoLa library is documented as safety-oriented/ASIL-B qualified and provides custom memory-management infrastructure suitable for bounded resource use and ASIL-B deployment | ✅ the LoLa library is documented as safety-oriented/ASIL-B qualified and provides custom memory-management infrastructure suitable for bounded resource use and ASIL-B deployment, including its method/event model | ✅ the message-passing library design supports fixed resource bounds, preallocation, and pool/monotonic allocation; the communication module documents safety-oriented quality tooling and ASIL-B qualification | ✅ the same message-passing library capabilities apply; the POC uses bounded queues and an application-owned worker pool | ⚠️ the same library provides safety-oriented capabilities, but the POC dynamically creates one endpoint and Engine session per client thread; bounded startup/resource evidence for production use is still required |
| **R2** Bounded timeout on every call | ⚠️ current adapter uses a blocking call without a configured deadline; deadline-based or async gRPC was not analyzed | ❌ single-phase blocking call — blocks indefinitely if server stalls | Phase 2 (response event) has a `wait_for()` in the POC, but Phase 1 (enqueue) `DoCall()` holds the caller's thread inside LoLa framework with no timeout API — because R2 applies to every phase, the option fails overall and requires a framework change | ⚠️ `SendWithCallback()` is non-blocking by design and can support an application-level timeout; mandatory timeout API and typed error handling remain production work. For QNX, configured Notify capacity is bounded; Linux socket blocking is outside the safety scope | ⚠️ `Send()` is non-blocking when the send queue and `truly_async` mode are configured; the client can bound its wait for `Notify()`. For QNX, configured Notify capacity is bounded; Linux socket blocking is outside the safety scope | ⚠️ client waits use an application timeout, but the server Engine callback performs the operation synchronously and has no operation deadline or cancellation path; a stalled callback can occupy the session indefinitely |
| **R3** Resilience to connection loss | ❓ not analysed in POC | ❓ not analysed in POC | ❓ not analysed in POC | ⚠️ transport disconnect was observed in the POC; typed propagation to all pending calls and cleanup policy remain production work | ⚠️ the POC wakes pending calls when the client connection reaches stopped, but typed error propagation, late notifications, and all delivery-failure paths remain production work | ⚠️ connection state is observed, but the current response wait is not directly completed by a stopped callback; crash/error propagation and bootstrap/session cleanup remain production work |
| **R4** Authentic peer identification | ❌ no UID based authentication mechanism | ⚠️ config specifies which UIDs may use a service instance — non-listed UIDs are rejected at runtime by the framework; no API to actively query the connected UID | ⚠️ config specifies which UIDs may use a service instance — non-listed UIDs are rejected at runtime by the framework; no API to actively query the connected UID | ✅ `score::message_passing` exposes an API to retrieve kernel-provided peer credentials from an active connection | ✅ same as Option D; the transport exposes kernel-provided peer credentials from an active connection | ✅ the server reads kernel-provided UID credentials in bootstrap and session connect callbacks |
| **R5** Minimal or zero configuration | ✅ socket path only | ❌ LoLa requires service-oriented configuration for the service, instance, method/event identifiers, application identity, and safety-relevant properties; configuration must be provided consistently to the participating applications and composed with any other `mw::com` services used in the same process | ❌ LoLa requires service-oriented configuration for the service, instance, method/event identifiers, application identity, and safety-relevant properties; configuration must be provided consistently to the participating applications and composed with any other `mw::com` services used in the same process | ⚠️ service identifier only, but worst-case buffer sizes must be configured explicitly: max client processes (N), max concurrent threads per client (T), and max payload size — all must be set to system-wide upper bounds at compile/startup time | ⚠️ service identifier only, but N, T, M, send-queue, and notify-queue bounds still must be configured explicitly; the no-`Reply` model removes the async-reply queue from the client-side sizing | ❌ requires a bootstrap endpoint, dynamically generated per-thread service identifiers, one session endpoint per thread, and separate connection/Engine lifecycle management |
| **R6** Flexible server-side threading model | ⚠️ gRPC owns an internal thread pool; handler is called on gRPC threads. Flexible configuration of that pool may not be sufficient for the required threading model, while a complete replacement of it may be feasible but was not evaluated | ⚠️ skeleton thread processes one call at a time and blocks until the handler returns; handler may dispatch to a pool internally but must block the skeleton on the result — skeleton is always occupied during work | ✅ flexible threading model can be built on top — POC demonstrates a server-side thread pool receiving work via the Phase 1 callback and completing it independently | ✅ `Reply()` callable from any thread at any time — server fully controls threading | ✅ `Notify()` callable from worker threads; the server queues work before returning from the `Send` callback, so it retains full control of the worker model | ❌ operation work runs on the message-passing Engine callback thread; the model does not provide an application-controlled worker-pool or per-request dispatch boundary |
| **R7** Concurrent calls from one process | ✅ channel is thread-safe, no external mechanism needed | ⚠️ concurrent calls depend on the LoLa proxy and method queue configuration; the service abstraction does not make the required parallelism transparent to the application | ⚠️ concurrent calls depend on the LoLa proxy, method queue, and event subscription configuration; the service abstraction does not make the required parallelism transparent to the application | ⚠️ the library supports concurrent use, while request-ID assignment, pending-call tracking, and response multiplexing must be implemented above the library; sufficient resource configuration is also needed | ⚠️ the library supports concurrent `Send()` calls, while request-ID assignment, pending-call tracking, and response multiplexing remain application responsibilities; fewer queue types need sizing than Option D | ⚠️ each client thread has its own endpoint and connection, so no application-level response multiplexing is required; however, concurrency scales open channels and Engine resources with thread count, and QNX imposes platform/deployment limits on the number of open channels |
| **R8** Multiple concurrent client processes | ✅ works out of the box | ⚠️ supported through the service-oriented deployment model, but requires consistent application/service configuration across participating processes — see R5 | ⚠️ supported through the service-oriented deployment model, but requires consistent application/service configuration across participating processes — see R5 | ✅ the library supports one server communicating with multiple client processes through independent client/server sessions; sufficient connection and queue resource configuration is needed | ✅ same as Option D; one server can communicate with multiple client processes through independent sessions, subject to connection and queue bounds | ⚠️ the POC exercises one client process; supporting multiple client processes requires bootstrap/session ownership and endpoint namespace rules beyond the demonstrated setup, and the per-thread channel model is constrained by QNX platform/deployment limits on the number of open channels |
| **R9** One-to-one communication | ✅ each call gets exactly one response | ✅ each call gets exactly one response | ⚠️ response is a broadcast event — requires one skeleton instance per client to prevent cross-client response leakage | ✅ each call gets exactly one response | ✅ each `Send()` gets one point-to-point `Notify()` response | ✅ each per-thread request receives one `Reply()` on its dedicated connection |
| **R10** Low latency | ⚠️ indicative POC measurement ~420 µs / 1244 µs | ❓ not measured | ⚠️ indicative POC measurement ~130 µs / - | ⚠️ indicative POC measurement ~155 µs / 342 µs | ⚠️ indicative POC measurement ~141 µs / 219 µs | ⚠️ indicative POC measurement ~99 µs / 185 µs |
| **R11** Inter-VM communication | ⚠️ gRPC supports network channels, but the current adapter hardcodes Unix-domain endpoints; an endpoint/configuration change and validation of the inter-VM transport and peer-authentication model are required | ⚠️ current LoLa binding is SHM-only (single-kernel); the service-oriented architecture could in principle support a network binding without changing the service API, but no such binding exists today | ⚠️ current LoLa binding is SHM-only (single-kernel); the service-oriented architecture could in principle support a network binding without changing the service API, but no such binding exists today | ❌ current `score::message_passing` backends are local Unix-domain socket and QNX message passing; the library provides no inter-VM transport. A new framework backend would be required. | ❌ same as Option D; the no-`Reply` protocol does not change the available local-only backends and a new framework backend would be required. | ❌ uses the same local Unix-domain socket and QNX message-passing backends; the bootstrap/session arrangement does not add inter-VM transport |
| **R12** C++/Rust interoperability | ✅ Tonic supports Rust gRPC clients/servers and custom codecs, and FlatBuffers supports Rust; cross-language use of this POC's C++-generated stubs is unverified | ⚠️ the v0.5.0 Rust COM interface macro rejects `Method<T>`; Rust Method support may be added later | ⚠️ Rust COM supports the Event phase, but the required `Method<T>` request phase is unsupported in v0.5.0 and may be added later | ❌ the v0.5.0 `score::message_passing` API is C++ only; Rust binding may not be in scope | ❌ the v0.5.0 `score::message_passing` API is C++ only; Rust binding may not be in scope | ❌ the Engine uses the C++-only `score::message_passing` API; Rust binding may not be in scope |
| **R13** Payload agnostic communication | ✅ gRPC transports the common serialized envelope; payload variants remain an application-schema concern | ✅ the fixed `IpcBuffer` method argument carries the common serialized envelope (POC limit: 4 KiB) | ✅ the fixed `IpcBuffer` method/event payload carries the common serialized envelope (POC limit: 4 KiB) | ✅ `SendWithCallback()`, `Reply()`, and `Notify()` carry opaque bytes for the common envelope | ✅ `Send()` and `Notify()` carry opaque bytes for the common envelope | ✅ Engine request/reply messages carry opaque bytes for the common envelope |

**Note:** R1 and R2 are hard safety blockers — any ❌ on these disqualifies an option for safety use regardless of performance on other requirements. Options A, B, and C each fail at least one of these requirements: A on R1, B on R2, and C on R2 because its Phase 1 enqueue has no timeout, even though its Phase 2 response wait is bounded.

**R12 evidence:** [Tonic's gRPC server API](https://docs.rs/tonic/latest/tonic/server/struct.Grpc.html)
supports a custom codec, and
[FlatBuffers supports Rust code generation and serialization](https://flatbuffers.dev/languages/rust/).
This shows an architectural path for Option A, but not a cross-language POC;
the local build generates its gRPC service bindings in C++. The
[score_communication v0.5.0 Rust interface macro](https://github.com/eclipse-score/communication/blob/v0.5.0/score/mw/com/rust/score_com_concept/interface_macros.rs)
rejects ``Method<T>`` definitions. The
[v0.5.0 message-passing BUILD](https://github.com/eclipse-score/communication/blob/v0.5.0/score/message_passing/BUILD)
declares C++ library targets and no Rust binding.

R13 assumes all peers use a common application-level base/envelope that
identifies the payload type and carries its encoded data. Each IPC option
transports that envelope; the application schema/encoding must remain
consistent between the communicating peers. The POC-specific payload limits
still apply, including the 4 KiB ``IpcBuffer`` used by Options B and C.

**POC note:** The LoLa POCs generated per-client configuration and used unique
application identifiers to exercise multiple clients. These are prototype
workarounds and should not be interpreted as the library's fundamental
configuration model.

---

## 5. Analysis

**Option A (gRPC)** fails R1 for the stated ASIL-B use because the general-purpose library uses framework-managed threads and dynamic resources and does not provide an ASIL-oriented deterministic resource profile or safety qualification artifacts. The current adapter also does not configure a deadline; deadline-based and asynchronous gRPC were not analyzed. It handles server crash via gRPC status errors but cannot distinguish a crashed server from a hung one without a configured deadline. Peer authentication requires a PKI (no `SO_PEERCRED` equivalent). It remains the strongest option for inter-VM, because gRPC provides network channel support, but the current adapter hardcodes Unix-domain endpoints and requires endpoint/configuration changes before that path is available. It is appropriate for QM-to-QM communication where safety certification is not required.

**Option B (LoLa Full SOA, synchronous)** meets the R1 library-capability assessment: the LoLa library is documented as safety-oriented/ASIL-B qualified and provides custom memory-management infrastructure suitable for bounded resource use. It fails R2 (timeout): there is no two-phase workaround available — the single blocking call holds the caller's thread until the handler returns with no escape path. The synchronous prototype was only validated in-process (skeleton and proxy on separate threads within a single test binary); cross-process concurrency was not tested. The config burden is high and would compound if LoLa is used elsewhere in the same process.

**Option C (LoLa Full SOA, asynchronous)** meets the R1 library-capability assessment: the LoLa library is documented as safety-oriented/ASIL-B qualified and provides custom memory-management infrastructure suitable for bounded resource use, including its method/event model. Its indicative POC latency is approximately 130 microseconds on WSL. It fails R2 overall: Phase 2 timeout is implemented and flexible server threading is achievable, but Phase 1 timeout contradicts the assumption of use of LoLa — it cannot be fixed in application code. Because R2 applies to every phase, the bounded Phase 2 wait does not compensate for the unbounded Phase 1 call. On server crash, Phase 2 never fires and the client hangs until the application-level timeout expires; the crash itself is not detected independently. The broadcast-event response model requires one skeleton instance per client, adding complexity and config overhead. Notably, LoLa's service-oriented architecture is transport-agnostic by design; a future network binding could enable inter-VM communication without application-level changes — a meaningful long-term advantage that does not resolve the current safety gaps.

**Option D (LoLa Message Passing Abstraction)** meets the R1 library-capability assessment: its design supports fixed resource bounds, preallocation, and pool/monotonic allocation, and the communication module documents safety-oriented quality tooling and ASIL-B qualification. Its indicative POC latency is approximately 155 microseconds on WSL and 342 microseconds on QNX in the collected runs. The application code is OS-agnostic; the framework provides the OS-specific transport backend (Unix domain socket on Linux, QNX message passing on QNX). The low-level message-passing prototype provides feasibility evidence for the intended skeleton: non-blocking `SendWithCallback` / `Reply` decoupling, application-level `request_id` multiplexing for concurrent threads, application-level bounded waiting, and detection of server death via socket EOF. Typed error propagation, mandatory timeout APIs, and backend-specific bounded-notification behavior remain implementation work. The selected library does not support inter-VM communication: its current backends are local, and a new framework backend would be required. The `IConnection` abstraction may provide a migration direction, but this has not been demonstrated and is not evidence of current library support.

**Option E (LoLa Message Passing Abstraction, send plus notify)** uses the same
OS-agnostic library and shared connection model, but removes the immediate
`Reply` acknowledgement. `Send()` is configured as fire-and-forget and the
server's callback only validates and queues the request; a worker later sends
the result with `Notify()`. This avoids the per-connection REQUEST/REPLY
serialization window and the client-side async-reply queue, making the
protocol simpler and potentially reducing submission overhead. It does not
provide an immediate admission acknowledgement: a successful `Send()` only
means the request was accepted by the client-side send path. If server-side
validation or work-queue submission fails, the server can return a negative
`Notify()` result; otherwise, `Notify()` carries the operation result. The POC
still requires application-level request IDs, pending-call tracking, bounded
waiting, queue sizing, and connection-lifetime protection for worker
notifications. Its indicative POC latency is approximately 141 microseconds on
WSL and 219 microseconds on QNX in the collected runs. Like Option D, it does
not provide inter-VM communication.

**Option F (Message Passing Engine)** demonstrates a bootstrap handshake that
creates a dedicated service endpoint, server Engine session, and client
connection for each client thread. The server Engine performs the complete
operation in its request callback and returns the response with `Reply()`, so
the POC needs no application work queue, worker pool, request-ID map, or
`Notify()` path. This makes one-to-one response matching straightforward and
keeps the server implementation small, but it couples the server's execution
capacity to the number of Engine sessions and client threads. The callback has
no operation deadline or cancellation path, so a stalled operation occupies
its Engine session and the client's application wait can expire without
interrupting the server work. The bootstrap and per-thread endpoint lifecycle
also add substantial configuration and resource-management complexity; the POC
does not establish the multiple-client-process or bounded-resource behavior
needed for production. As with Options D and E, the current backends do not
provide inter-VM communication. On QNX, the maximum number of open channels is
configurable, but the per-thread design consumes one channel and Engine session
per client thread against that limit, leading to many channels open at the
server side. QNX recommends sharing a single channel among multiple threads
instead, so this POC's scaling model is not the platform-preferred approach
and would need a deployment-specific channel-count assessment or redesign. Its
indicative POC latency is approximately 99 microseconds on WSL and 185
microseconds on QNX in the collected runs, but this performance does not offset
its R2, R6, and resource-scaling limitations.

---

## 6. Decision

**Option E — LoLa Message Passing Abstraction (Send + Notify)** is selected as the IPC transport for the score-crypto daemon, using `score::message_passing` as its current implementation basis. The no-`Reply` protocol avoids the per-connection request/reply serialization window and still allows server-side submission failures to be reported through a negative `Notify()` result.

---

## 7. Consequences

**Accepted trade-offs:**
- Option E is not the fastest measured option: the indicative results show lower round-trip latency for Option F and, in some measurements, for the asynchronous LoLa POC. Option E is selected because it provides a better overall balance across the requirements, including bounded client-side waiting, concurrent client and server operation, point-to-point responses, peer identification, configuration, and server-threading flexibility. Further preliminary measurements indicated that the IPC overhead was below 20% of the overall operation time (of the target daemon architecture), reducing the practical impact of the latency difference.
- Option E does not provide an immediate admission acknowledgement. A successful `Send()` confirms only client-side enqueueing; server-side validation or work-queue submission failure must be returned through a negative `Notify()`, and the client must handle final-result timeouts and late notifications. In rare cases (Server cannot retrieve request_id), the notify cannot be matched to a specific client request. This however is considered as a rare case and could be partially mitigated e.g. by relying on the timeout mechanism.
- The selected library does not currently support inter-VM communication. The existing `IConnection` abstraction may guide a second, dedicated IPC mechanism, but that migration path has not been demonstrated and remains separate follow-up work.

**Production implementation follow-up:**

The formal implementation of the ``IConnection`` and ``IControlServer``
interfaces to replace the gRPC adapter remains pending and will be addressed
separately.
