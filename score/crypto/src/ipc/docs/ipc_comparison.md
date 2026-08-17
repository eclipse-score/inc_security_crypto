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

| ID | Requirement | Rationale |
|---|---|---|
| R1 | Suitability for ASIL-B use | The library must be designed and documented to support deterministic and bounded execution and resource behavior, controlled heap/allocation use on ASIL-relevant paths, suitable isolation for the deployment, and appropriate quality artifacts such as requirements/design traceability, analysis, verification, and compliance or qualification evidence. |
| R2 | Bounded timeout on every call | WCET must be provable. A stalled QM server must never indefinitely block an ASIL-B client thread. |
| R3 | Resilience to server crash / connection loss | If the server process dies or the connection is lost, the client must receive a typed error. The client must not block indefinitely or silently operate on a dead connection. |
| R4 | Authentic peer identification | Server must be able to identify the calling process via an OS-enforced mechanism, not a client-supplied value. |
| R5 | Minimal or zero configuration | The IPC usage should require minimal configuration and be fully configurable programmatically. |
| R6 | Flexible server-side threading model | The IPC transport must not impose a threading model. The server must be free to choose single-thread, fixed pool, or per-request threads. |
| R7 | Concurrent calls from one process | Multiple threads in one client process must be able to issue independent calls simultaneously. |
| R8 | Multiple concurrent client processes | Multiple independent processes must each be able to connect and call the server simultaneously. |
| R9 | One-to-one communication | Each request maps to exactly one response. No broadcast, no fan-out. |
| R10 | Low latency | IPC overhead should be low. Data throughput is not a priority, since crypto provides a separate data plane for transfer of bigger data elements. |
| R11 | Inter-VM communication | The mechanism must either natively support inter-VM communication on a safety hypervisor, or have a minimal and safe migration path to do so. Crypto has an IPC / connection abstraction which allows the usage of different IPC / connection mechanisms. |

---

## 3. Options Considered

### Option A — gRPC over Unix Domain Socket (current)

gRPC using FlatBuffers serialisation, connected via `unix://` channel. In production use in the repo today via `GrpcControlClient` / `GrpcControlServer`.

### Option B — LoLa Full SOA Abstraction (synchronous Method)

S-CORE `mw::com` LoLa binding, synchronous Method call. Single `Execute(IpcBuffer) → IpcBuffer` method over shared memory. Evaluated in the synchronous LoLa prototype.

### Option C — LoLa Full SOA Abstraction (asynchronous Method + Event)

S-CORE `mw::com` LoLa binding, two-phase protocol: Phase 1 — short blocking Method call returns a ticket; Phase 2 — result delivered via a broadcast Event. Evaluated in the asynchronous LoLa prototype.

### Option D — LoLa Message Passing Abstraction (SendWithCallback + Notify)

The platform-independent message-passing abstraction uses the S-CORE
`score::message_passing` API with `SendWithCallback` / `Reply` / `Notify`
primitives. The transport backend is OS-specific and provided by the framework:
Unix domain socket on Linux, QNX message passing on QNX. The application code is
OS-agnostic. Evaluated in the low-level message-passing prototype.

---

## 4. Decision Matrix

Options C and D use a two-phase protocol (enqueue + async response); R2 applies to both phases independently. For Options A and B, which are single-phase, R2 describes a single blocking call.

The matrix describes target library and architecture capabilities, not completed
production guarantees. ``✅`` means the option appears capable of meeting the
requirement architecturally; ``⚠️`` means the result depends on a wrapper,
backend, configuration, or follow-up implementation; ``❌`` means an identified
architectural mismatch; and ``❓`` means it was not evaluated. The POCs provide
feasibility evidence for selected points, while the production implementation
must validate the remaining requirements.

| Requirement | Option A — gRPC | Option B — LoLa Full SOA (sync) | Option C — LoLa Full SOA (async) | Option D — LoLa Message Passing Abstraction |
|---|---|---|---|---|
| **R1** ASIL-B suitability | ❌ general-purpose gRPC uses framework-managed threads and dynamic runtime resources; the library does not provide an ASIL-oriented deterministic resource profile or safety qualification artifacts | ✅ the LoLa library is documented as safety-oriented/ASIL-B qualified and provides custom memory-management infrastructure suitable for bounded resource use and ASIL-B deployment | ✅ the LoLa library is documented as safety-oriented/ASIL-B qualified and provides custom memory-management infrastructure suitable for bounded resource use and ASIL-B deployment, including its method/event model | ✅ the message-passing library design supports fixed resource bounds, preallocation, and pool/monotonic allocation; the communication module documents safety-oriented quality tooling and ASIL-B qualification |
| **R2** Bounded timeout | ⚠️ current adapter uses a blocking call without a configured deadline; deadline-based or async gRPC was not analyzed | ❌ single-phase blocking call — blocks indefinitely if server stalls | ⚠️ Phase 2 (response event): `wait_for()` indicated in POC; Phase 1 (enqueue): ❌ `DoCall()` holds caller's thread inside LoLa framework with no timeout API — requires framework change | ⚠️ `SendWithCallback()` is non-blocking by design and can support an application-level timeout; mandatory timeout API and typed error handling remain production work, and server-side `Notify()` bounds are backend-dependent |
| **R3** Server crash / connection loss | ❓ not analysed in POC | ❓ not analysed in POC | ❓ not analysed in POC | ⚠️ transport disconnect was observed in the POC; typed propagation to all pending calls and cleanup policy remain production work |
| **R4** Authentic peer identification | ❌ no authentication mechanism | ⚠️ config specifies which UIDs may use a service instance — non-listed UIDs are rejected at runtime by the framework; no API to actively query the connected UID | ⚠️ config specifies which UIDs may use a service instance — non-listed UIDs are rejected at runtime by the framework; no API to actively query the connected UID | ✅ `score::message_passing` exposes an API to retrieve kernel-provided peer credentials from an active connection |
| **R5** Minimal config | ✅ socket path only | ❌ LoLa requires service-oriented configuration for the service, instance, method/event identifiers, application identity, and safety-relevant properties; configuration must be provided consistently to the participating applications and composed with any other `mw::com` services used in the same process | ❌ LoLa requires service-oriented configuration for the service, instance, method/event identifiers, application identity, and safety-relevant properties; configuration must be provided consistently to the participating applications and composed with any other `mw::com` services used in the same process | ⚠️ service identifier only, but worst-case buffer sizes must be configured explicitly: max client processes (N), max concurrent threads per client (T), and max payload size — all must be set to system-wide upper bounds at compile/startup time |
| **R6** Flexible server threading | ⚠️ gRPC owns an internal thread pool; handler is called on gRPC threads. Flexible configuration of that pool may not be sufficient for the required threading model, while a complete replacement of it may be feasible but was not evaluated | ⚠️ skeleton thread processes one call at a time and blocks until the handler returns; handler may dispatch to a pool internally but must block the skeleton on the result — skeleton is always occupied during work | ✅ flexible threading model can be built on top — POC demonstrates a server-side thread pool receiving work via the Phase 1 callback and completing it independently | ✅ `Reply()` callable from any thread at any time — server fully controls threading |
| **R7** Concurrent calls / same process | ✅ channel is thread-safe, no external mechanism needed | ⚠️ concurrent calls depend on the LoLa proxy and method queue configuration; the service abstraction does not make the required parallelism transparent to the application | ⚠️ concurrent calls depend on the LoLa proxy, method queue, and event subscription configuration; the service abstraction does not make the required parallelism transparent to the application | ⚠️ the library supports concurrent use, while request-ID assignment, pending-call tracking, and response multiplexing must be implemented above the library; sufficient resource configuration is also needed |
| **R8** Multiple client processes | ✅ works out of the box | ⚠️ supported through the service-oriented deployment model, but requires consistent application/service configuration across participating processes — see R5 | ⚠️ supported through the service-oriented deployment model, but requires consistent application/service configuration across participating processes — see R5 | ✅ the library supports one server communicating with multiple client processes through independent client/server sessions; sufficient connection and queue resource configuration is needed |
| **R9** One-to-one | ✅ each call gets exactly one response | ✅ each call gets exactly one response | ⚠️ response is a broadcast event — requires one skeleton instance per client to prevent cross-client response leakage | ✅ each call gets exactly one response |
| **R10** Latency | ❌ indicative POC measurement ~430 µs (full request + response) | ❓ not measured | ⚠️ indicative POC measurement ~130 µs (lowest measured value, but still significant IPC overhead) | ⚠️ indicative POC measurement ~160 µs (second-lowest measured value, but still significant IPC overhead) |
| **R11** Inter-VM | ⚠️ gRPC supports network channels, but the current adapter hardcodes Unix-domain endpoints; an endpoint/configuration change and validation of the inter-VM transport and peer-authentication model are required | ⚠️ current LoLa binding is SHM-only (single-kernel); the service-oriented architecture could in principle support a network binding without changing the service API, but no such binding exists today | ⚠️ current LoLa binding is SHM-only (single-kernel); the service-oriented architecture could in principle support a network binding without changing the service API, but no such binding exists today | ❌ current `score::message_passing` backends are local Unix-domain socket and QNX message passing; the library provides no inter-VM transport. A new framework backend would be required. |

**Note:** R1 and R2 are hard safety blockers — any ❌ on these disqualifies an option for safety use regardless of performance on other requirements. Options A, B, and C all carry at least one ❌ on R1 or R2.

**POC note:** The LoLa POCs generated per-client configuration and used unique
application identifiers to exercise multiple clients. These are prototype
workarounds and should not be interpreted as the library's fundamental
configuration model.

---

## 5. Analysis

**Option B (LoLa Full SOA, synchronous)** meets the R1 library-capability assessment: the LoLa library is documented as safety-oriented/ASIL-B qualified and provides custom memory-management infrastructure suitable for bounded resource use. It fails R2 (timeout): there is no two-phase workaround available — the single blocking call holds the caller's thread until the handler returns with no escape path. The synchronous prototype was only validated in-process (skeleton and proxy on separate threads within a single test binary); cross-process concurrency was not tested. The config burden is high and would compound if LoLa is used elsewhere in the same process.

**Option C (LoLa Full SOA, asynchronous)** meets the R1 library-capability assessment: the LoLa library is documented as safety-oriented/ASIL-B qualified and provides custom memory-management infrastructure suitable for bounded resource use, including its method/event model. Its indicative POC latency of approximately 130 microseconds is the lowest measured value, but still represents significant IPC overhead and should remain a warning rather than an unqualified pass. It fails partially on R2: Phase 2 timeout is implemented and flexible server threading is achievable, but Phase 1 timeout requires a LoLa framework change — it cannot be fixed in application code. On server crash, Phase 2 never fires and the client hangs until the application-level timeout expires; the crash itself is not detected independently. The broadcast-event response model requires one skeleton instance per client, adding complexity and config overhead. Notably, LoLa's service-oriented architecture is transport-agnostic by design; a future network binding could enable inter-VM communication without application-level changes — a meaningful long-term advantage that does not resolve the current safety gaps.

**Option A (gRPC)** fails R1 for the stated ASIL-B use because the general-purpose library uses framework-managed threads and dynamic resources and does not provide an ASIL-oriented deterministic resource profile or safety qualification artifacts. The current adapter also does not configure a deadline; deadline-based and asynchronous gRPC were not analyzed. It handles server crash via gRPC status errors but cannot distinguish a crashed server from a hung one without a configured deadline. Peer authentication requires a PKI (no `SO_PEERCRED` equivalent). It remains the strongest option for inter-VM, because gRPC provides network channel support, but the current adapter hardcodes Unix-domain endpoints and requires endpoint/configuration changes before that path is available. It is appropriate for QM-to-QM communication where safety certification is not required.

**Option D (LoLa Message Passing Abstraction)** meets the R1 library-capability assessment: its design supports fixed resource bounds, preallocation, and pool/monotonic allocation, and the communication module documents safety-oriented quality tooling and ASIL-B qualification. Its indicative POC latency of approximately 160 microseconds is the second-lowest measured value, but still represents significant IPC overhead and should remain a warning rather than an unqualified pass. The application code is OS-agnostic; the framework provides the OS-specific transport backend (Unix domain socket on Linux, QNX message passing on QNX). The low-level message-passing prototype provides feasibility evidence for the intended skeleton: non-blocking `SendWithCallback` / `Reply` decoupling, application-level `request_id` multiplexing for concurrent threads, application-level bounded waiting, and detection of server death via socket EOF. Typed error propagation, mandatory timeout APIs, and backend-specific bounded-notification behavior remain implementation work. The selected library does not support inter-VM communication: its current backends are local, and a new framework backend would be required. The `IConnection` abstraction may provide a migration direction, but this has not been demonstrated and is not evidence of current library support.

---

## 6. Decision

**Option D — LoLa Message Passing Abstraction** is selected as the IPC transport for the score-crypto daemon, using `score::message_passing` as its current implementation basis.

---

## 7. Consequences

**Accepted trade-offs:**
- Indicative POC measurements show ~160 µs for message_passing, ~130 µs for LoLa Full SOA (async), and ~430 µs for gRPC. These figures are not a controlled benchmark and must be validated with the proper implementation using a common platform, payload, concurrency, warm-up, and measurement method. The observed gap between LoLa Full SOA and message_passing is partly attributed to configuration: the LoLa Full SOA asynchronous prototype was measured with QM-only settings, whereas the message_passing prototype was configured for mixed usage (`truly_async=true`). Configuring message_passing for QM-only reduced its observed round-trip to ~140 µs; the remaining difference was not analyzed. Throughput would be higher with LoLa Full SOA due to shared memory, but this is not a control-plane requirement: larger data transfers are expected to use a dedicated data plane.
- The selected library does not currently support inter-VM communication. The existing `IConnection` abstraction may guide a second, dedicated IPC mechanism, but that migration path has not been demonstrated and remains separate follow-up work.

**Production implementation follow-up:**

The formal implementation of ``IConnection`` and ``IControlServer`` interfaces
replacing the gRPC adapter is still pending will be taken up.
