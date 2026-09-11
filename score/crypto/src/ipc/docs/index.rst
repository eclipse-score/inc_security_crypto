..
   # *******************************************************************************
   # Copyright (c) 2026 Contributors to the Eclipse Foundation
   #
   # See the NOTICE file(s) distributed with this work for additional
   # information regarding copyright ownership.
   #
   # This program and the accompanying materials are made available under the
   # terms of the Apache License Version 2.0 which is available at
   # https://www.apache.org/licenses/LICENSE-2.0
   #
   # SPDX-License-Identifier: Apache-2.0
   # *******************************************************************************

IPC Design Decisions
====================

Selection of LoLa Message Passing as IPC
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Selection of LoLa Message Passing as IPC
  :id: dec_rec__crypto__lola_message_passing_ipc
  :version: 1
  :status: proposed
  :context: doc__crypto_architecture
  :decision: Use LoLa Message Passing, implemented with the score::message_passing API, as the crypto daemon control-plane IPC transport.

  .. :affects: comp__crypto

LoLa Message Passing, implemented with the ``score::message_passing`` API, is
selected as the target control-plane transport for communication between client
processes and the daemon. Production integration and implementation validation
are follow-up work.

Context
*******

The IPC transport must be suitable for use in an ASIL-B environment. This
includes deterministic and bounded execution and resource behavior, controlled
heap/allocation use on ASIL-relevant paths, suitable isolation for the
deployment, and appropriate quality artifacts such as requirements and design
traceability, analysis, verification, and compliance or qualification evidence.
The safety-relevant deployment target for this decision is QNX. Linux support
is retained for development, testing, and non-safety or QM deployments; Linux
backend limitations are not acceptance blockers for the QNX safety target.
It must also provide bounded client-side waiting, allow concurrent calls from
multiple client processes and threads, expose the identity of the peer, avoid
imposing the daemon's worker-thread model, and keep the application protocol
independent of operating-system transport details.

Decision
********

Use ``score::message_passing`` with FlatBuffers as the serialized control-plane
payload format. The application uses the ``ClientFactory`` and
``ServerFactory`` abstractions and does not depend directly on Unix-domain
socket or QNX message-passing APIs.

The deployment configuration shall establish fixed system-level upper bounds:

* ``N``: maximum number of client processes and server connections.
* ``T``: maximum number of concurrent in-flight requests per client process.
* ``M``: maximum serialized payload size in bytes.

The client and server must use consistent protocol and queue-size settings.
The relevant capacities shall be derived from ``N``, ``T``, and ``M``, and the
expected server connections shall be pre-allocated. These values are
integration parameters, not runtime-adaptive values, and must be reviewed when
the deployment topology or concurrency assumptions change.

Consequences
************

**Positive:**

* Kernel-mediated transport provides process isolation without a shared
  writable memory region between client and daemon processes.
* The server can retrieve kernel-provided peer credentials from an active
  connection, avoiding reliance on a client-supplied identity.
* The application-facing API is OS-agnostic; the framework selects the native
  backend for the target operating system.
* The daemon retains control of its execution model and can dispatch work to a
  fixed worker pool with appropriate implementation.
* The communication module documents safety-oriented quality tooling and ASIL-B
  qualification, while the LoLa Message Passing design supports fixed
  resource bounds, preallocation, and pool/monotonic allocation.
* Multiple client processes and multiple concurrent client threads are
  supported. A shared connection per client process avoids the
  client-process-times-thread connection growth of a per-thread design.
* A service identifier is sufficient to locate the endpoint; no per-client
  service configuration or service registry is required by the application.

**Negative:**

* Safe operation requires explicit worst-case sizing for ``N``, ``T``, and
  ``M``. In particular, an undersized QNX notify queue can cause ``ENOBUFS``
  and a lost response, while inconsistent payload sizes can cause send or
  receive failures.
* The selected LoLa Message Passing implementation does not provide
  inter-VM communication. Inter-VM deployment depends on a future framework
  backend. The separate connection implementation suggested by the crypto IPC
  abstraction is only a possible migration direction.
* The transport is not shared-memory based, so it may have higher per-message
  overhead than LoLa for very high-throughput data transfer. This is not a
  control-plane requirement because bulk data is handled separately.

Alternatives Considered
***********************

gRPC over Unix-Domain Socket
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

gRPC provides mature request/response and inter-VM channel options, but the
general-purpose library uses framework-managed threads and dynamic resources and
does not provide an ASIL-oriented deterministic resource profile or safety
qualification artifacts. The evaluated blocking call also does not establish
the required bounded waiting behaviour. It remains suitable for QM-to-QM
communication and is the strongest option for an immediate network or inter-VM
channel.

LoLa Full SOA Abstraction
^^^^^^^^^^^^^^^^^^^^^^^^^

LoLa is documented as safety-oriented/ASIL-B qualified, with custom
memory-management infrastructure and quality tooling. The synchronous method
lacks an application escape from an indefinitely blocked call. The asynchronous
method layer built on top during POCs, improves server threading and response
timeout handling, but its internal method call still blocks without a timeout
and its broadcast response model requires additional per-client skeleton
instances and response routing.

LoLa Message Passing
^^^^^^^^^^^^^^^^^^^^

The message-passing abstraction exposes platform-independent client and server
factories while keeping the operating-system transport behind the IPC layer.
Using ``Send`` with ``Notify`` separates request submission from operation
completion without the per-connection REQUEST/REPLY serialization window. A
shared connection per client process supports concurrent client threads through
explicit request identifiers and a server-side worker pool, without scaling
connections as ``N * T``. Server-side validation or work-queue submission
failure is reported through a negative ``Notify`` result. The design requires
explicit bounds for client processes, in-flight requests, payload size, and
transport queues, but preserves process isolation and the daemon's freedom to
choose its worker model.

Comparison Summary
******************

The alternatives were assessed against ASIL-B suitability, bounded waiting,
connection-loss handling, authentic peer identification, configuration effort,
server-threading flexibility, concurrency, one-to-one communication, latency,
and inter-VM support.

* **gRPC over Unix-domain sockets** provides mature request/reply semantics and
  the strongest network and inter-VM path. Its general-purpose runtime does not
  provide the deterministic resource profile or safety evidence required for
  the intended ASIL-B use. The current adapter also has no configured deadline,
  and peer authentication would require an additional security mechanism.
* **LoLa Full SOA synchronous Method** provides a safety-oriented service model
  and one-to-one responses, but its blocking call offers no application escape
  when the server stalls. Its service configuration is also more extensive than
  the selected solution requires.
* **LoLa Full SOA asynchronous Method plus Event** allows independent server
  worker execution and bounded waiting for the final event. The initial method
  call remains blocking without a framework change, and broadcast event
  delivery requires additional per-client instances and response routing.
* **LoLa Message Passing** provides platform-independent client and server
  factories, process-isolating transport, kernel-provided peer credentials,
  and a server-controlled worker model. ``Send`` followed by ``Notify`` supports
  concurrent calls over one connection per client process, with application-
  level request identifiers for response routing. A negative ``Notify`` result
  reports server-side validation or work-queue submission failure. It requires
  explicit resource bounds and a typed timeout and connection-loss contract. It
  does not provide inter-VM communication.

LoLa Message Passing is selected because it best satisfies the ASIL-B,
bounded-client-waiting, peer-identity, concurrency, and server-threading goals
while keeping operating-system transport details below the application IPC
interface. The remaining backend, error-contract, resource-sizing, and inter-VM
limitations are explicit implementation and verification work.

Justification for the Decision
******************************

LoLa Message Passing is the only evaluated option that appears capable of
meeting the broader ASIL-B use goals and the bounded client call-path goal based
on its library design and documented quality properties. Meeting the timeout
and connection-loss requirements still depends on the production IPC wrapper,
and a typed error contract. The lack of inter-VM communication is accepted,
the control-plane IPC abstraction can potentially be used to offer a separate
inter-VM transport in the future.

Send and Notify Completion
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Send and Notify Completion
  :id: dec_rec__crypto__send_notify_ipc_interaction
  :version: 1
  :status: proposed
  :context: doc__crypto_architecture
  :decision: Use Send for non-blocking request submission and Notify for the operation result or a negative server-side submission result.

  .. :affects: comp__crypto

The selected IPC protocol uses a non-blocking ``Send`` request followed by a
point-to-point ``Notify`` message containing either the operation result or a
negative result when server-side validation or work-queue submission fails.

Context
*******

Using LoLa Message Passing, the selected ``Send`` path avoids the per-connection
REQUEST/REPLY serialization window. A client process may have many threads
issuing independent operations, and the server must be able to process those
operations concurrently.

Using a single long-running request callback would keep the shared connection
occupied for the duration of the cryptographic operation. The selected
communication model returns from the ``Send`` callback after validation and
work-queue submission, then performs the operation in a worker and sends the
terminal result with ``Notify``. The client uses an application-level timeout;
it does not wait indefinitely inside the IPC library.

Decision
********

The protocol is defined as follows:

1. The client assigns a unique non-zero ``request_id``, inserts a pending-call
   record, and calls ``Send`` with the FlatBuffer ``ControlRequest``.
2. The server validates the request and copies the complete request into the
   application work queue. If validation or queue submission fails, the server
   sends a negative ``Notify`` result carrying the request ID when it can be
   recovered from the request.
3. A server worker performs the operation and calls ``Notify`` on the same
   ``IServerConnection`` with a ``ControlResponse`` carrying the original
   ``request_id`` and the result payload.
4. The client ``NotifyCallback`` routes the response by ``request_id`` and
   signals the waiting application thread. The application waits with a
   bounded timeout and retires the pending-call record after completion, error,
   or timeout.

The ``Send`` call confirms only that the request was accepted by the client-side
send path; it is not an immediate admission acknowledgement. The transport
does not automatically retry requests. If a result or negative ``Notify`` is
not observed because of a timeout or delivery failure, the outcome is unknown
to the caller. The application may explicitly retry when the operation
semantics allow it. A malformed request for which the server cannot recover a
request ID cannot be correlated to a pending call and must be handled through
the connection-error or timeout path.

Consequences
************

**Positive:**

* ``Send`` avoids the per-connection REQUEST/REPLY serialization window before
  the potentially slow operation. Subsequent requests can be accepted while
  earlier requests execute in the worker pool.
* ``Send`` returns without holding the caller inside the IPC operation. A
  production wrapper can use a mandatory application-level ``wait_for`` to
  provide a bounded wait for the final response and report a typed timeout.
* One connection can be shared by all threads in a client process. The
  application-level ``request_id`` protocol provides deterministic response
  demultiplexing without requiring one connection per thread.
* ``Notify`` is point-to-point, so a response is delivered only to the client
  connection that issued the request. This avoids the cross-client response
  leakage risk of a broadcast event model.
* The server can use a fixed worker pool and must protect connection lifetime
  while workers complete delayed notifications.

**Negative:**

* The protocol and implementation are more complex than a single synchronous
  call. Pending-call state, request identifiers, response parsing, timeout
  cleanup, and late-notification handling are required.
* ``Send`` does not provide an immediate admission acknowledgement; callers
  must handle negative ``Notify`` results and final-notification timeouts.
* Queue capacities must cover the configured concurrency. The client send queue and server
  notify queue must still be sized consistently. An undersized queue can reject
  a send or drop a notification.
* A worker may finish after the client has timed out. The server must detect a
  disconnected connection or safely skip the notification, and the client
  must discard late notifications for retired request identifiers.
* ``Notify`` has backend-dependent blocking behaviour. The QNX backend used by
  the safety target provides bounded preallocated notification capacity and
  reports exhaustion as ``ENOBUFS``; queue sizing and the resulting failure
  handling remain part of the QNX production configuration. The Linux backend
  may block in the socket layer, which is an accepted limitation for
  development, testing, and non-safety or QM deployments and must not be used
  as evidence for a Linux safety deployment.

Alternatives Considered
***********************

Single SendWaitReply Call
^^^^^^^^^^^^^^^^^^^^^^^^^

The client sends a request and waits for the server to return the final result
through the REQUEST/REPLY exchange. This is simpler and naturally matches one
request to one response, but it blocks the caller inside the IPC library for
the whole operation and provides no application-level timeout. With a shared
connection, the server callback also serializes all requests until work is
complete.

Long-Running SendWithCallback Reply
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The server could defer ``Reply`` until the worker has finished and return the
final response through ``ReplyCallback``. This preserves a single response
channel, but retains the per-connection serialization window for the entire
operation. It prevents the shared-connection design from accepting concurrent
requests at the intended rate and makes the server callback lifetime depend on
operation duration.

LoLa Method plus Broadcast Event
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The LoLa asynchronous method plus event uses a short method call followed by an
event, which has similar separation of acceptance and completion. Its event is
broadcast, however, so the design needs one skeleton instance per client and
additional routing to prevent clients from observing one another's responses.
The ``Notify`` primitive provides the same asynchronous completion model as a
point-to-point message on the existing client connection.

Justification for the Decision
******************************

``Send`` plus ``Notify`` is selected because it avoids the request/reply
serialization window and the client-side acknowledgement queue while allowing
the server to dispatch work independently. The ``Notify`` completion keeps the
client thread out of the IPC library's blocking path, enables an explicit
application timeout, and preserves one connection per client process. A
negative ``Notify`` communicates server-side submission failure when the
request ID is available.

Reference
~~~~~~~~~

.. include:: ipc_comparison.md
  :parser: myst_parser.sphinx_
