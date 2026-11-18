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

Design Decision: Selection of IPC Transport
===========================================

Selection of LoLa Message Passing as IPC
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Selection of LoLa Message Passing as IPC
  :id: dec_rec__crypto__lola_message_passing_ipc
  :version: 1
  :status: accepted
  :context: doc__crypto_architecture
  :decision: Use LoLa Message Passing, implemented with the score::message_passing API, as the crypto daemon control-plane IPC transport.
  :affects: comp__ipc_message_passing_adapter

LoLa Message Passing, implemented with the ``score::message_passing`` API, is
selected as the target control-plane transport for communication between client
processes and the daemon.

Context
*******

The IPC transport must be suitable for use in an ASIL-B environment. It must also provide
bounded client-side waiting, allow concurrent calls from
multiple client processes and threads, expose the identity of the peer, avoid
imposing the daemon's worker-thread model, and keep the application protocol
independent of operating-system transport details.

Decision
********

Use ``score::message_passing`` as the control-plane transport. The application
uses the ``ClientFactory`` and ``ServerFactory`` abstractions and does not
depend directly on Unix-domain socket or QNX message-passing APIs. The current
shared control protocol serializes payloads with FlatBuffers; that encoding is
separate from this transport selection.

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

Reference
~~~~~~~~~

.. include:: ipc_comparison.md
  :parser: myst_parser.sphinx_
