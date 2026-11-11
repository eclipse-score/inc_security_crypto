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

Design Decisions
~~~~~~~~~~~~~~~~

.. dec_rec:: Send and Notify Completion
  :id: dec_rec__crypto__send_notify_ipc_interaction
  :version: 1
  :status: accepted
  :context: doc__crypto_architecture
  :decision: Use Send for non-blocking request submission and Notify for the operation result or a negative server-side submission result.
  :affects: comp__ipc_message_passing_adapter

The message-passing adapter uses a non-blocking ``Send`` request followed by a
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

The message-passing interaction is defined as follows:

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
* Queue capacities must cover the configured concurrency. The client send queue
  and server notify queue must still be sized consistently. An undersized queue
  can reject a send or drop a notification.
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


.. dec_rec:: Request Work Is Not Queued
  :id: dec_rec__crypto__ipc_request_work_admission
  :version: 1
  :status: accepted
  :context: doc__crypto_architecture
  :decision: Do not queue request operations in the daemon. Return kProviderBusy when no worker is idle, and let the Crypto API handle it.
  :affects: comp__ipc_message_passing_adapter

Request Work Admission and API Retry
*************************************
Context
^^^^^^^
The asynchronous request path admits work before execution. Queueing a request
in the daemon when all workers are busy would retain pending request state,
delay overload feedback, and require a queue capacity and adjustments to the timeout policy.
Returning ``kProviderBusy`` immediately keeps daemon-side request work bounded.

Decision
^^^^^^^^
``TrySubmitWorkItem`` assigns a request only to an idle worker. When all workers
are busy, it returns ``kProviderBusy`` and the dispatcher sends that result to
the client; request operations are never queued in the daemon.

The Crypto API can then implement a retry strategy for ``kProviderBusy`` responses.

Consequences
^^^^^^^^^^^^
The daemon retains no request backlog, and executing or assigned request work
remains bounded by the worker count.

Implementation of a retry mechanism needs to be handled separately e.g. in the API.

Alternatives Considered
^^^^^^^^^^^^^^^^^^^^^^^

Daemon-side queue or retry
--------------------------

Queueing or retrying inside the daemon would retain requests and require
decisions about queue size, whether it is provider-specific or daemon-wide,
whether capacity is configurable, and what happens when the queue fills. It
would also complicate the ASIL operation-timeout behavior and require a policy
for the delay between retries. A queue cannot eliminate overload rejection:
once full, the daemon still needs to return ``kProviderBusy``.


.. dec_rec:: Purpose-built Worker Executor
  :id: dec_rec__crypto__ipc_fixed_worker_executor
  :version: 1
  :status: accepted
  :context: doc__crypto_architecture
  :decision: Use a purpose-built FixedWorkerWorkItemExecutor to implement the adapter's admission, worker initialization, startup reporting, and restart requirements without an additional scheduler around a generic thread pool.
  :affects: comp__ipc_message_passing_adapter

Custom Worker Executor Instead of Baselibs ThreadPool
*****************************************************

Context
^^^^^^^

The executor must satisfy several independent requirements:

* Request admission follows :need:`dec_rec__crypto__ipc_request_work_admission`;
  request operations are rejected at saturation instead of queued.
* Cleanup work has its own admission policy and bounded queue.
* Each worker has a preconstructed request-handler chain that it reuses.
* Startup reports thread or handler initialization failures before the server
  starts listening.

Decision
^^^^^^^^

Use a purpose-built worker executor to accept work into a thread pool instead of adapting an
existing generic thread pool. Owning the executor lets the adapter implement its request and
cleanup admission policies directly, construct and retain one handler chain per
worker and report worker initialization failures before listening starts.
Reusing a generic pool would require additional coordination around these policies
and lifecycle requirements.

Consequences
^^^^^^^^^^^^

A custom worker executor will be implemented satisfying the requirements outlined above.

Alternatives Considered
^^^^^^^^^^^^^^^^^^^^^^^

Baselibs ``score::concurrency::ThreadPool``
-------------------------------------------

The Baselibs thread pool queues submitted tasks when workers are busy and does
not provide the admission control required by
:need:`dec_rec__crypto__ipc_request_work_admission`. Using it would require an
additional scheduler to reject request work at saturation and to give cleanup
work its separate bounded queue. Coordinating preconstructed per-worker handler
chains, reporting initialization failures before listening starts, and
supporting a stopped-to-started lifecycle would also require additional
orchestration. The custom executor keeps these admission and lifecycle policies
together, at the cost of owning their synchronization.
