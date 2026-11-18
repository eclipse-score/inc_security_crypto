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

.. _crypto_message_passing_adapter_architecture:

Message-Passing Adapter Architecture
====================================

.. document:: Message-Passing Adapter Architecture
  :id: doc__crypto_msg_pass_arch
  :version: 1
  :status: draft
  :safety: ASIL_B
  :security: YES
  :realizes: wp__feature_arch

Overview
--------

The message-passing adapter is the current concrete IPC implementation for the crypto daemon control plane. It coordinates client calls, connection and session state, request dispatch, and worker execution, using SCORE message passing to carry serialized frames. It does not implement the crypto operations or the underlying transport.

The client API is synchronous from its caller's perspective: a call waits for a matching response, a terminal error, or its bounded timeout. On the server, transport callbacks hand incoming frames to session admission and request dispatch, while worker threads execute admitted operations independently of the transport callback.

The adapter currently constructs ``FlatBufferCodec`` for the shared crypto control protocol. The
codec contract, schema, and wire format are documented in
:doc:`../../../protocol/docs/index`; the package boundary does not by itself make alternate
transports or codecs pluggable end to end.

Static Architecture
-------------------

.. uml:: message_passing_adapter_architecture.puml
  :align: center
  :caption: Message-Passing Adapter Static Architecture
  :alt: Component diagram of the message-passing adapter's client, protocol, transport, and server components.

The connection interfaces carry serialized frames and transport lifecycle callbacks across the process boundary. The client and server use the same codec contract and FlatBuffers schema, while their session and work-item state remains process-local.

Components and Responsibilities
-------------------------------

Client Side
~~~~~~~~~~~

MessagePassingControlClient
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Client-facing synchronous facade for the message-passing control protocol. Owns the transport
factory and codec; ``ClientSession`` owns the connection and its request and transport lifecycle
state.

ClientSession
^^^^^^^^^^^^^

Coordinates request/response calls and transport lifecycle for one client connection. Encoded
responses are matched to pending calls by request ID. Shutdown terminates outstanding calls and
waits for the transport to stop.

PendingCallRegistry
^^^^^^^^^^^^^^^^^^^

Registers client calls and correlates terminal responses by request ID. Owns the pending-call map
for a client session and propagates transport failures to all calls.

PendingCall
^^^^^^^^^^^

Holds the completion state and result for one client request. Provides synchronized response
waiting and a single terminal transition to completed or failed.

Transport
~~~~~~~~~

SCORE Message-Passing Transport
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Moves serialized byte frames between ``IClientConnection`` and ``IServerConnection`` and reports
connection lifecycle events. The adapter uses this transport today; the codec itself operates on
serialized bytes rather than message-passing connection types.

Server Side
~~~~~~~~~~~

MessagePassingControlServer
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Hosts the control-plane server over SCORE message passing. It accepts control-plane connections
and processes requests; lifecycle operations start listening, initiate graceful shutdown, and wait
for termination. The implementation composes transport callbacks, connection/session management,
request dispatch, the wire codec, and bounded worker execution.

SessionManager
^^^^^^^^^^^^^^

Authorizes transport connections and routes them to registered server sessions. Coordinates
admission, disconnect notification, and waiting for connection cleanup through ``SessionRegistry``.

SessionRegistry
^^^^^^^^^^^^^^^

Owns synchronized connection registration, admission reservations, and cleanup accounting. Maps
transport connections to sessions and releases admission capacity only when disconnect cleanup has
completed.

Session
^^^^^^^

Owns the request and disconnect-cleanup state for one server connection. Tracks admitted work items
by request ID and delivers responses on the associated server connection.

WorkItem
^^^^^^^^

Owns the server-side state and backing bytes for one received request. Tracks request identity and
deadline from admission through completion.

WorkItemDispatcher
^^^^^^^^^^^^^^^^^^

Routes decoded requests to per-connection sessions and worker execution. Dispatches operation
admission and coordinates response delivery; per-request state is owned by ``Session`` rather than
by the dispatcher.

FixedWorkerWorkItemExecutor
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Executes operation work and disconnect-cleanup jobs using a fixed set of workers. It creates one
request handler per worker, assigns request jobs only to idle workers, and queues cleanup jobs up to
the configured capacity.

Detailed Design
---------------

The interaction diagrams for connection admission, client/server request handling, timeout, and disconnect cleanup are documented in :doc:`../detailed_design/index`.
