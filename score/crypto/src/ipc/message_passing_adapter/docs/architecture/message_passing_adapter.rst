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

.. literalinclude:: ../../client/message_passing_control_client.h
  :language: rst
  :start-after: @brief
  :end-before: @endrst

ClientSession
^^^^^^^^^^^^^

.. literalinclude:: ../../client/client_session/client_session.h
  :language: rst
  :start-after: @brief
  :end-before: @endrst

PendingCallRegistry
^^^^^^^^^^^^^^^^^^^

.. literalinclude:: ../../client/client_session/pending_call_registry.h
  :language: rst
  :start-after: @brief
  :end-before: @endrst

PendingCall
^^^^^^^^^^^

.. literalinclude:: ../../client/client_session/pending_call.h
  :language: rst
  :start-after: @brief
  :end-before: @endrst

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

.. literalinclude:: ../../server/message_passing_control_server.h
  :language: rst
  :start-after: @brief
  :end-before: @endrst

SessionManager
^^^^^^^^^^^^^^

.. literalinclude:: ../../server/session/session_manager.h
  :language: rst
  :start-after: @brief
  :end-before: @endrst

SessionRegistry
^^^^^^^^^^^^^^^

.. literalinclude:: ../../server/session/session_registry.h
  :language: rst
  :start-after: @brief
  :end-before: @endrst

Session
^^^^^^^

.. literalinclude:: ../../server/session/session.h
  :language: rst
  :start-after: @brief
  :end-before: @endrst

WorkItem
^^^^^^^^

.. literalinclude:: ../../server/session/work_item.h
  :language: rst
  :start-after: @brief
  :end-before: @endrst

WorkItemDispatcher
^^^^^^^^^^^^^^^^^^

.. literalinclude:: ../../server/session/work_item_dispatcher.h
  :language: rst
  :start-after: @brief
  :end-before: @endrst

FixedWorkerWorkItemExecutor
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: ../../server/work_item_execution/fixed_worker_work_item_executor.h
  :language: rst
  :start-after: @brief
  :end-before: @endrst

Detailed Design
---------------

The interaction diagrams for connection admission, client/server request handling, timeout, and disconnect cleanup are documented in :doc:`../detailed_design/index`.
