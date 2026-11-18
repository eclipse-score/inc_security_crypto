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

.. _crypto_message_passing_adapter_dd_server:

Message-Passing Adapter Server-Side Design
==========================================

.. document:: Message-Passing Adapter Server-Side Design
   :id: doc__crypto_msg_pass_dd_server
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__feature_arch

This page describes server-side object ownership, worker execution, and state transitions for connections, requests, cleanup, and shutdown.

Server-Side Ownership and Work Execution
----------------------------------------

.. uml:: message_passing_adapter_server_ownership.puml
   :align: center
   :caption: Server-side ownership and work execution
   :alt: Component diagram showing server composition, session ownership, worker threads, and bounded request and cleanup scheduling.

Server-Side State Machines
--------------------------

.. uml:: message_passing_adapter_server_state_machines.puml
   :align: center
   :caption: Server-side state machines and their interactions
   :alt: State diagram showing server, executor, registry, session, and work-item lifecycles across connection, request, disconnect, start, and stop flows.
