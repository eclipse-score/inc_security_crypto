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

IPC Requirements
================

.. document:: IPC Requirements
   :id: doc__ipc_requirements
   :version: 1
   :status: valid
   :safety: ASIL_B
   :security: YES
   :realizes: wp__requirements_comp[version==1]
   :tags: ipc

Scope
-----

The requirements below describe the requirements for an IPC mechanism to be used to allow
communication between the library and the daemon.

Functional requirements
-----------------------

.. comp_req:: Suitability for ASIL-B use
   :id: comp_req__ipc__suitability_for_asil_b_use
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC shall be designed and documented to support deterministic and bounded execution and
   resource behavior, controlled heap/allocation use on ASIL-relevant paths, suitable isolation
   for the deployment, and appropriate quality artifacts such as requirements/design traceability,
   analysis, verification, and compliance or qualification evidence.

.. comp_req:: Bounded timeout on every call
   :id: comp_req__ipc__bounded_timeout_on_every_call
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC shall be allow proven WCET for all call. A stalled QM server shall never indefinitely
   block an ASIL-B client thread.

.. comp_req:: Resilience to connection loss
   :id: comp_req__ipc__resilience_to_connection_loss
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC shall be resilient to crash or connection loss. If one of the participating processes
   dies or the connection is lost in any other means the users of the IPC shall be notified
   appropriately. The client shall not block indefinitely or silently operate on a dead connection.

.. comp_req:: Authentic peer identification
   :id: comp_req__ipc__authentic_peer_identification
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The server shall be able to identify the calling identity via an OS-enforced mechanism,
   not a client-supplied value.

.. comp_req:: Minimal or zero configuration
   :id: comp_req__ipc__minimal_or_zero_configuration
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC usage shall require minimal configuration and be fully configurable programmatically.

.. comp_req:: Flexible server-side threading model
   :id: comp_req__ipc__flexible_server_thread_model
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC shall not impose a threading model on the server. The server must be free to choose
   single-thread, fixed pool, or per-request threads.

.. comp_req:: Concurrent calls from one process
   :id: comp_req__ipc__concurrent_client_calls
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC shall support multiple concurrent calls from within a single client process.

.. comp_req:: Multiple concurrent client processes
   :id: comp_req__ipc__concurrent_client_processes
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC shall support multiple concurrent calls from multiple client processes.

.. comp_req:: One-to-one communication
   :id: comp_req__ipc__one_to_one_communication
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC shall support a one-to-one communication model and shall not rely on broadcast or
   fan-out mechanisms.

.. comp_req:: Low latency
   :id: comp_req__ipc__low_latency
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC shall provide low-latency communication between client and server processes. Data
   throughput is not a priority, since crypto provides a separate data plane for transfer of
   bigger data elements.

.. comp_req:: Inter-VM communication
   :id: comp_req__ipc__inter_vm_communication
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC shall support communication between client and server processes running in different
   virtual machines (VMs).

.. comp_req:: C++/Rust interoperability
   :id: comp_req__ipc__cpp_rust_interoperability
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC shall support interoperability between C++ and Rust client and server processes in
   order to enable future rust components.

.. comp_req:: Payload agnostic communication
   :id: comp_req__ipc__payload_agnostic_communication
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__ipc_message_passing_adapter

   The IPC shall support payload-agnostic communication, allowing the transfer of different types
   of payload data without the need for changes to the IPC mechanism itself.
