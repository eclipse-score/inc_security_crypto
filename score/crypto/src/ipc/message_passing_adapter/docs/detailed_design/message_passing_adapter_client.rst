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

.. _crypto_message_passing_adapter_dd_client:

Message-Passing Adapter Client-Side Design
==========================================

.. document:: Message-Passing Adapter Client-Side Design
   :id: doc__crypto_msg_pass_dd_client
   :version: 1
   :status: draft
   :safety: ASIL_B
   :security: YES
   :realizes: wp__feature_arch

This page describes the client connection lifecycle and the per-request pending-call lifecycle, including how transport callbacks, responses, timeouts, and shutdown interact.

Client-Side State Machines
--------------------------

.. uml:: message_passing_adapter_client_state_machines.puml
   :align: center
   :caption: Client-side session and pending-call state machines and their interactions
   :alt: State diagram showing request creation and send, NotifyCallback response correlation, pending-call completion or timeout, and transport StateCallback transitions.
