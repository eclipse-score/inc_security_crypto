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

.. _ipc_message_passing_adapter:

IPC Message Passing Adapter
###########################

.. document:: IPC Message Passing Adapter
   :id: doc__crypto_ipc_message_passing_adapter
   :version: 1
   :status: draft
   :safety: ASIL_B
   :security: YES
   :realizes: wp__cmpt_request
   :tags: ipc

Overview
========

The IPC Message Passing Adapter provides the control-plane communication
boundary between Crypto client processes and the score-crypto daemon. It
allows clients to request cryptographic operations without coupling the
application-facing IPC interface to operating-system transport details.

The selected target uses the ``score::message_passing`` API (LoLa Message
Passing) with FlatBuffers payloads. The framework supplies the operating-
system-specific transport backend. Bulk data transfer remains outside this
control-plane component.

.. toctree::
   :maxdepth: 1

   architecture/index
   requirements/index
