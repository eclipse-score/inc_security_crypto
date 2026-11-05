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

.. _ipc_protocol_architecture:

IPC Protocol Component Architecture Documentation
================================================================

.. document:: IPC Protocol Architecture
   :id: doc__crypto_ipc_protocol_architecture
   :status: valid
   :version: 1
   :safety: ASIL_B
   :security: YES
   :realizes: wp__component_arch
   :tags: ipc, architecture


.. comp:: IPC Protocol
   :id: comp__ipc_protocol
   :version: 1
   :security: YES
   :safety: ASIL_B
   :status: valid
   :belongs_to: feat__mtef

Overview
--------

The control protocol defines wire format of the message exchanged between client and daemon.
``IControlCodec`` defines the typed-request to serialized-bytes boundary;
``FlatBufferCodec`` is the current implementation and uses ``control.fbs``.

Requirements Linked to Component Architecture
---------------------------------------------

.. needtable:: Overview of Component Requirements
   :style: table
   :columns: title;id
   :filter: search("comp__ipc_protocol", str(satisfied_by))
   :colwidths: 70,30
