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

.. _crypto_ipc_docs:

Crypto IPC Documentation
========================

The IPC layer defines the interface at the library-to-daemon boundary and thus allows
communication between processes implementing the client library and the daemon process.

On a high level, the IPC layer is divided into a control protocol element,
which defines the actual exchanged messages and their semantics,
and a transport element does implement the transport of the messages
between the client library and the daemon process.

.. toctree::
   :maxdepth: 1

   requirements/index
   architecture/index
   ../protocol/docs/index
   ../message_passing_adapter/docs/index
