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

.. _ipc_client_id_assignment:

Client ID Assignment and Scope
==============================

.. glossary::

   ClientId
      A server-assigned 64-bit identity for one IPC connection. It combines the
      authenticated peer UID with an opaque daemon-generated connection
      generation.

The IPC server assigns a ``ClientId`` when it registers an authorized
connection. The session and all requests received on that connection use the
same ID. It is a daemon-side connection scope, not a client-chosen identity.

Why the ID combines UID and generation
--------------------------------------

The UID is obtained from the transport's authenticated peer credentials and is
used by UID-based access policies. A UID alone cannot isolate connection-owned
state: several processes can run under the same UID. The opaque generation
distinguishes those connections while preserving the UID needed for authorization.

Encoding and allocation
-----------------------

The 64-bit value is encoded as follows:

.. code-block:: text

   ClientId = (uint64_t(uid) << 32) | generation

The upper 32 bits contain the UID. The lower 32 bits contain an opaque
connection generation. The generation is maintained by the server's
``SessionRegistry`` and starts at 1. It is advanced only after the connection,
session, client state, and UID capacity reservation have all been registered
successfully. Zero is skipped, and candidates already reserved by the registry
are skipped.

Connection and cleanup cases
----------------------------

* Requests on the same connection share one ``ClientId``; a new ID is not
  generated per request, context, or stack using that connection.
* Reconnecting after a disconnect generates another ID,
  even when the process and UID have not changed.
* Processes with the same UID have the same UID component but different
  generations, so their full ``ClientId`` values differ while both connections
  are registered.
* A successfully completed disconnect cleanup releases the ID reservation.
  The generation has already advanced, so that ID is not normally reused.
  Failed cleanup quarantines the ID and retains its capacity reservation; it
  cannot be reused while quarantined.
* The generation is 32 bits and wraps, skipping zero. The registry skips IDs
  that are still reserved, but a fully cleaned-up ID can recur after wraparound.
  The sequence restarts at 1 when the daemon restarts, so ``ClientId`` values
  are not persistent identifiers across daemon restarts.
