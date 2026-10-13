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

.. _crypto_message_passing_adapter_detailed_design:

Message-Passing Adapter Detailed Design
=======================================

.. document:: Message-Passing Adapter Detailed Design
   :id: doc__crypto_msg_pass_detail
   :version: 1
   :status: draft
   :safety: ASIL_B
   :security: YES
   :realizes: wp__feature_arch

These sequence diagrams describe connection admission, client and server request handling, timeout behavior, and disconnect cleanup.

Connection Establishment and Admission
---------------------------------------

.. uml:: message_passing_adapter_connection_flow.puml
   :align: center
   :caption: Connection establishment, authorization, and admission
   :alt: Sequence diagram showing IPC peer identity retrieval, authorization, admission checks, and one unified denied path.

Normal Request and Response
---------------------------

Client Side
~~~~~~~~~~~

.. uml:: message_passing_adapter_request_flow.puml
   :align: center
   :caption: Client-side request send and response correlation
   :alt: Sequence diagram showing client readiness, pending-call registration, request serialization and send, response callback, and request-ID correlation.

Server Side
~~~~~~~~~~~

.. uml:: message_passing_adapter_server_request_flow.puml
   :align: center
   :caption: Server-side request dispatch and response delivery
   :alt: Sequence diagram showing the OnRequest callback, session lookup and admission, worker execution, handler call, response serialization, and Notify.

Client-Side Timeout
-------------------

.. uml:: message_passing_adapter_timeout_flow.puml
   :align: center
   :caption: Client-side request timeout
   :alt: Sequence diagram showing pending-call registration, request send, condition_variable wait_until timeout, and timeout return to the caller.

Disconnect and Cleanup
----------------------

.. uml:: message_passing_adapter_disconnect_flow.puml
   :align: center
   :caption: Disconnect and session cleanup flow
   :alt: Sequence diagram showing the OnDisconnect callback, session work draining, disconnect cleanup, and capacity release.