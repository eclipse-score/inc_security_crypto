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
.. _data_plane_architecture:

Data Plane Architecture
=======================

The data plane implements zero-copy shared memory (SHM) transfer between
the client library and the daemon. The client maps SHM regions directly
into its address space; the daemon resolves these regions by ``DataNodeId``
during operation handling.

----


Daemon Side
-----------

.. uml::  data_plane_daemon_overview.puml
   :align: center
   :caption: Daemon-Side Data Plane — Class Diagram
   :alt: UML class diagram of the daemon-side data plane (request handler chain, mediator, SHM registry/factory, data node hierarchy).

----

API Side
-------------

.. uml::  data_plane_client_overview.puml
   :align: center
   :caption: Data Plane — Client and API Integration
   :alt: UML diagram of the client-side data plane and API integration.
