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

.. _api_class_architecture:

API Architecture
================

Class Diagram
-------------

The Score Crypto API architecture is illustrated by several focused UML diagrams:

..
    TODO: These might be later generated from the real_arc_int and operations.

.. uml:: api_overview.puml
    :align: center
    :caption: Score Crypto API — Stack, Factory, and Context Overview
    :alt: UML diagram showing ICryptoStack, ICryptoContext, and context factory relationships.

.. uml:: api_contexts.puml
    :align: center
    :caption: Score Crypto API — Operation Context Hierarchy
    :alt: UML diagram showing operation context inheritance and relationships (ICipherContext, IAeadContext, etc.).

.. uml:: api_certificate_contexts.puml
    :align: center
    :caption: Score Crypto API — Certificate Operation Contexts
    :alt: UML diagram showing certificate, verification, and CSR context relationships.

.. uml:: api_typed_objects.puml
    :align: center
    :caption: Score Crypto API — Typed Object Hierarchy
    :alt: UML diagram showing typed object inheritance (IKeyObject, ICertificateObject, etc.).

.. uml:: api_resource_management.puml
    :align: center
    :caption: Score Crypto API — Resource Management
    :alt: UML diagram showing CryptoResourceGuard, CryptoResourceId, and daemon ref-counting lifecycle.

.. uml:: configuration_objects.puml
    :align: center
    :caption: Score Crypto API — Configuration Object Hierarchy
    :alt: UML diagram showing configuration struct relationships (CipherContextConfig, KeyGenConfig, etc.).

.. uml:: key_configuration_params.puml
    :align: center
    :caption: Score Crypto API — Key Configuration Parameters
    :alt: UML diagram showing key configuration parameter relationships (DeriveKeyParams, AgreeKeyParams, KdfParameters).
