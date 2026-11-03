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

Certificate Management Architecture
===================================

.. document:: Certificate Management Architecture
   :id: doc__crypto_cert_management_architecture
   :version: 1
   :status: valid
   :safety: QM
   :security: YES
   :realizes: wp__component_arch
   :tags: cert_management, architecture

.. comp:: Certificate Management
    :id: comp__crypto_cert_management
    :version: 1
    :security: YES
    :safety: QM
    :status: valid
    :belongs_to: feat__security_crypto

Purpose
-------

``cert_management`` is a daemon subcomponent parallel to
``key_management``. It owns certificate and trust-store resource lifecycle;
it does not own private keys or provider-specific cryptographic objects.

Overview
--------

The component serves three families of callers, each reaching it through the
service or the managers it coordinates:

* **Certificate-slot lifecycle** — parse, load, save, export, release, and
  slot-scoped CRL operations, through ``CertManagementService``.
* **Trust-store membership** — add, remove, enable, disable, acknowledge, and
  member CRL operations, through ``TrustStoreManager`` after the trust-store
  write policy is checked.
* **Verification** — binding a leaf, chain, and trust store, and reading the
  store's anchors and CRLs for path validation, which a provider performs.

Typed-object responses (certificate, slot, trust-store member) are encoded by
``CertObjectResponseBuilder``. Parsing and path
validation stay behind the provider boundary; the component supplies the
provider-neutral certificate and trust material they consume. How requests reach
these entry points is owned by the daemon control plane and is outside this
component.

.. uml:: cert_management_overview.puml

Static decomposition
--------------------

The composition diagram shows the package structure and dependencies. The query
layer centralizes IPC response encoding, enforces
``common::kMaxResponsePayloadBytes``, and builds trust-store member identities
and details separately so callers can request member details one at a time.

.. uml:: cert_management_composition.puml

Public certificate loading
--------------------------

Certificate contexts support two equivalent resource paths. Passing a resolved
``kCertSlot`` directly lets the context load and release the certificate for its
own operation. ``ICertificateManagementContext::LoadCertificate(slot)`` performs
an explicit load and returns a guarded ephemeral ``kCertificate`` resource.
Applications can retain that guard and reuse the loaded certificate across
multiple contexts; destroying the guard releases the client-owned data node.

Stored objects and ownership
----------------------------

The data-model diagram describes stored objects, ownership, and lifetime.
Runtime behavior and edge cases are described below.

.. uml:: cert_management_data_model.puml

Provider boundary
-----------------

The provider boundary consists of:

* The selected certificate-management provider must expose ``ICertParser``
  to convert DER/PEM bytes into a provider-neutral ``CertObject``.
* ``ICertSlotHandler`` loads and stores slot data.
* Provider context handlers perform verification, CSR generation, conversion,
  and public-key operations.
* Cross-context services are expected to provide signing and public-key operations
  for non-exportable keys, with provider ownership of private keys preserved.
* Verification handlers obtain trust anchors, CRLs, and chain-building lookups
  through ``ITrustStoreHandler``.


Design decisions
----------------

The structural decisions that shape the component's storage model, including
their rationale, alternatives, and consequences, are documented in
:ref:`crypto_cert_management_design_decisions`.
