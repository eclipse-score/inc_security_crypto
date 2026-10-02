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

Static decomposition
--------------------

The implementation is divided by responsibility:

* ``interfaces/`` contains provider-neutral certificate values, slot and trust
  store contracts, configuration types, and public handles.
* ``core/`` contains ``CertManagementService``, ``CertRegistry``, and
  ``CertEntry``.
* ``nodes/`` contains DataManager nodes for certificate slots, loaded
  certificates, and trust stores.
* ``slot/`` contains slot registration, file-backed storage
  (``FileBackedSlotHandler``), deployment dispatch, and co-located CRL storage
  (``CrlHandler``).
* ``truststore/`` contains trust-store membership, anchor caching, persistence,
  and per-client references.
* ``policy/`` contains the shared slot/trust-store access-policy checks.
* ``query/`` contains ``CertObjectResponseBuilder`` — free functions that
  encode certificate, slot, and trust-store objects into the IPC response
  wire format. This component exposes it as the single intended encoding path
  so that an executor and any mediator typed-object handlers built on top of
  it share one wire-layout definition instead of duplicating it. Every builder
  checks its output against ``common::kMaxResponsePayloadBytes`` and returns
  ``kResponseTooLarge`` rather than an oversized payload. Trust-store member
  identities and per-member detail are resolved through separate functions
  (``BuildTrustStoreMemberIdListResponse``, ``BuildTrustStoreMemberObjectResponse``)
  so a caller can resolve one member at a time rather than needing a single
  response sized by total, configuration-driven membership.
* Public value definitions are owned by ``api/types``: ``common.hpp`` contains
  cross-domain resource/provider types, ``certificate.hpp`` contains certificate,
  CRL, OCSP, and verification types, and ``key.hpp`` contains key slot and
  permission types. ``api/common`` contains shared utilities and guards, not
  domain-specific type contracts.
* ``provider/`` supplies parsing and provider-specific context handlers. The
  selected certificate-management provider must expose ``ICertParser``;
  certificate management does not require a particular provider. The
  component defines two scoped context types for provider handlers built on
  top of it: ``CERT:MANAGEMENT`` for certificate-slot lifecycle operations
  and ``CERT:TRUST_STORE`` for trust-store membership curation. Handlers
  registered under either type are expected to share the same
  ``CertManagementService`` and certificate-management capability.

Public certificate loading
--------------------------

Certificate contexts support two equivalent resource paths. Passing a resolved
``kCertSlot`` directly lets the context load and release the certificate for its
own operation. ``ICertificateManagementContext::LoadCertificate(slot)`` performs
an explicit load and returns a guarded ephemeral ``kCertificate`` resource.
Applications can retain that guard and reuse the loaded certificate across
multiple contexts; destroying the guard releases the client-owned data node.

.. uml:: cert_management_static.puml

Runtime boundaries
------------------

Resource resolution is client-scoped through the Data Manager. A resolved
certificate slot or trust store is represented by a lightweight DataNode. A
certificate loaded from a slot becomes a ``CertDataNode`` backed by a
per-client ``CertEntry``. Each ``Load`` call produces an independent
``CertEntry`` so that per-client state — such as a session-scoped CRL
associated via session-scoped ``ImportCrl`` — cannot bleed across clients.
``CertSlotManager`` holds a weak-ptr cache of ``CertObject`` instances keyed
by slot: when the cache entry is live, multiple clients share the same parsed
bytes without redundant I/O; when it expires, the next load re-reads the slot.
Trust-store anchor content is loaded lazily and cached separately by
``TrustStoreManager``.

The current provider boundary is intentionally narrow:

* ``ICertParser`` converts DER/PEM bytes into ``CertObject``.
* ``ICertSlotHandler`` loads and stores slot data.
* Provider context handlers perform verification, CSR generation, conversion,
  and public-key operations.
* Cross-context services may provide signing and public-key operations for
  non-exportable keys while preserving provider ownership of private keys.

Architecture constraints
------------------------

* Certificate slots reference one storage backend selected at startup.
* Trust stores reference certificate slots, never raw certificate paths.
* CRLs are slot-scoped and are not independently resolved.
* CRL metadata is exposed through certificate views; CRL encoding format stays
  internal to storage and provider decoding.
* All trust-store mutation paths require trust-store write authorization.
* Trust-store mutations are dispatched through ``CERT:TRUST_STORE``; the
  ``CERT:MANAGEMENT`` context retains certificate-slot and slot-CRL lifecycle.
* Shared deployment writes are atomic; a partially written descriptor must not
  replace the previous valid descriptor.
* A built IPC response payload must stay within ``common::kMaxResponsePayloadBytes``;
  a query path whose output size depends on configuration or certificate
  content (DN length, trust-store member count) rejects with
  ``kResponseTooLarge`` rather than emitting an oversized payload.

Key interfaces
--------------

``ICertSlotHandler`` is implemented by certificate storage backends such as
``FileBackedSlotHandler``. The handler factory is injected into
``TrustStoreManager`` so the core component does not depend on a concrete
provider backend.

``ITrustStoreHandler`` exposes anchor retrieval and chain-building lookups.
``TrustStoreHandler`` receives an anchor-loader callback from
``TrustStoreManager`` and loads its anchor content on demand.

``TrustStoreManager::GetMemberSlotHandles`` lists a trust store's occupied
member identities without resolving certificate content, and
``GetMemberSnapshot`` resolves one member's detail on demand. Querying member
by member keeps each call's cost independent of total, configuration-driven
trust-store membership.

``ICertParser`` is the narrow provider boundary for converting DER or PEM
bytes into a provider-neutral ``CertObject``. Verification, CSR generation,
format conversion, and public-key extraction are provider context operations,
not responsibilities of the core storage component.

Runtime flows
-------------

During startup, the configuration adapter registers certificate slots and
trust stores. A client resolves an application resource into a DataManager
node. Loading a certificate goes through ``CertSlotManager``, which checks
its weak-ptr ``CertObjectCache`` first: on a hit the parsed bytes are returned
without disk I/O; on a miss the slot handler reads and parses the certificate
and the result is stored in the cache. A fresh ``CertEntry`` is created for
each caller and registered in ``CertRegistry``; no entry is shared across
clients.

Trust-store anchors are loaded lazily. ``TrustStoreManager`` resolves each
typed member slot and caches the resulting ``CertObject`` through a weak
reference. The trust-store handler holds strong references while active.

After a certificate update, ``CertManagementService`` finds every trust store
that references the slot and calls ``NotifySlotCertChanged``, which forwards
to ``TrustStoreManager::NotifySlotChanged``. The affected cache
entry is invalidated, and the next anchor request reloads and reparses the
certificate. Per-client references prevent one client's cleanup from evicting
another client's active cache.

Design decisions
----------------

The structural decisions that shape the component's storage model, including
their rationale, alternatives, and consequences, are documented in
:ref:`crypto_cert_management_design_decisions`.
