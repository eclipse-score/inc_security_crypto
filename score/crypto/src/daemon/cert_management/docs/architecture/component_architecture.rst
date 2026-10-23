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
  wire format. It is the intended single encoding path, so that the
  certificate-management executor and the typed-object query
  handlers share one wire-layout definition. Every builder
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

Public certificate loading
--------------------------

Certificate contexts support two equivalent resource paths. Passing a resolved
``kCertSlot`` directly lets the context load and release the certificate for its
own operation. ``ICertificateManagementContext::LoadCertificate(slot)`` performs
an explicit load and returns a guarded ephemeral ``kCertificate`` resource.
Applications can retain that guard and reuse the loaded certificate across
multiple contexts; destroying the guard releases the client-owned data node.

.. uml:: cert_management_static.puml

Stored objects and ownership
----------------------------

The diagram below shows the objects the component keeps, who owns each, and how
long it lives.

.. uml:: cert_management_data_model.puml

Ownership rules:

* **Configuration** (slot, trust-store, and member definitions and access
  policies) is fixed after startup. Registries hand out stable references to it.
* **CertObject and CrlData** are immutable values shared by
  ``shared_ptr``. A change to stored content produces a new value; a holder keeps
  the value it was given. A slot's CRL presence and metadata can be read
  without loading the CRL bytes.
* **CertSlotManager** is the single cache owner for slot content. Its
  certificate cache holds weak references and its CRL cache holds, per slot, the
  CRL presence and metadata plus a weak reference to the ``CrlData``. Each slot keeps a
  generation for its certificate and one for its CRL; a load that overlaps an
  invalidation of its own part is not cached.
* **TrustStoreHandler** is one object per configured store, shared by all
  clients. It holds the store's anchors and CRLs strongly; these are the same
  snapshots the slot manager hands out, filtered by member enablement and, for
  conditional members, by the accepted fingerprint. Member state is persisted in
  the store's descriptor when the store has a deployment path; without one it is
  held in memory only.
* **Per-client objects** are ``CertSlotDataNode``, ``TrustStoreDataNode`` (both
  hold only a handle), and ``CertDataNode`` with its ``CertEntry``. A
  ``CertEntry`` is created for each load, wraps the shared ``CertObject``, and
  carries the client's session CRL. Releasing the node releases the entry.
* **Persisted state** is the slot descriptor (certificate and CRL locations,
  certificate and CRL metadata), the certificate and CRL files, and the
  trust-store descriptor (member enabled flag and accepted fingerprint). A session
  CRL is never persisted.

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
``CertSlotManager`` separately caches each slot's CRL: an immutable ``CrlData``
snapshot (bytes, encoding, metadata) shared by every reader, together with the
slot's CRL presence and metadata. The cache is invalidated on any write that
changes CRL state, so presence and metadata queries do not read the CRL file.
Trust-store anchor content is cached by the trust-store handlers only while a client holds the
store, and the handlers share the slot-level certificate and CRL values rather than copying them.

The provider boundary consists of:

* The selected certificate-management provider must expose ``ICertParser``
  to convert DER/PEM bytes into a provider-neutral ``CertObject``.
* ``ICertSlotHandler`` loads and stores slot data.
* Provider context handlers perform verification, CSR generation, conversion,
  and public-key operations.
* Cross-context services are expected to provide signing and public-key operations
  for non-exportable keys, with provider ownership of private keys preserved.

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
``FileBackedSlotHandler``. A handler factory (``SlotHandlerFactory`` for
provider-backed slots) is injected into ``CertSlotManager``, which owns handler
creation and per-slot caching, so the core component does not depend on a
concrete provider backend. ``TrustStoreManager`` resolves slot handlers through
``CertSlotManager`` rather than holding a factory of its own.

``ITrustStoreHandler`` exposes anchor retrieval, CRL retrieval, and
chain-building lookups. ``TrustStoreHandler`` implements it and owns one trust
store's member state, anchor and CRL cache, member mutations, and persisted
state; its cache is built when a client binds the store and dropped when the
last client releases it. ``TrustStoreManager`` is the
registry in front of the handlers: it owns the name index, the slot-to-store
reverse index, and the per-client reference counts, and it checks the
trust-store write policy before forwarding an operation to a handler.

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
its weak-ptr certificate cache first: on a hit the parsed bytes are returned
without disk I/O; on a miss the slot handler reads and parses the certificate
and the result is stored in the cache. A fresh ``CertEntry`` is created for
each caller and registered in ``CertRegistry``; no entry is shared across
clients. CRL presence and metadata queries (``HasCrl``, ``GetCrlMetadata``,
``GetCrlNextUpdate``) go through the same kind of cache, keyed by slot: a miss
asks the slot handler for presence and metadata, which it answers from the
descriptor without reading the CRL file. Each query takes the requesting client's
id and checks it against the slot's access policy. Loading the CRL itself goes
through ``ICertSlotHandler::LoadCrlData``, which returns bytes, encoding, and
metadata as one value; ``CertSlotManager`` shares that value as an immutable
snapshot among all readers.

A trust store's cache has an explicit lifecycle. When a client binds the store
(``TrustStoreManager::AddRef``), the handler resolves each enabled typed member
slot and loads its ``CertObject`` and CRL through ``CertSlotManager``'s weak-ptr
cache, which every reader of the slot shares, and holds strong references to them
while any client holds the store. If an existing member certificate or CRL cannot
be read, the bind fails with that error and keeps no reference; an empty member
slot and a missing CRL are not failures. When the last client releases the store
(``ReleaseRef``, or ``CleanupClient``), the cache is cleared. A read on a store
that no client holds resolves the members the same way and returns the result
without caching it. Member mutations and slot notifications update the cache only
while it is warm; otherwise they change persisted member state only. A write made
through a slot's backend handler by the trust store (exclusive members) evicts
the slot's cached state in ``CertSlotManager``, as a write through
``CertSlotManager`` does.

Certificate-slot and CRL mutations are reachable only through
``CertManagementService::StoreCertificate``, ``ClearSlot``, ``StoreCrl``, and
``ClearCrl``;``CertSlotManager`` performs the underlying write but has no
trust-store awareness. After each write that reaches the slot's backend, successful
or failed, the service finds every trust store that references the slot and calls
``TrustStoreManager::NotifySlotChanged`` (certificate updates) or
``NotifySlotCrlChanged`` (CRL updates) for each. A failed backend write can still
have changed the stored content, so the notification is not gated on success.
Writes refused before the backend (access check, unknown slot, no handler) do not
notify; the slot manager reports whether the backend was invoked. In a
warm cache, a certificate update reloads the changed member's anchor and CRL
entries and replaces them, leaving other members untouched; a CRL-only update
makes the handler take the slot's current CRL snapshot from ``CertSlotManager``
without reloading the certificate. If refreshing a member fails, the cache is
dropped so that the next read resolves every member again and reports the
failure.
Per-client references prevent one client's cleanup from evicting another
client's active cache.

Design decisions
----------------

The structural decisions that shape the component's storage model, including
their rationale, alternatives, and consequences, are documented in
:ref:`crypto_cert_management_design_decisions`.
