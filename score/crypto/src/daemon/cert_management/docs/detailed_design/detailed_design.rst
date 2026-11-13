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

Certificate Management Detailed Design
======================================

.. document:: Certificate Management Detailed Design
   :id: doc__crypto_cert_management_detailed_design
   :version: 1
   :status: valid
   :safety: QM
   :security: YES
   :realizes: wp__sw_implementation
   :tags: cert_management, detailed_design

Implementation units
--------------------

``CertManagementService``
   Coordinates resource resolution, DataManager nodes, certificate registry
   access, slot operations, and trust-store update notifications.

``CertRegistry`` and ``CertEntry``
   Own live certificate entries. Each ``Load`` call produces a fresh
   ``CertEntry`` per client; entries are never shared across clients.
   ``CertEntry`` holds a ``CertObject::Sptr`` (the immutable parsed bytes) and
   an optional session-scoped CRL from ``ImportCrl``
   that is never written to disk. Because ``CertEntry`` is per-client, the
   session CRL is isolated — one client's ``ImportCrl`` cannot be observed by
   another client that loaded the same slot.

``CertSlotRegistry``
   Stores immutable slot configuration and application resource mappings.

``FileBackedSlotHandler`` and ``CrlHandler``
   Read and write certificate/CRL data using the deployment descriptor and
   shared atomic file I/O. The slot handler delegates parsing to ``ICertParser``.
   ``CrlHandler`` is composed into ``FileBackedSlotHandler`` and handles all
   ``[crl]`` section operations.

``TrustStoreManager`` and ``TrustStoreHandler``
   Resolve typed slot memberships, maintain reverse indices, load anchors
   lazily, persist mutable member state, and manage per-client references.
   Slot handlers are created on demand (lazy cache in ``GetOrCreateHandler``).
   Reference counting is per-client: one client releasing its verification
   context cannot evict another client's active anchor cache.
   ``GetMemberSlotHandles`` lists occupied member identities without resolving
   certificate content; ``GetMemberSnapshot`` resolves one member's detail on
   demand.

``AccessPolicyEnforcer``
   Applies UID-based read/write policy. Mutation is default-deny when no writer
   UID is explicitly configured.

``CertObjectResponseBuilder`` (``query/``)
   Free functions that encode ``CertObject``, ``ICertSlotHandler`` state, and
   trust-store member snapshots into the ``common::ResponseParameters`` IPC
   wire format. Exposed as the single intended encoding path so that an
   executor and any mediator typed-object handlers built on top of it share
   one wire-layout definition for certificate, slot, and trust-store objects
   instead of duplicating it. ``BuildTrustStoreMemberIdListResponse`` (member
   identities only) and ``BuildTrustStoreMemberObjectResponse`` (one member's
   detail) let a caller resolve trust-store membership one entry at a time
   rather than requiring a response sized by total, configuration-driven
   membership. Every function checks its built payload with
   ``common::EstimateResponseSize`` against
   ``common::kMaxResponsePayloadBytes`` and returns ``kResponseTooLarge``
   instead of an oversized result — the estimate is recomputed from the actual
   built output each call, so it does not need updating when a wire layout's
   field set changes.

Data and lifetime model
-----------------------

* ``CertSlotDataNode`` is a client-scoped reference to a configured slot.
* ``CertDataNode`` is a client-scoped reference to a registry-owned
  ``CertEntry``.
* ``TrustStoreDataNode`` is a client-scoped reference to a manager-owned trust
  store.
* ``CertObject`` is immutable and provider-neutral.
* ``CertSlotManager`` holds a weak-ptr cache of ``CertObject`` values keyed by
  slot index. The cache avoids repeated disk reads when multiple clients open
  the same slot in quick succession. Entries expire automatically when no
  ``CertEntry`` holds a strong reference; ``StoreCertificate`` and
  ``ClearSlot`` invalidate the entry explicitly so the next load reads fresh
  bytes.
* Trust-store anchor contents are loaded on demand by ``TrustStoreManager``
  through a separate anchor cache. Per-client references prevent one client
  from evicting another client's active anchor cache.

Storage contract
----------------

A certificate slot uses a KV deployment descriptor with a ``[certificate]``
section and optional ``[certificate_metadata]`` and ``[crl]`` sections. The
certificate and CRL payloads are stored in files referenced by the descriptor.
Descriptor and payload writes use the shared storage utilities; the previous
descriptor remains available until the replacement is complete.

Trust-store update contract
---------------------------

After a successful slot certificate update, the service obtains the reverse
membership list and calls ``TrustStoreManager::NotifySlotChanged``. The manager
invalidates the affected ``TrustStoreHandler`` cache. For a
``kConditionalExternal`` member, the manager also disables the member and
persists its existing accepted fingerprint. The member remains unavailable
until ``AcknowledgeMemberUpdate`` records the replacement fingerprint and
re-enables it. Other member kinds retain their enablement state. The next
``GetAnchors`` operation reloads the slot and reconstructs its ``CertObject``
through the injected parser.

Provider boundary and scope
----------------------------

The core component does not depend on OpenSSL or PKCS#11 concrete types.
OpenSSL supplies the ``ICertParser`` implementation used for parsing; provider
context handlers built on the same ``CertObject`` values are expected to
supply verification and CSR generation. PKCS#11 is expected to supply its own
``ICertSlotHandler`` for certificate-slot storage. Hardware-key CSR signing is
expected to use a cross-context service without exporting private key
material. OCSP remains a provider-boundary extension.

.. uml:: cert_management_dynamic.puml
