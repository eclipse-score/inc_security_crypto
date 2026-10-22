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

``TrustStoreManager``
   The registry in front of the trust stores. It owns the name index, the
   application-resource mapping, the slot-to-store reverse index, and the
   per-client reference counts, and it enforces the trust-store write policy
   before forwarding an operation to the store's handler. Reference counting is
   per-client: one client releasing its verification context cannot evict
   another client's active anchor cache.

``TrustStoreHandler``
   One instance per trust store. It owns the store's configuration, the runtime
   state of each member, the anchor and CRL cache, the member mutations, and the
   persisted member state. The cache is built when a client binds the store and
   dropped when the last client releases it; a read on an unheld store resolves
   the members without caching. Member
   certificates and CRLs are read and written through the slot backends obtained
   from ``CertSlotManager``, and the slot's cached state is evicted after every
   backend write. ``GetMemberSlotHandles`` lists occupied member identities
   without resolving certificate content; ``GetMemberSnapshot`` resolves one
   member's detail on demand. Callers that verify certificates see only the read
   side, ``ITrustStoreHandler``.

   The handler is valid only if every member names a configured slot, no slot is
   listed twice, and the persisted member state, when a state file exists, can be
   read. An absent state file is the first run. An invalid handler reports
   ``kTrustStoreInvalid`` when it is resolved, bound, read, or mutated, instead of
   running with fewer members or default state. A member state is changed in
   memory only after it has been persisted when the change increases trust
   (adding or enabling a member, accepting new conditional content); a change
   that reduces trust takes effect immediately and a failed persist is reported.

``AccessPolicyEnforcer``
   Applies UID-based read/write policy. Mutation is default-deny when no writer
   UID is explicitly configured.

``CertObjectResponseBuilder`` (``query/``)
   Free functions that encode ``CertObject``, ``ICertSlotHandler`` state, and
   trust-store member snapshots into the ``common::ResponseParameters`` IPC
   wire format. Provides the single encoding path for certificate, slot, and
   trust-store objects, so every caller that builds these responses shares one
   wire-layout definition. ``BuildTrustStoreMemberIdListResponse`` (member
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
* ``CertSlotManager`` also holds a CRL cache keyed by slot index. A slot's CRL
  is a ``CrlData`` value (bytes, encoding, metadata) read from the backend as
  one unit and shared as an immutable ``CrlData::Sptrc``; a CRL update yields a new
  value and never modifies one already handed out. Each cache entry holds the
  slot's CRL state — whether a CRL is stored and its optional metadata — and a
  weak reference to the ``CrlData``. ``HasCrl``, ``GetCrlMetadata``, and
  ``GetCrlNextUpdate`` are answered from the state without reading the CRL bytes;
  ``LoadCrlData`` serves the shared ``CrlData`` while any reader holds it and
  re-reads it otherwise. On a state miss the slot handler answers ``HasCrl`` and
  ``GetCrlMetadata`` from the descriptor, and on a data miss
  ``ICertSlotHandler::LoadCrlData`` reads the descriptor once plus the CRL file.
  ``FileBackedSlotHandler`` provides these through its composed ``CrlHandler``.
  Any slot handler that keeps CRLs in the descriptor's ``[crl]`` section composes the same ``CrlHandler``. ``StoreCertificate``, ``ClearSlot``,
  ``StoreCrl``, and ``ClearCrl`` invalidate the entry explicitly. The CRL
  encoding is part of ``CrlData`` and is not queried separately. Every slot read
  takes the requesting client's id and checks it against the slot's access policy.
* Each part of a slot's cache (certificate and CRL) has its own generation, which its
  invalidation advances. A load records the generation of its part before the backend
  read and caches the result only if that generation is unchanged afterwards. A read
  that overlaps an invalidation of its own part is returned to its caller but not
  cached, so the cache never holds content older than the latest completed write. A
  CRL import therefore leaves a cached certificate in place.
* Each ``TrustStoreHandler`` caches its members' anchors and CRLs only while a client holds
  the store: ``TrustStoreManager::AddRef`` builds the cache from the shared slot-level
  objects, and the last release clears it. ``TrustStoreManager`` keeps per-client
  references, which prevent one client from evicting another client's active cache.

Storage contract
----------------

A certificate slot uses a KV deployment descriptor with a ``[certificate]``
section and optional ``[certificate_metadata]`` and ``[crl]`` sections. The
certificate and CRL payloads are stored in files referenced by the descriptor.
Descriptor and payload writes use the shared storage utilities; the previous
descriptor remains available until the replacement is complete.

Trust-store update contract
---------------------------

Certificate-slot and CRL mutations are only reachable through
``CertManagementService::StoreCertificate``, ``ClearSlot``, ``StoreCrl``, and
``ClearCrl``. Each performs the underlying ``CertSlotManager`` write and then
notifies every trust store that references the slot when the stored content
may have changed, whether the write succeeded or failed; a caller performing a slot write through the service never
issues a separate notification step, and ``CertSlotManager`` itself has no trust-store
awareness — it depends only on slot configuration and backend handlers.

For a certificate update, the service obtains the reverse membership list and
calls ``TrustStoreManager::NotifySlotChanged`` for each referencing store. The
manager forwards the notification to the store's handler. While the cache is warm the
handler re-reads only the changed member: it loads the member's certificate through the
slot manager, replaces that member's entry in its anchor cache, and refreshes that
member's CRL entry. While the cache is cold there is nothing to refresh. Other
members are not re-read and keep their cached anchors and CRL
entries. For a ``kConditionalExternal`` member, the handler compares the slot's content with
the accepted fingerprint and, on a mismatch, disables the member and persists the state with
its existing accepted fingerprint, whether or not the cache is warm. The member remains
unavailable until ``AcknowledgeMemberUpdate`` records the replacement fingerprint and
re-enables it. Other member kinds retain
their enablement state.

The certificate and CRL entries of a member are refreshed in separate steps. A concurrent reader may therefore briefly observe the new certificate
with the previous CRL for that member. The anchor set itself is never partially
rebuilt: each member entry is replaced atomically under the handler's mutex.

For a CRL update, the service calls ``TrustStoreManager::NotifySlotCrlChanged``
for each referencing store, which calls ``TrustStoreHandler::OnSlotCrlChanged``.
The handler obtains the slot's current CRL snapshot from ``CertSlotManager`` and
replaces the member's cached CRL with it, without reloading the certificate. The
cached CRL is the same shared ``CrlData::Sptrc`` the slot manager holds, so a CRL is
held once however many stores reference its slot. A member that is not enabled
keeps no CRL. This does not affect conditional-member enablement — a CRL
refresh changes revocation data, not the anchor's identity.

Provider boundary and scope
----------------------------

The core component does not depend on OpenSSL or PKCS#11 concrete types, and no
provider is hardcoded as the parsing authority. ``SlotHandlerFactory`` resolves one
canonical ``ICertParser`` for the component: the provider named by
``CertificateConfig::GetParserProviderName`` when one is configured, otherwise the
provider selected for the certificate-management capability. Resolution happens on
first use unless a caller invokes ``Initialize()`` to resolve eagerly; a successful
parser is cached and shared, and a failed resolution is not cached so a later call
retries. Each provider supplies its own verification and CSR generation handlers, built
on the same provider-neutral ``CertObject`` values. PKCS#11 is expected to supply its
own ``ICertSlotHandler`` for certificate-slot storage. Hardware-key CSR signing is
expected to use a cross-context service without exporting private key material. OCSP
remains a provider-boundary extension.

.. uml:: cert_management_dynamic.puml

Use cases
---------

The sequences below follow one operation each through the units above. They
share the participants and cache behaviour described in the preceding sections;
``cert_management_dynamic.puml`` shows startup registration and cache states
across several operations in one diagram. The executor and mediator dispatch
steps in the sequences are abbreviated.

Loading a certificate from a slot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Resolving a slot resource yields a client-scoped slot node. Loading it returns the
shared ``CertObject`` from the slot cache or reads and parses it, and the service
wraps it in a new per-client ``CertEntry`` registered under a ``CertDataNode``.

.. uml:: uc_certificate_slot_load.puml

Writing a certificate slot
~~~~~~~~~~~~~~~~~~~~~~~~~~

A slot write is a service operation: the slot manager applies its write checks and
writes through the handler, invalidating its caches, and the service then refreshes
every trust store that references the slot. A conditional-external member is
disabled instead of reloaded until its new content is acknowledged.

.. uml:: uc_certificate_slot_update.puml

Importing a CRL
~~~~~~~~~~~~~~~

A session-scoped import is
attached to the client's ``CertEntry`` and goes no further. A persistent import
writes the slot's CRL and notifies the referencing trust stores, which take the
slot's current CRL snapshot.

Import stores the supplied CRL as given and does not validate it against its issuer certificate.

.. uml:: uc_crl_import.puml

Adding a certificate to a trust store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A trust store writes only the exclusive-mutable slots it owns. Membership is
deduplicated by fingerprint across all member kinds before an empty exclusive slot
is used.

.. uml:: uc_trust_store_member_add.puml

Verifying a certificate
~~~~~~~~~~~~~~~~~~~~~~~

Binding a trust store increments a per-client reference count. Verification reads
the store's anchors and CRL snapshots, loading them from the enabled member slots when
the store's cache is cold, and passes them to the provider verifier.

.. uml:: uc_certificate_verification.puml
