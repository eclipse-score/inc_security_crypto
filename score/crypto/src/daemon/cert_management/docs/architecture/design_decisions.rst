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

.. _crypto_cert_management_design_decisions:

Design Decisions
================

Trust Stores Reference Certificate Slots, Not Raw Paths
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Trust Stores Reference Certificate Slots, Not Raw Paths
   :id: dec_rec__crypto_cert_mgmt__ts_ref_slots
   :version: 1
   :status: accepted
   :context: doc__crypto_cert_management_architecture
   :decision: Trust-store membership is expressed as typed references to named certificate slots, never as raw filesystem paths or inline certificate bytes. The slot is the indirection point for loading, caching, and change notification.

   .. :affects: comp__crypto_cert_management

Trust-store membership is expressed as typed references to named certificate
slots (``kSharedStatic``, ``kExclusiveMutable``, ``kConditionalExternal``).
Neither raw filesystem paths nor inline certificate bytes appear in a trust-store
configuration or in the in-memory member list.

Context
-------

A trust store must react correctly when the certificate it anchors changes.
The component also requires lazy loading (cert bytes are not read at startup),
shared cert content across stores (same physical cert referenced by multiple
stores), and cache invalidation that is scoped to the changed slot rather than
requiring a full store reload.

Three representations were considered for trust-store membership:

1. **Raw filesystem paths** — ``[trust_store]/member_paths = ["/certs/root.pem"]``.
   Simple to configure, but paths must be validated at startup, change
   notification requires watching the filesystem (inotify or polling), there is
   no shared-ownership model for the cert content, and CRL co-location is lost.

2. **Inline certificate bytes in the trust-store descriptor** — the trust-store
   deployment file contains base64 PEM content. No slot indirection needed.
   Removing, replacing, or CRL-associating an anchor requires re-writing the
   descriptor with new content. There is no sharing across trust stores and no
   single change-notification point.

3. **Named certificate slot references** — the trust store lists slot names; the
   ``CertSlotRegistry`` resolves each name to a ``CertSlotHandle`` at startup.
   The ``TrustStoreManager`` maintains a reverse index (slot → stores) so that a
   single ``NotifySlotChanged(slot)`` call after ``StoreCertificate`` invalidates
   every affected trust store's anchor cache in O(1).

Decision
--------

Named certificate slot references (option 3) were selected. The slot layer
already provides lazy loading, deployment-descriptor management, and atomic
writes. Trust stores piggy-back on this infrastructure without duplicating it.

The ``TrustStoreHandler`` holds strong ``CertObject`` references during active
use; ``TrustStoreManager`` holds corresponding weak references in
``m_slot_cert_cache``. A cert shared by *N* trust stores allocates its bytes
exactly once.

A typed membership kind (``TrustStoreMemberKind``) records the ownership
relationship:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Kind
     - Ownership semantics
   * - ``kSharedStatic``
     - Slot is externally managed; the trust store may not mutate it.
   * - ``kExclusiveMutable``
     - Slot is trust-store-owned; ``AddCertificateToTrustStore`` may write to it.
   * - ``kConditionalExternal``
     - Slot is externally managed; anchor is disabled if the cert fingerprint
       changes unexpectedly until the application acknowledges the update.

Consequences
------------

**Positive:**

* ``NotifySlotChanged`` targets exactly one slot; unchanged anchors retain their
  cached ``CertObject`` strong references.
* The same cert slot can anchor multiple trust stores simultaneously with zero
  additional memory.
* CRL co-location (see ``dec_rec__crypto_cert_mgmt__crl_co_location``) is a
  natural consequence of slot-scoped membership — the CRL is already at the slot.
* Startup loading is strictly lazy — no cert bytes are read during ``Load()``.

**Negative:**

* Every trust-store member must be a registered cert slot; there is no escape
  hatch for one-off ephemeral certs. Ephemeral anchors are instead set with
  ``SetTrustedCertificate`` on the verification context.
* Configuration must name slots explicitly; adding a new anchor requires both a
  slot entry and a trust-store membership entry.

---

CRL Co-located with the Certificate Slot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: CRL Co-located with the Certificate Slot (No Separate CRL Registry)
   :id: dec_rec__crypto_cert_mgmt__crl_co_location
   :version: 1
   :status: accepted
   :context: doc__crypto_cert_management_architecture
   :decision: A CRL is stored in an optional ``[crl]`` section of the certificate slot's KV deployment descriptor. There is no independent CRL registry, CRL resource type, or CRL-specific DataNode. The slot is the resolution unit for both the certificate and its associated CRL.

   .. :affects: comp__crypto_cert_management

A CRL is stored in the optional ``[crl]`` section of the certificate slot's KV
deployment descriptor alongside the ``[certificate]`` section. CRL storage and
retrieval are encapsulated in ``CrlHandler``, which is composed into both
``FileBackedSlotHandler`` and ``Pkcs11CertSlotHandler``.

Context
-------

CRLs are revocation data for a specific issuing CA. Revocation status for a
given certificate chain therefore depends on the issuer's CRL, which is
naturally associated with the issuer's certificate slot. Three storage models
were evaluated:

1. **Separate CRL registry** — a ``CrlRegistry`` analogous to ``CertRegistry``,
   with its own DataNodes, resource IDs, and deployment descriptors. Gives CRLs
   a first-class resource identity. Requires separate resolution paths, a new
   ``kCrl`` resource type in the API, cross-resource foreign-key management
   (cert slot → CRL resource), and orphan handling when a cert slot is cleared.

2. **Global CRL file per trust store** — each trust store holds one CRL bundle
   file. Simple but coarse: updating one issuer's CRL requires rewriting the
   full bundle; per-issuer revocation is not possible; the slot-to-CRL mapping
   is implicit.

3. **CRL co-located with the certificate slot** — the ``[crl]`` section lives
   in the same KV file as ``[certificate]``. Lifecycle is automatic: clearing
   the slot clears the CRL; updating the certificate invalidates the CRL
   (``StoreCertificate`` clears ``[crl]`` fields while preserving ``crl_path``
   so the next ``StoreCrl`` reuses the same location). No orphan CRL is possible
   because no independent resource exists.

Decision
--------

CRL co-location with the cert slot (option 3) was selected. ``ICertSlotHandler``
is extended with ``HasCrl``, ``LoadCrl``, ``StoreCrl``, ``ClearCrl``, and
``GetCrlNextUpdate`` — implemented by the composed ``CrlHandler``. The
``crl_next_update`` epoch is written by ``StoreCrl`` and exposed through the
descriptor so the daemon can evaluate CRL freshness without loading the full DER.

For PKCS#11 token slots (where no filesystem cert path exists), ``CrlHandler``
stores CRL data in the deployment filesystem using the same ``crl_path``
convention — the PKCS#11 token provides no native CRL object type.

Consequences
------------

**Positive:**

* No new resource type, DataNode subclass, or registry required.
* CRL lifecycle is entirely derived from slot lifecycle — no orphan CRLs.
* ``StoreCertificate`` stale-CRL invalidation is a single write path with no
  cross-registry coordination.
* The verification handler walks trust-store member slots and calls ``HasCrl``
  per slot — no separate CRL lookup service.
* ``crl_next_update`` in the descriptor enables freshness checks without
  deserialising the DER.

**Negative:**

* A CRL can only be associated with a slot that holds a matching certificate.
  Detached CRLs (no corresponding cert slot) are not supported.
* CRL data is not independently addressable — no ``kCrl`` API resource type.
  Applications use ``ImportCrl(cert_resource_id, ...)`` rather than
  ``ImportCrl(crl_resource_id, ...)``.

---

Mutation Default-Deny with Explicit Writer UID
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Mutation Default-Deny with Explicit Writer UID
   :id: dec_rec__crypto_cert_mgmt__deny_mutation
   :version: 1
   :status: accepted
   :context: doc__crypto_cert_management_architecture
   :decision: All certificate slot and trust-store mutations (StoreCertificate, ImportCrl, AddMember, RemoveMember, EnableMember, DisableMember) are default-deny. Write access is granted only to UIDs listed in the slot or trust-store access policy. Reads do not require explicit authorisation beyond resource resolution.

   .. :affects: comp__crypto_cert_management

Certificate slot and trust-store mutations require explicit write authorisation.
The caller's UID must appear in the ``writers`` list of the ``AccessPolicy``
attached to the resource. Read operations (``LoadCertificate``, ``GetSlotInfo``,
``GetAnchors``) are accessible to any UID that can resolve the resource.

Context
-------

Certificate slots may contain CA root anchors or intermediate CA certificates
whose integrity is a security prerequisite for the entire verification chain.
Allowing any connected application to overwrite an anchor would undermine all
chain verification guarantees. Three approaches were evaluated:

1. **Per-call capability tokens** — the client presents a short-lived
   capability signed by a policy authority. Flexible, but requires a separate
   capability-issuing service, token validation logic, and replay protection.
   Overhead is disproportionate to the requirement at the current stage.

2. **Separate ACL service** — a dedicated access-control component that the
   cert management core queries before each mutation. Cleanly separable, but
   introduces an additional IPC hop and a new inter-component dependency for
   every mutation operation.

3. **UID-based access policy per resource** — each slot and trust-store
   configuration declares a ``writers`` set of UIDs (and optionally ``readers``
   if further restriction is desired). ``AccessPolicyEnforcer`` checks
   ``client_uid`` against the policy before the mutation is dispatched to the
   handler. Follows the same pattern already established by ``key_management``.

Decision
--------

UID-based per-resource access policy (option 3) was selected.
``AccessPolicyEnforcer`` is local to ``cert_management``; the long-term goal is
a shared access-control component across the daemon, but that refactoring is
deferred. The ``AccessPolicy`` type is defined in
``cert_management/interfaces/access_policy.hpp`` and is composed into both
``CertSlotConfig`` and ``TrustStoreConfig``.

Enforcement points:

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Operation
     - Access required
   * - ``StoreCertificate`` / ``ClearSlot``
     - Slot write
   * - ``ImportCrl`` / ``DeleteCrl``
     - Slot write
   * - ``AddCertificateToTrustStore`` / ``RemoveCertificateFromTrustStore``
     - Trust-store write
   * - ``EnableTrustStoreMember`` / ``DisableTrustStoreMember``
     - Trust-store write
   * - ``SaveCertificate`` (to a slot via mgmt context)
     - Slot write
   * - ``LoadCertificate`` / ``GetSlotInfo`` / ``GetAnchors``
     - None (resource resolution grants access)

Consequences
------------

**Positive:**

* CA anchor slots can be locked so that only the provisioning UID may write
  them; application UIDs can only read.
* Write access to a trust store is independent of write access to its member
  slots — a trust-store administrator can add/remove exclusive members without
  holding write access to the shared-static backing slot.
* Consistent with the ``key_management`` pattern — same mental model for
  operators configuring both subsystems.

**Negative:**

* UID-based access control is coarser than capability tokens; it cannot
  express time-limited or operation-specific delegation.
* Misconfigured ``writers`` sets are caught at runtime, not at compile time.
* Long-term refactoring to a shared ACL component will require updating
  enforcement sites in both ``key_management`` and ``cert_management``.

---

Atomic File Writes via Temp-File and Rename
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Atomic File Writes via Temp-File and Rename
   :id: dec_rec__crypto_cert_mgmt__atomic_writes
   :version: 1
   :status: accepted
   :context: doc__crypto_cert_management_architecture
   :decision: All file-backed certificate and descriptor writes use the shared ``file_io::WriteFile`` primitive from ``daemon/common/storage/``, which writes to a temporary file and then renames it atomically over the target. A partially written descriptor or certificate payload can never replace the previous valid state.

   .. :affects: comp__crypto_cert_management

File-backed certificate payloads and KV deployment descriptors are written via
``file_io::WriteFile`` (``daemon/common/storage/file_io.hpp``). That primitive
writes to a sibling temporary file, then issues an atomic ``rename`` to replace
the target. The same mechanism is used by ``KvDeploymentWriter`` for descriptor
updates.

Context
-------

The crypto daemon may be killed by SIGKILL (watchdog expiry, power loss) at any
point during a write. A partially written certificate or descriptor must not
leave the slot in a state where the daemon reads corrupt data on the next startup.
Three strategies were evaluated:

1. **Direct writes** — open the target file and write in place. Simple, but a
   crash mid-write leaves a truncated or partially overwritten file. The previous
   valid content is lost with no recovery path.

2. **Write-ahead log (WAL)** — record the intent before writing, then apply and
   mark complete. Provides full crash recovery but requires a WAL reader at
   startup, adds ~100–200 LOC of journal management, and is disproportionate
   for individual file writes without transactional multi-file requirements.

3. **Temp-file + ``rename``** — write the new content to a sibling temporary
   file; call ``rename(tmp, target)`` which is atomic on POSIX filesystems.
   The old content survives until ``rename`` succeeds; after ``rename``, the new
   content is fully visible. No reader of the target file ever observes a partial
   state.

Decision
--------

Temp-file + ``rename`` (option 3) was selected and implemented in
``file_io::WriteFile``. The utility is shared between ``cert_management`` and
``key_management``; it is the only file-write primitive that components in
``daemon/common/storage/`` expose. Certificate payload bytes use
``WriteFile``; key material continues to use ``WriteKeyFile`` which adds
``SecureZeroizeAndClear`` semantics on the temporary.

``KvDeploymentWriter`` applies the same pattern for descriptor files: the
descriptor is preserved on disk until the new content is fully written and
renamed in place.

Consequences
------------

**Positive:**

* A daemon crash at any point during a write leaves the slot in the previous
  valid state — no manual recovery or fsck-style startup scan is needed.
* Readers (including a concurrently running verification context) never observe
  a partial file — POSIX ``rename`` is atomic with respect to other
  ``open``/``read`` calls on the target path.
* A single shared utility eliminates per-component write-safety logic.

**Negative:**

* Requires the temporary file and the target to be on the same filesystem
  (``rename`` across mount points is not atomic). Deployment configuration must
  not place ``tmp`` and target on different volumes — this is documented but not
  enforced at runtime.
* Write amplification: every update writes a full new copy of the file rather
  than patching in place. Acceptable for certificate and descriptor sizes (a few
  kilobytes); not suitable for large append-only data.

---

Provider Boundary: Parsing Only; No Private Key or HSM Handle Crossing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Provider Boundary — Parsing Only; No Private Key or HSM Handle Crossing
   :id: dec_rec__crypto_cert_mgmt__provider_boundary
   :version: 1
   :status: accepted
   :context: doc__crypto_cert_management_architecture
   :decision: The certificate management component receives DER or PEM bytes from a provider via ``ICertParser`` and stores an immutable ``CertObject`` value. Provider-specific handles (PKCS#11 object handles, HSM references), raw private keys, and provider internal types do not cross the certificate management boundary in either direction.

   .. :affects: comp__crypto_cert_management

The certificate management core interacts with providers through one narrow
interface: ``ICertParser::ParseCertificate`` converts raw bytes into an
immutable ``CertObject`` value. No provider handle, HSM reference, or raw
private key enters or leaves the core component. Provider context handlers
(verification, CSR generation, format conversion) are separate objects created
by the provider factory; they do not share types with the storage layer.

Context
-------

A cert management component that allows provider handles to cross its boundary
would couple core storage logic to specific HSM APIs. Two alternative designs
were evaluated:

1. **Provider-owned certificate objects** — the provider allocates a
   ``ProviderCertHandle`` (analogous to a PKCS#11 ``CK_OBJECT_HANDLE``) and
   passes it through the component boundary. The core stores the handle.
   Loading a cert from storage calls the provider to deserialise its own handle.
   This design ties cert lifetime to provider availability and prevents sharing
   cert content between providers or between the storage layer and the
   verification handler.

2. **Immutable value type (``CertObject``) with a narrow parsing interface** —
   the provider converts bytes to a provider-neutral value once at load time.
   The core stores and shares the value; the provider is not involved in
   subsequent reads. Verification handlers receive ``CertObject`` values and
   apply provider-specific OpenSSL or HSM operations internally.

Decision
--------

Immutable ``CertObject`` value type with ``ICertParser`` as the sole
provider-crossing interface (option 2) was selected. ``CertObject`` contains:

* Raw DER or PEM bytes (reproduced faithfully from what was stored).
* ``CertChainMetadata`` — SKID, AKID, SHA-256 fingerprint, ``is_ca`` flag,
  subject, issuer, serial number — extracted at parse time and cached.

``ICertFactory``, ``ICertHandler``, ``ICertLoader``, and ``ProviderCertHandle``
were considered during early design and are explicitly **not present** in the
implementation. Cert context operations (verify, CSR, convert, key extract)
belong inside handlers created by ``ICryptoHandlerFactory::CreateHandler``; they
are not responsibilities of the storage component.

For CSR generation, signing requires the private key to remain inside the
provider. The planned cross-context broker (``IKeyOperationEndpoint``) provides
a ``Sign(data, algorithm)`` call that the CSR handler invokes without the
private key material ever leaving the key management provider boundary.

Consequences
------------

**Positive:**

* ``CertObject`` can be shared across trust stores, verification contexts, and
  the cert registry without provider involvement after the initial parse.
* Replacing the OpenSSL provider with a different implementation requires only a
  new ``ICertParser`` and new context handlers — the storage and trust-store
  layers are unaffected.
* Private keys cannot leak through the certificate management path; the boundary
  is structurally enforced (``ICertParser`` receives only cert bytes and returns
  only cert values).
* Verification handlers receive fully self-contained ``CertObject`` values and
  operate without callback into the storage layer during chain building.

**Negative:**

* Parse-time extraction of ``CertChainMetadata`` means the full cert is parsed
  even when only the fingerprint is needed. The overhead is proportional to
  cert count at startup (lazy loading mitigates this — certs are not parsed
  until a trust store is first accessed).
* Some provider-specific cert attributes (e.g., PKCS#11 token labels) are not
  captured in ``CertObject``. Applications that need them must use
  ``ICertSlotHandler``-specific query paths, which the current API does not
  expose publicly.
