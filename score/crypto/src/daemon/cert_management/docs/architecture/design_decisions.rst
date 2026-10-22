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
   single ``NotifySlotChanged(slot)`` call after ``StoreCertificate`` refreshes
   the anchor and CRL entries of every trust-store member backed by that slot. Conditional-external members are
   disabled and persisted until ``AcknowledgeMemberUpdate`` records the new
   fingerprint.

Decision
--------

Named certificate slot references (option 3) were selected. The slot layer
already provides lazy loading, deployment-descriptor management, and atomic
writes. Trust stores piggy-back on this infrastructure without duplicating it.

The ``TrustStoreHandler`` holds strong ``CertObject`` references during active
use; ``CertSlotManager`` holds the corresponding weak references, so every
reader of a slot, including each trust store, shares one parsed object. A cert
shared by *N* trust stores allocates its bytes exactly once.

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

Trust-Store Notification Is Owned by CertManagementService, Not CertSlotManager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Trust-Store Notification Is Owned by CertManagementService, Not CertSlotManager
   :id: dec_rec__crypto_cert_mgmt__notify_ownership
   :version: 1
   :status: accepted
   :context: doc__crypto_cert_management_architecture
   :decision: Certificate-slot and CRL mutations are reachable only through CertManagementService::StoreCertificate, ClearSlot, StoreCrl, and ClearCrl. Each performs the underlying CertSlotManager write and then, when the stored content may have changed, notifies every trust store referencing the slot, whether the write succeeded or failed. CertSlotManager itself has no trust-store awareness and never calls TrustStoreManager.

   .. :affects: comp__crypto_cert_management

Certificate-slot and CRL mutations are reachable only through
``CertManagementService``'s own mutation methods. ``CertSlotManager`` performs
the underlying write and knows nothing about trust stores; it depends only on
slot configuration and backend handlers.

Context
-------

A trust store's cached anchors and CRLs must stay consistent with the
certificate slots they reference (see
``dec_rec__crypto_cert_mgmt__ts_ref_slots``). Something must notify every
referencing trust store after a slot write that may have changed the stored content. ``TrustStoreManager``
already depends on ``CertSlotManager`` — it holds a ``CertSlotManager::Sptr``,
includes its header, and is friend-gated into
``CertSlotManager::GetTrustStoreCertSlotHandler`` for Tier-3 backend access.
Any design that issues the notification from inside ``CertSlotManager`` itself
needs the reverse dependency, which is circular, not a layering refinement.

Four placements were considered:

1. **Caller-driven notification** — a caller invokes
   ``CertSlotManager::StoreCertificate``/``ClearSlot``/``StoreCrl``/``ClearCrl``
   directly and separately calls a notification method afterward. Correctness
   depends entirely on every caller remembering the second call, with nothing
   at the type level enforcing it: a caller can perform the slot write and
   simply omit the notification, leaving trust-store caches stale with no
   observable error.

2. **``CertSlotManager`` calls ``TrustStoreManager`` directly** — move the
   notification into ``CertSlotManager``'s own mutation methods, calling
   ``TrustStoreManager::NotifySlotChanged``/``NotifySlotCrlChanged`` after a
   backend write that may have changed the stored content. Requires ``CertSlotManager`` to depend on
   ``TrustStoreManager``, which already depends on ``CertSlotManager`` — a
   circular dependency. The exclusive-slot write guard in
   ``CertSlotManager::ApplyWriteChecks`` would need to ask ``TrustStoreManager``
   whether a slot is a trust-store-owned member.

3. **A registered observer on ``CertSlotManager``** — ``CertSlotManager`` exposes
   a slot-change callback interface that ``CertManagementService`` wires to
   ``TrustStoreManager`` at construction, so the slot manager depends only on an
   abstract callback. This removes the type-level cycle but not the underlying
   risk: every write path in ``CertSlotManager`` must still remember to invoke
   the callback, and a write path added later can forget it as easily as a
   caller can forget a separate notification call.

4. **``CertManagementService`` owns both the write and the notification** —
   the service wraps ``CertSlotManager``'s four mutation methods; after each
   call that may have changed the stored content, successful or failed, it
   calls ``TrustStoreManager::GetMembershipsForSlot`` and fans out to
   ``NotifySlotChanged`` (certificate updates) or ``NotifySlotCrlChanged`` (CRL
   updates) for each referencing store. ``CertManagementService`` already holds
   both ``CertSlotManager::Sptr`` and ``TrustStoreManager::Sptr`` as sibling
   dependencies, so this introduces no new dependency edge.

Decision
--------

Option 4 was selected. ``CertManagementService::StoreCertificate``/``ClearSlot``
call ``TrustStoreManager::NotifySlotChanged``, which reloads only the changed
member's anchor and CRL entries, leaving other members' cached entries
untouched. ``StoreCrl``/``ClearCrl`` call
``TrustStoreManager::NotifySlotCrlChanged``, which calls
``TrustStoreHandler::OnSlotCrlChanged``. The handler takes the slot's current CRL
snapshot — or none, after a delete — from ``CertSlotManager`` and replaces the
member's cached CRL with it, without reloading the certificate, since a CRL
refresh changes revocation data, not the anchor's identity. Reading the current
snapshot, rather than receiving one in the notification, keeps concurrent
updates ordered by the slot's state and not by notification arrival.
``GetSlotManager()`` remains available for read-only slot operations, which
have no trust-store side effect to coordinate; only the four mutation methods
are redirected through the service.

Consequences
------------

**Positive:**

* Trust-store notification cannot be skipped by caller oversight — it is
  structural, not a discipline every caller must independently uphold.
* No new dependency edge: the notification lives in the component that already
  holds both collaborators, rather than introducing a cycle between them.
* ``CertSlotManager`` stays usable, and testable, without a ``TrustStoreManager``
  — it has no awareness that trust stores exist.

**Negative:**

* ``CertManagementService::GetSlotManager()`` returns the underlying
  ``CertSlotManager::Sptr`` for read-only operations (``LoadCertificate``,
  ``GetSlotInfo``, ``HasCrl``, ``GetCrlNextUpdate``, and similar). A caller that
  holds this handle can still call its ``StoreCertificate``/``ClearSlot``/
  ``StoreCrl``/``ClearCrl`` methods directly and silently lose trust-store
  notification; nothing at the type level prevents this. The constraint is
  documented on ``GetSlotManager()`` but not enforced.
* A ``kExclusiveMutable`` trust-store member slot configured with a non-empty
  ``allowed_write_uids`` still lets a listed UID write it directly through
  ``CertSlotManager``/``ICertSlotHandler``, bypassing both the trust store's
  write-access gate and this notification. That remains a configuration
  invariant, recorded under ``dec_rec__crypto_cert_mgmt__deny_mutation``, and is
  not enforced by this decision.
* Certificate and CRL notification are two separate code paths
  (``NotifySlotChanged`` vs. ``NotifySlotCrlChanged``) with different cache
  semantics (reload the member vs. refresh only its CRL), which a future third
  kind of slot-state change would need to extend rather than reuse wholesale.

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
retrieval are encapsulated in ``CrlHandler``, which is composed into
``FileBackedSlotHandler``.

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
is extended with ``HasCrl``, ``GetCrlMetadata``, ``LoadCrlData``, ``StoreCrl``,
and ``ClearCrl`` — implemented by the composed
``CrlHandler``. The descriptor persists the CRL fingerprint, issuer fingerprint,
``thisUpdate``, ``nextUpdate``, and ``cRLNumber``. The public
``ICertificateObject`` exposes this as optional ``CrlMetadata``; encoding format
remains an internal persistence detail. Persisted ``CrlMetadata`` is written
by ``StoreCrl``. A ``[crl]`` section that holds only ``crl_path``/``crl_format``,
with no fingerprint fields, has no stored metadata; the file-backed handler
derives it on demand when it has a parser and the slot holds a certificate, and
reports none otherwise.
This has no revocation-checking implication: the cached descriptor fields are
for inspection only. Revocation checking is a provider verification
responsibility and is expected to parse raw CRL bytes directly rather than
rely on this cache. The cached fields exist solely to answer inspection
queries (``ICertificateObject::GetCrlMetadata``) without deserialising the
CRL.

Consequences
------------

**Positive:**

* No new resource type, DataNode subclass, or registry required.
* CRL lifecycle is entirely derived from slot lifecycle — no orphan CRLs.
* ``StoreCertificate`` stale-CRL invalidation is a single write path with no
  cross-registry coordination.
* The verification handler walks trust-store member slots and calls ``HasCrl``
  per slot — no separate CRL lookup service.
* CRL metadata is available without deserialising the CRL during normal reads.

**Negative:**

* A CRL can only be associated with a slot that holds a matching certificate.
  Detached CRLs (no corresponding cert slot) are not supported.
* CRL data is not independently addressable — no ``kCrl`` API resource type.
  Applications use ``ImportCrl(cert_resource_id, ...)`` rather than
  ``ImportCrl(crl_resource_id, ...)``.
* A CRL written to a slot's ``[crl]`` section out of band (bypassing
  ``ImportCrl``/``StoreCrl``) has no cached ``CrlMetadata`` in the descriptor.
  The file-backed handler derives it on demand by validating the CRL against the
  slot's certificate through the canonical parser; a handler without a parser, or
  a slot without a certificate, reports no metadata even though the CRL is usable
  for revocation checking.

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
The caller's UID must appear in the ``allowed_write_uids`` list of the ``AccessPolicy``
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
   Overhead is disproportionate to the stated requirement.

2. **Separate ACL service** — a dedicated access-control component that the
   cert management core queries before each mutation. Cleanly separable, but
   introduces an additional IPC hop and a new inter-component dependency for
   every mutation operation.

3. **UID-based access policy per resource** — each slot and trust-store
   configuration declares an ``allowed_write_uids`` set of UIDs; ``allowed_uids``
   is reserved for a future read restriction. ``AccessPolicyEnforcer`` checks
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
* Misconfigured ``allowed_write_uids`` sets are caught at runtime, not at compile time.
* Long-term refactoring to a shared ACL component will require updating
  enforcement sites in both ``key_management`` and ``cert_management``.
* ``CertSlotManager``'s slot-write enforcement is keyed purely off
  ``allowed_write_uids``; it has no notion of trust-store ownership. A
  ``kExclusiveMutable`` trust-store member slot must therefore be configured
  with an empty ``allowed_write_uids`` — the exclusive slot is meant to be
  written only through the trust store's own write-access gate. A non-empty
  list on such a slot lets any listed UID write to it directly, bypassing
  that gate and the trust store's cache/notification bookkeeping. This is
  a configuration invariant; ``CertSlotManager`` does not enforce it.

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
were considered during early design and are not part of the
implementation. Cert context operations (verify, CSR, convert, key extract)
belong inside handlers created by ``ICryptoHandlerFactory::CreateHandler``; they
are not responsibilities of the storage component.

For CSR generation, signing requires the private key to remain inside the
provider that owns it. The CSR handler therefore obtains a signature over the
``TBSCertRequest`` through a daemon-internal cross-context service rather than
by exporting key material. The constraint is part of this boundary decision; the
mechanism that satisfies it belongs to the cross-context design and is not fixed
here.

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
  cert count at startup (lazy loading limits this: certificates are parsed on first
  read, not at startup).
* Some provider-specific cert attributes (e.g., PKCS#11 token labels) are not
  captured in ``CertObject``. Applications that need them must use
  ``ICertSlotHandler``-specific query paths, which the public API does not
  expose.

---

One Canonical Certificate Parser, Selected by Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: One Canonical Certificate Parser, Selected by Configuration
   :id: dec_rec__crypto_cert_mgmt__parser_authority
   :version: 1
   :status: accepted
   :context: doc__crypto_cert_management_architecture
   :decision: Slot loading, certificate-management operations, and trust-store metadata use a single canonical ``ICertParser`` for the whole component. The supplying provider is either named explicitly in the certificate configuration or selected by the certificate-management capability default. It is never selected by the client or by a per-context provider hint.

   .. :affects: comp__crypto_cert_management

``SlotHandlerFactory`` owns parser selection and supplies the resolved parser to
every slot handler it creates. No provider is hardcoded as the parsing
authority, and no caller may substitute a different parser for an individual
operation.

Context
-------

Parsing a certificate produces more than bytes: ``CertChainMetadata`` carries
the SHA-256 fingerprint, SKID, AKID, ``is_ca``, subject, issuer, and serial
number. Trust-store membership matching, the slot ``CertObject`` cache, anchor
deduplication, and chain building all key off those derived values. Three
selection models were evaluated:

1. **Per-context parser selected by the client's provider hint** — the parser
   follows the same hint that selects a context's verification or CSR provider.
   Rejected: the same certificate bytes would acquire a different identity
   depending on which context loaded them, so a slot could appear as two
   distinct anchors, and a trust-store member could fail to match the slot it
   was configured from. Two parsing authorities for one certificate is a
   correctness defect, not a configuration preference.

2. **Hardcoded OpenSSL parser** — simple and always available in the provider
   set. Rejected: a deployment that does not register the OpenSSL
   provider, or that must route parsing through a qualified implementation, has
   no way to redirect it, and the core component would name a concrete provider
   in violation of the provider-boundary decision.

3. **One canonical parser, resolved from configuration with a capability
   default** — an optional configured provider name pins the parser; when unset,
   the certificate-management capability selection applies.

Decision
--------

Option 3 was selected. ``SlotHandlerFactory`` resolves the parser as follows:

* When ``CertificateConfig::GetParserProviderName`` is non-empty, that exact
  provider is looked up by name and must both advertise the
  certificate-management capability and return a non-null parser. Any failure is
  reported rather than silently falling back to another provider — an explicit
  deployment choice is not overridden.
* When it is empty, the provider selected for the certificate-management
  capability supplies the parser.

Resolution is lazy on first slot-handler creation. ``Initialize()`` resolves
eagerly and returns the resolution error without exposing the parser, so a
caller can fail fast at startup; ``CertManagementModule::Create`` invokes it only
when a parser provider is explicitly configured, and returns no module when that
configured provider cannot be honoured. A successful parser is cached and shared
across copies of the factory. A failed resolution is not cached, so a later call
retries once the provider set is complete.

Context provider hints remain meaningful for context-scoped capabilities such as
path validation and CSR generation. They do not select the parser.

Consequences
------------

**Positive:**

* A certificate has one identity regardless of which context loaded it, so
  trust-store matching, slot caching, and anchor deduplication stay consistent.
* The parsing authority is a deployment decision rather than a compile-time one,
  without naming a concrete provider in the component.
* An explicitly configured parser provider that cannot be honoured is a startup
  failure, not a silent substitution.
* Parser resolution costs one provider lookup for the life of the component.

**Negative:**

* When no parser provider is configured and no provider offers the
  certificate-management capability, slot handlers are created without a parser.
  Operations that need one (certificate parsing, CRL validation) report an error
  at the point of use; slot enumeration, slot state, and trust-store membership
  listing remain available. Startup does not fail in this case, because no
  explicit deployment choice has been contradicted.
* Because failed resolution is not cached, the diagnostic for a missing
  certificate-management provider is emitted on each attempt rather than once.
* A client cannot request a particular provider's parsing behaviour. Deployments
  that need different parsing for different certificate populations cannot
  express that through this component.

---

A Trust Store That Cannot Be Used Fails Closed; Trust Increases Are Persisted Before They Are Published
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: A Trust Store That Cannot Be Used Fails Closed; Trust Increases Are Persisted Before They Are Published
   :id: dec_rec__crypto_cert_mgmt__trst_str_vdty
   :version: 1
   :status: accepted
   :context: doc__crypto_cert_management_architecture
   :decision: A trust store whose members cannot all be resolved, or whose persisted state exists but cannot be used, is invalid. An invalid store is reported when it is resolved, bound, read, or mutated, and it never runs with a subset of its members or with default state. Reading an existing member certificate or CRL that fails is returned to the caller; an empty member slot and a missing CRL are valid. A change that increases trust is persisted before it is published to the running store; a change that reduces trust takes effect immediately.

   .. :affects: comp__crypto_cert_management

Context
-------

A trust store combines configuration (its name and members), persisted state (each member's
enabled flag and accepted fingerprint), and the content of its member slots. Each can be
wrong independently, and each can be wrong in a way that silently trusts more or checks less:

* A member that names no configured slot would be skipped, leaving a smaller anchor set.
* A persisted state that cannot be read, if treated as empty, would enable members that an
  operator had disabled.
* A member certificate or CRL that fails to read, if skipped, would drop an anchor or the
  revocation data without the client learning of it.
* A change that is published before it is persisted would be trusted by the running process
  and then lost at the next start.

Options
-------

1. **Partial loading** — use whatever resolves and log the rest. The store keeps working, but
   a client cannot tell that its anchor set or revocation data is incomplete, and the cause is
   visible only in the log.
2. **Invalid store (selected)** — a store that cannot be used reports an error from every
   operation that would use it. The cause is logged once, naming the store and member but no
   file system locations.
3. **Fail the whole daemon** — appropriate for a duplicate store name, where there is no
   defined store to mark invalid, and used for that case only.

Decision
--------

* ``TrustStoreManager::Load`` rejects an empty or duplicate store name and loads nothing.
* A store with a member that does not name a configured slot, a slot listed twice, or a
  persisted state that cannot be used is created as invalid (``TrustStoreHandler::IsValid()``).
  Resolving it, binding it (``AddRef``), reading it, and mutating it return
  ``kTrustStoreInvalid``. Read-only inspection of members stays available.
* An absent state file is the first run: members start from the configuration. A state file
  that exists but cannot be parsed, or holds a value that is not ``true`` or ``false`` or a
  malformed fingerprint, makes the store invalid. A member with no persisted entry, for example
  one added by a configuration change, starts from the configuration.
* An empty member slot and a missing CRL are valid states. Any other failure to read an existing
  member certificate or CRL makes the bind or read fail with that error.
* Changes that increase trust (adding or enabling a member, accepting a conditional member's new
  content) are written to the state descriptor first and only then published to the in-memory
  state and the cache. If the write fails, the previous state stays in place. Changes that reduce
  trust (disabling or removing a member) take effect immediately; if their state cannot be
  persisted the error is returned and the reduction stays in effect for the running process.
* Adding a member that cannot be completed leaves nothing trusted: a failed CRL write or a failed
  state write clears the certificate that was just stored, and a failed CRL upsert for an existing
  member is returned.

Consequences
------------
**Positive:**

* A client learns about a damaged store when it resolves or binds it, not through a later
  verification failure.
* A damaged state file cannot re-enable a disabled member.
* The running process never trusts more than what is on storage.

**Negative:**

* One unusable member makes the whole store unavailable. An operator can disable a member
  without loading it, but a configuration or state error needs repair of the configuration or
  state file; there is no operation to repair it through the API.
* The cleanup after a failed add is best effort. A failure of the cleanup itself can leave the
  certificate in the slot until the next add or an explicit removal.
* A write that fails after changing storage is not atomic at the slot level. Atomic slot updates
  are a separate concern from this decision.

---

A Trust-Store State Without a Deployment Path Is Held in Memory Only
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: A Trust-Store State Without a Deployment Path Is Held in Memory Only
   :id: dec_rec__crypto_cert_mgmt__trst_str_mem
   :version: 1
   :status: accepted
   :context: doc__crypto_cert_management_architecture
   :decision: A trust store configured without a deployment path keeps its member state (enabled flags and accepted fingerprints) in memory for the life of the process. Nothing is read at startup or written, so a restart restores the configuration. A state change still takes effect and reports success. Stores with a deployment path persist their state as described in the trust-store validity record.

   .. :affects: comp__crypto_cert_management

Context
-------

The deployment path is optional. A store with static membership has no need for a state file, and
requiring one would add configuration to every deployment. A store without a path has nowhere to
read or write its state, so two kinds of trust decision are not kept across a restart: a member
disabled at runtime, and a conditional member whose content change was not acknowledged.

Options
-------

1. **Require a deployment path for every store with members.** Every state change survives a
   restart. Static stores need a state file they do not otherwise use.
2. **Allow an empty path and keep state in memory (selected).** A static store needs no state file.
   A restart resets all member state to the configuration.

Decision
--------

* An empty deployment path is accepted. The store starts from its configuration, a state change
  takes effect for the running process and returns success, and nothing is written.
* The persistence guarantees in the trust-store validity record apply only to stores with a
  deployment path.

Consequences
------------

**Positive:**

* A static store needs no state file and no path in its configuration.

**Negative:**

* A member disabled at runtime is enabled again after a restart. An operator who needs a
  revocation to survive a restart must configure a deployment path for that store.
* For a conditional member with the accept-current initialization policy, a content change that
  was not acknowledged is accepted again after a restart. Under the other policy the member is
  disabled after a restart.
* The persistence requirement ``comp_req__crypto_cert_management__persistence`` is met only for
  stores with a deployment path.
