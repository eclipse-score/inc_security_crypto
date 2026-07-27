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

.. _crypto_api_description:

API Description
===============

..
   TODO: We should rather have an overview of the complete stack library and daemon architecture here.
   Currently it is quite API focused.

Resource ID Model
-----------------

The API uses a two-phase resource identification model:

1. **Resolution phase**: Applications call ``ICryptoContext::ResolveResource()``
   with an app-defined string ``ResourceId`` (e.g., ``"KeySlot_42"``) and the
   expected ``ResourceType``. The daemon looks up the string in the per-application
   configuration, verifies access control, and returns a ``CryptoResourceId``.

2. **Operation phase**: All operation contexts, configs, and queries accept only
   ``CryptoResourceId`` — no strings cross into operation contexts.

``CryptoResourceId`` is a compact ~16-byte struct:

.. code-block:: cpp

   struct CryptoResourceId {
       uint64_t id;                   // daemon-assigned, unique per session
       ResourceType type;             // kProvider, kKeySlot, kCertSlot, kVerificationTrustStore,
                                      // kKey, kCertificate, kCrl, kSecureObject, kDataObject
       ResourcePersistence persistence; // kPersistent or kEphemeral
       uint16_t primary_provider;     // owning device/provider index (0 = unbound)
   };

The struct is fully numeric, cheap to copy and hash, and includes
``operator==``, ``operator!=``, and ``std::hash`` specialization for use
in unordered containers.

``CryptoResourceId`` unifies persistent and ephemeral resources via the
``ResourcePersistence`` field. Keys are ephemeral by default when
generated, derived, agreed, imported, or unwrapped — they receive a
``CryptoResourceId`` with ``type == kKey`` and
``persistence == kEphemeral``. Use
``IKeyManagementContext::PersistKey()`` to promote an ephemeral key
to a persistent slot.

Key slots (``kKeySlot``) represent only logical persistent storage locations.
Ephemeral keys exist in transient memory and have no slot; some providers
may internally use RAM slots, but this is an implementation detail not
modeled at the interface level.

For specialized queries on a resource (e.g., key algorithm, slot state,
certificate subject), typed object interfaces can be obtained from
``ICryptoContext`` accessor methods such as ``GetKeyObject()``,
``GetKeySlotObject()``, ``GetCertificateObject()``, and
``GetProviderObject()``.

Resource Lifecycle and CryptoResourceGuard
------------------------------------------

Transient resources (ephemeral keys, loaded key material, extracted
certificate public keys) must be deterministically released to prevent
sensitive key material from lingering in daemon memory.

All resource-producing methods (``GenerateKey``, ``DeriveKey``, ``AgreeKey``,
``UnwrapKey``, ``ImportKey``, ``LoadKey``, ``LoadCertificatePublicKey``,
``ImportCrl``) return ``CryptoResourceGuard`` — a move-only RAII wrapper.
Transient resource lifetime is managed by the daemon via per-resource reference
counting: the guard holds
a type-erased IPC release handle; ``Create*Context()`` atomically
validates the key and increments the daemon ref-count; guard destruction
decrements it. On client disconnect, the daemon bulk-frees all resources.

The implicit conversion operator means a single
``SetKey(const CryptoResourceId&)`` signature works for both raw
``CryptoResourceId`` and ``CryptoResourceGuard`` — no overloads needed.

**Two key usage paths:**

1. **Slot-direct path** (simplest — no guard needed):
   Pass a resolved ``kKeySlot`` directly to ``SetKey()``. The context
   factory internally loads key material from the slot and releases it
   on context destruction:

   .. code-block:: cpp

      auto slot = ctx->ResolveResource("MyKey", ResourceType::kKeySlot).value();
      CipherContextConfig config;
      config.SetAlgorithm("AES-256-CBC").SetKey(slot).SetDirection(CipherDirection::kEncrypt);
      auto cipher = ctx->CreateCipherContext(config).value();
      // Context loads key internally; releases on ~cipher.

2. **Guard path** (for generated/loaded/derived/imported resources):
   Resource-producing methods return a ``CryptoResourceGuard`` that
   auto-releases on destruction:

   .. code-block:: cpp

      auto guard = key_mgmt->GenerateKey(GenerateKeyParams{}.SetAlgorithm("AES-256")).value();
      CipherContextConfig config;
      config.SetAlgorithm("AES-256-GCM").SetKey(guard).SetDirection(CipherDirection::kEncrypt);
      auto cipher = ctx->CreateCipherContext(config).value();
      // ... use cipher ...
      // ~guard: Release(id) IPC → daemon decrements ref-count, frees ephemeral key.

3. **Guard outliving its context** (guard destroyed after context):
   After ``Create*Context()`` succeeds, the guard may be destroyed at any
   time — the daemon bound the key to the context and incremented its
   ref-count. The context continues to use the key independently:

   .. code-block:: cpp

      ICipherContext::Uptr cipher;
      {
          auto guard = key_mgmt->GenerateKey("AES-256").value();
          config.SetAlgorithm("AES-256-GCM").SetKey(guard).SetDirection(CipherDirection::kEncrypt);
          cipher = ctx->CreateCipherContext(config).value();
          // Daemon ref-count = 2 (guard + context)
      }  // ~guard: Release(id) IPC → daemon ref-count = 1 (context holds ref)
      cipher->Init(iv);
      cipher->Update(plaintext, ciphertext);
      cipher->Finalize(output);
      // ~cipher: daemon ref-count = 0 → key freed

**Cleanup ownership via ResourceType:**

When a config's key has ``type == kKeySlot``, the context owns the
internally-loaded copy and releases it on destruction. When
``type == kKey``, the caller (guard) owns the material — the context
only references it. No communication between guard and context is
needed; the ``ResourceType`` already encodes the ownership model.

**Cleanup guarantee:**

1. ``CryptoResourceGuard`` destructor — automatic, deterministic.
   Sends ``Release(id)`` IPC (daemon decrements ref-count).
2. Daemon bulk-free on process exit or crash —
   all resources registered for the client are freed regardless of
   whether destructors ran (crash-safe safety net). This is not
   triggered by individual ``ICryptoStack`` destruction.

**Explicit release with synchronous error handling**:

When the application needs to explicitly confirm release before destruction — for example,
to detect that the resource is still referenced by an active context — call
``guard.Release()``:

.. code-block:: cpp

   auto result = guard.Release();  // Result<std::monostate>; auto-deactivates on success
   if (!result.has_value()) {
       // e.g. resource still used by an active context — destroy it first
   }

Memory and Data Plane Model
---------------------------

The data plane is architecturally independent of the IPC control plane:

- ``ICryptoStack::GetMemoryAllocator()`` returns a ``Result<IMemoryAllocator::Uptr>``
  transferring ownership of the allocator to the caller.
- ``IMemoryAllocator::Allocate(size)`` allocates shared memory with ``kDefault``
  type. The daemon tracks allocations against a per-application quota
  (configurable, overridable per app).
- ``IMemoryAllocator::Allocate(size, kProviderCompatible, providerHandle)``
  allocates memory directly usable by a specific provider (e.g., DMA-capable
  for hardware/TEE), enabling the zero-copy path.
- ``IReadWriteMemoryRegion`` provides ``AsSpan()`` and ``AsWritableSpan()`` for
  passing data to operation contexts.
- Memory regions are shared between library and daemon, so operation data does
  not traverse the IPC serialization path.
- Destruction of a memory region releases it from the daemon's pool and adjusts
  the quota.

Zero-Copy Path
--------------

When provider-compatible memory is used, the data path avoids all copies:

1. Application allocates provider-compatible memory via
   ``Allocate(size, kProviderCompatible, providerHandle)``
2. Application writes data into the region
3. Application passes ``region.AsSpan()`` to an operation context
4. Daemon forwards the same physical memory to the target provider
5. No copies occur end-to-end

For non-compatible memory or when ``kDefault`` is used, the daemon copies
data into an internal provider-compatible buffer transparently.

Base Class Hierarchy
--------------------

Three base interfaces capture shared behavior across operation contexts,
promoting DRY code reuse:

.. code-block:: none

   IContext
   ├── IStreamingContext (Init + Update)
   │   ├── IStreamingOutputContext (+ Finalize + GetOutputSize)
   │   │   ├── IHashContext (+ SingleShot, GetDigestSize)
   │   │   ├── ICipherContext (+ Init with IV, SingleShot; direction from config)
   │   │   ├── ISignContext (+ SignFinalize, SingleShot, GetSignatureSize)
   │   │   └── IMacContext (+ Verify, GetMacSize)
   │   ├── IAeadContext (+ UpdateAad, Finalize, VerifyAndFinalize, GetTagSize)
   │   └── IVerifySignatureContext (+ VerifyFinalize, SingleShot)
   ├── IRandomContext (Generate, Seed)
   ├── IKeyManagementContext (key lifecycle operations)
   ├── ICertificateManagementContext (certificate lifecycle operations)
   ├── ICertificateVerificationContext (builder-style chain verification)
   └── ICsrGenerationContext (builder-style CSR generation)

Typed Object Hierarchy
^^^^^^^^^^^^^^^^^^^^^^

Typed crypto object interfaces provide specialized access to resources
identified by ``CryptoResourceId``. Objects are obtained via
``ICryptoContext`` accessor methods and are lightweight proxies into
daemon state, not owned data copies:

.. code-block:: none

   ICryptoObject (base — GetId, GetType)
   ├── IKeyObject (algorithm, persistence, exportability, key length)
   │   ├── ISymmetricKeyObject (allowed cipher modes)
   │   ├── IPublicKeyObject (ExportPublicKey)
   │   └── IPrivateKeyObject (HasCorrespondingPublicKey)
   ├── IKeySlotObject (slot state, allowed algorithm, provider binding)
   ├── ICertificateObject (subject, issuer, validity, public key algorithm)
   ├── ICertSlotObject (occupancy)
   ├── IProviderObject (provider type, name, supported algorithms)
   ├── ISecureObject (data, size)
   └── IDataObject (data, size)

- ``IContext``: Root base with ``Uptr`` typedef and virtual destructor
- ``IStreamingContext``: Adds ``Init() → Result<std::monostate>``,
  ``Update(span<const uint8_t>) → Result<std::monostate>``, and
  ``Reset() → Result<std::monostate>`` for streaming patterns
- ``IStreamingOutputContext``: Adds ``Finalize(span<uint8_t>) → Result<size_t>``
  and ``GetOutputSize() → size_t`` for operations that produce output

Contexts needing extra ``Init`` parameters (e.g., IV for encrypt/AEAD) hide
the base ``Init()`` with a more specific signature.

Context Reuse via Reset()
^^^^^^^^^^^^^^^^^^^^^^^^^

All streaming contexts (hash, encrypt, decrypt, sign, verify, MAC, AEAD)
support in-place reuse through ``Reset()``, declared on
``IStreamingContext``:

.. code-block:: cpp

   virtual Result<std::monostate> Reset() = 0;

``Reset()`` returns the context to its **post-construction** state,
clearing the streaming state machine and any accumulated intermediate
data while preserving:

- The key binding established at context creation
- The algorithm and provider selection
- The configuration (including per-context timeout overrides)

**Reuse lifecycle**::

   Init() → Update()* → Finalize() → Reset() → Init() → ...

**State-machine rules**:

- ``Reset()`` is valid after ``Finalize()`` / ``SignFinalize()`` /
  ``VerifyFinalize()`` / ``VerifyAndFinalize()``, or mid-stream
  (aborting the current sequence).
- ``Reset()`` on an already-idle context (post-construction or
  post-Reset) is a no-op that returns success.
- ``Reset()`` on a destroyed context returns
  ``kContextAlreadyDestroyed``.
- On failure the context transitions to error state; the caller should
  destroy and recreate the context via the factory.

**Error code**: ``kContextResetFailed`` is returned
when the daemon cannot clear the context's internal state.

Device Binding
--------------

``CryptoResourceId::primary_provider`` (``uint16_t``) identifies the owning
device/provider. This embeds device binding directly in the handle so any
code holding a reference knows which provider owns the resource without a
daemon round-trip.

Access Control
--------------

``ICryptoContext::ResolveResource()`` enforces per-application ACL based on
uid. The same ``ResourceId`` string may resolve to different
``CryptoResourceId`` handles for different application instances.

The library transparently passes caller identity to the daemon during
connection setup. The daemon's per-application configuration defines which
resources (key slots, certificate slots, trust anchors) each application
identity is permitted to access.

Key Operation Permission Model
------------------------------

Beyond access control (which controls *who* may use a resource), the API
enforces **per-key operation permissions** — controlling *what* a key may
do. This implements the principle of least privilege: a key provisioned
for signing cannot be misused for encryption, and vice versa.

**Permission bitmask:**

``KeyOperationPermission`` is a ``uint32_t`` bitmask grouped by
operation category:

.. code-block:: none

   Data protection  (bits 0–3):  kEncrypt, kDecrypt, kWrap, kUnwrap
   Authentication   (bits 4–7):  kSign, kVerify, kMac, kAgree
   Key lifecycle    (bits 8–10): kDerive, kExport, kImport

Composite presets are provided for common deployment patterns:

- ``kDataProtection`` = encrypt + decrypt + wrap + unwrap
- ``kAuthentication`` = sign + verify + mac + agree
- ``kFullLifecycle`` = derive + export + import
- ``kAll`` = all operations permitted (default)
- ``kNone`` = storage-only key (no operations)

**Permission sources:**

1. **Slot-provisioned permissions**: Each key slot has a
   ``permitted_operations`` field set during daemon-side provisioning.
   When a key is loaded from a slot (either via ``LoadKey()`` or the
   slot-direct path), the key inherits the slot's permissions.

2. **Generation-time permissions**: ``GenerateKeyParams``, ``ImportKeyParams``,
   and ``UnwrapKeyParams`` include a ``permissions`` field
   (defaults to ``kAll``). This constrains the ephemeral key at
   creation time.

3. **Persist-time validation**: When an ephemeral key is persisted to
   a slot via ``PersistKey()``, the daemon validates that the key's
   permissions are a subset of the target slot's
   ``permitted_operations``. If not, the persist fails with
   ``kKeyOperationNotPermitted``.

**Enforcement:**

Permissions are enforced by the daemon at context creation time. Each
``Create[Op]Context()`` method maps to a required permission:

.. code-block:: none

   CreateCipherContext(kEncrypt)          → kEncrypt
   CreateCipherContext(kDecrypt)          → kDecrypt
   CreateSignContext()                    → kSign
   CreateVerifySignatureContext()         → kVerify
   CreateMacContext()                     → kMac
   CreateAeadContext(kEncrypt)            → kEncrypt
   CreateAeadContext(kDecrypt)            → kDecrypt
   WrapKey()                              → kWrap (on wrapping key)
   UnwrapKey()                            → kUnwrap (on wrapping key)
   DeriveKey()                            → kDerive (on source key)
   ExportKey()                            → kExport
   AgreeKey()                             → kAgree

If the key's permissions do not include the required operation, the
daemon returns ``CryptoErrorCode::kKeyOperationNotPermitted`` and the
context is not created. This is a fail-fast check — no resources are
allocated on permission violation.

**Querying permissions:**

Permissions can be queried at runtime via:

- ``IKeySlotObject::GetPermittedOperations()`` — slot-level policy
- ``IKeyObject::GetPermittedOperations()`` — effective key permissions
- ``KeySlotInfo::permitted_operations`` field
- ``HasPermission(granted, required)`` — convenience predicate

.. code-block:: cpp

   auto slot_obj = ctx->GetKeySlotObject(slot).value();
   auto perms = slot_obj->GetPermittedOperations();
   if (HasPermission(perms, KeyOperationPermission::kSign)) {
       // This key can be used for signing
   }

Configuration Model
-------------------

The system uses a two-tier configuration model:

1. **Daemon configuration** (loaded at daemon startup):

   - Provider enumeration and hardware capability discovery
   - Per-provider configuration (device paths, library paths)
   - System-wide security policy

2. **Per-application configuration** (loaded per connection):

   - Resource mappings (string → slot/provider bindings)
   - Memory quotas (max allocation per application)
   - Accessible key slots and certificate slots
   - Trust anchor assignments
   - Provider preferences

``CreateCryptoStack(CryptoStackConfig)`` is the entry point; connection
management is internal.

Config Extensibility Contract
-----------------------------

All configuration structs (``CryptoStackConfig`` and all per-operation
context configs) follow the same backward-compatible extensibility pattern:

- **Default-constructible** — no positional constructor arguments. All
  construction via default constructor + fluent builder setters.
- **Fluent builder setters** (``Set...() → Config&``) are the only way to
  populate fields — callers who don't call new setters get default behavior
  automatically.
- **Adding new optional fields never breaks existing call sites**
  (source-compatible). Existing code continues to compile and behave
  identically.

Provider Auto-Resolution
-------------------------

When ``provider`` is omitted from a context config but a ``key`` is
specified, the daemon auto-resolves the provider from
``CryptoResourceId::primary_provider`` of the key.

Certificate Lifecycle
---------------------

**ICertificateManagementContext** handles the full certificate lifecycle:

- **Parsing**: ``ParseCertificate()`` returns an ``ICertificateObject::Uptr`` with
  field accessors (subject, issuer, serial, validity dates, algorithm). The object
  is backed by a daemon-assigned ephemeral ``CryptoResourceId``.
- **Persistence**: ``SaveCertificate(id, slot)`` promotes a parsed certificate to a slot
  (copy semantics — the parsed object remains valid after the call)
- **Export**: ``GetCertificateExportSize()`` + ``ExportCertificate()`` two-call pattern
- **CRL**: ``ImportCrl()``, ``DeleteCrl()``, ``DeleteExpiredCrls()`` for offline revocation
- **Key extraction**: ``LoadCertificatePublicKey()`` extracts the public key
  as a ``CryptoResourceGuard`` wrapping an ephemeral ``CryptoResourceId``
  with ``type == kKey``, following the same guard model as key-producing methods.
  Use ``ICryptoContext::GetKeyObject()`` for specialized key property queries.
- **OCSP**: ``GetOcspRequestData()`` generates a request; the response is
  consumed via ``ICertificateVerificationContext::SetOcspResponse()``

**ICertificateVerificationContext** provides builder-style chain verification:

- ``SetCertificate()``, ``SetCertificateChain()``, ``SetVerificationTrustStore()``, ``SetAdditionalTrustAnchors()``
- ``SetRevocationCheckPolicy()`` with CRL, OCSP, or combined strategies
- ``Verify()`` executes the configured verification

**ICsrGenerationContext** provides builder-style CSR generation:

- ``SetSubjectKey()``, ``SetSignatureAlgorithm()``, ``SetSubjectDn()``
- ``AddSubjectAltName()`` for SAN extensions
- ``Generate()`` produces an ``ICsrExport`` with encoded CSR bytes

IPC Transport
-------------

The IPC transport (control plane serialization, encoding, protocol
negotiation) is an internal implementation concern **outside the scope of
this user-facing API**. The API layer defines only the logical interfaces;
the IPC layer will be addressed separately.

Operation Timeout and Deadline
------------------------------

Every IPC call to the daemon is bounded by a configurable per-call
deadline to ensure deterministic behavior (ISO 26262 SA2) and graceful
degradation (SA5).

**Two-layer timeout model:**

1. **Stack-level default** via
   ``CryptoStackConfig::SetDefaultOperationTimeout(ms)``:
   Applies to *all* IPC calls on this stack — ``ResolveResource()``,
   ``Create[Op]Context()``, ``Init()``, ``Update()``, ``Finalize()``,
   ``QueryCapabilities()``, etc. When ``std::nullopt`` (default), the
   daemon applies its own built-in default (implementation-defined,
   typically 5000 ms).

2. **Per-context override** via ``BaseContextConfig``:
   ``SetOperationTimeout(ms)`` overrides the stack default for a
   specific context. ``DisableTimeout()`` removes the deadline entirely
   (the context waits indefinitely). ``EnableTimeout()`` re-enables it.

**Effective timeout resolution:**

.. code-block:: none

   if (config.timeout_enabled == false)
       → no deadline (infinite wait)
   else if (config.operation_timeout.has_value())
       → config.operation_timeout
   else if (stack_config.default_operation_timeout.has_value())
       → stack_config.default_operation_timeout
   else
       → daemon built-in default

**Timeout semantics:**

- The timeout applies **per-IPC-call**, not per streaming sequence.
  Each ``Init()``, ``Update()``, ``Finalize()`` has its own deadline.
  For ``SingleShot()``, the timeout covers the single IPC call.
- On timeout, the operation returns
  ``CryptoErrorCode::kOperationTimedOut`` and the context transitions
  to an error state. Subsequent calls return ``kInvalidOperation``.
  The context must be destroyed and recreated.
- Implementation must use ``std::chrono::steady_clock`` (monotonic) to
  be immune to NTP and wall-clock adjustments.

**Daemon-side enforcement (architectural constraint):**

The deadline is **enforced by the daemon**, not by the client library.
This is an architectural requirement — not merely an implementation
detail — because only the daemon owns the resources that need cleanup
on timeout:

1. **Deadline propagation**: The client library propagates the
   resolved deadline to the daemon as IPC-level metadata (e.g., gRPC
   deadline). The daemon receives and enforces it.

2. **Daemon-side checks**: The daemon checks the deadline at key
   decision points during operation processing:

   - Before dispatching to a crypto provider
   - Between provider calls for multi-step operations
   - Before allocating or modifying resources

   If the deadline has expired, the daemon aborts immediately without
   performing the operation.

3. **Resource cleanup on timeout**: When the daemon aborts due to
   deadline expiration, it is responsible for:

   - Zeroing and releasing any intermediate key material
   - Releasing provider handles and locks
   - Reclaiming any allocated shared memory
   - Transitioning the server-side context state to ``kError``

   This is the same cleanup path as context destruction, ensuring no
   resources are orphaned.

4. **Client-side role**: The client library's only responsibility is
   to propagate the deadline and interpret the daemon's timeout
   response (``kOperationTimedOut``). The client does **not** perform
   independent timer-based cancellation — the daemon is the single
   source of truth.

5. **IPC backend contract**: Any IPC transport used by this
   architecture (gRPC, shared-memory IPC, SOME/IP) must support
   deadline propagation from client to daemon. This is an
   architectural constraint on the IPC layer.

This daemon-side enforcement model provides a stronger safety guarantee
than client-side timeout alone: it ensures that even if the client
process crashes or is preempted after sending a request, the daemon will
still abort the operation after the deadline expires and clean up all
associated resources.

**Disabling timeout:**

Certain operations are legitimately long-running and should not be
interrupted:

- PQC key generation on hardware tokens (ML-KEM, ML-DSA)
- HSM-backed key agreement or unwrapping
- Certificate chain verification with online OCSP

For these, use ``config.DisableTimeout()`` on the relevant context
config. Document the rationale in the safety case when using
``DisableTimeout()`` in safety-relevant applications, as it removes
the WCET bound.

.. code-block:: cpp

   // Stack-wide 500 ms deadline
   CryptoStackConfig stack_config;
   stack_config.SetConnectionEndpoint("unix:///var/run/crypto-daemon.sock")
               .SetDefaultOperationTimeout(std::chrono::milliseconds{500});

   // Per-context override: 200 ms for hash, disabled for key gen
   HashContextConfig hash_cfg;
   hash_cfg.SetAlgorithm("SHA-256")
           .SetOperationTimeout(std::chrono::milliseconds{200});

   KeyManagementContextConfig keygen_cfg;
   keygen_cfg.DisableTimeout();  // PQC key generation may take seconds

Rationale Behind Architecture Decomposition
--------------------------------------------

The architecture is decomposed along three axes:

1. **Control plane vs. data plane**: Memory allocation
   (``IMemoryAllocator``) is separated from the control plane
   (``ICryptoContext``, operation contexts) because (a) it is
   architecturally independent, (b) it can be passed independently to
   components needing only memory, and (c) it enables isolated unit
   testing of memory management.

2. **Common types vs. operation contexts**: Common types, error domain,
   and memory interfaces are in ``common/`` with no dependencies on
   operation-specific code. This enables minimal-dependency compilation
   units and independent unit testing.

3. **Base hierarchy vs. concrete contexts**: Three base interfaces
   (``IContext``, ``IStreamingContext``, ``IStreamingOutputContext``)
   capture shared streaming behavior, while concrete contexts add
   operation-specific methods. Configs are separated into ``config/``
   to decouple configuration from the interfaces they parameterize.
