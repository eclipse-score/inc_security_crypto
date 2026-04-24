..
    # =============================================================================
    #  C O P Y R I G H T
    # -----------------------------------------------------------------------------
    #  Copyright (c) 2026 by ETAS GmbH. All rights reserved.
    #
    #  The reproduction, distribution and utilization of this file as
    #  well as the communication of its contents to others without express
    #  authorization is prohibited. Offenders will be held liable for the
    #  payment of damages. All rights reserved in the event of the grant
    #  of a patent, utility model or design.
    # =============================================================================

.. _crypto_design_decisions:

Design Decisions
================

ABI Compatibility for IPC Layer (Deferred Post-Stabilisation)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: ABI Compatibility for IPC Layer (Deferred Post-Stabilisation)
   :id: dec_rec__crypto__no_abi_compatibility_ipc
   :status: proposed
   :context: doc__crypto_architecture
   :decision: ABI compatibility for the IPC layer between the crypto library and daemon is deferred until the API and wire format are stable. Once stable, a versioned wire format (FlatBuffers is the primary candidate) will be introduced to allow independent deployment of library and daemon versions.

   .. :affects: comp__crypto

ABI compatibility for the IPC layer between the crypto library and daemon is
deferred until the API and wire format are stable. Once stable, a versioned wire
format (FlatBuffers is the primary candidate) will be introduced to allow
independent deployment of library and daemon versions.

Context
-------

The crypto module uses an IPC layer to communicate between the client library and
the daemon process. During initial development, maintaining strict ABI compatibility
would impose versioning overhead (protocol negotiation, backward/forward compatibility
handling) before the interfaces are settled. The decision is therefore to defer ABI
compatibility until the stack is stable, at which point the investment is justified.

Once the API and wire format are frozen, the following will be required:

* A versioned wire format with forward/backward compatibility guarantees
* Protocol negotiation mechanisms during connection establishment
* Support for a defined compatibility window (e.g., N−1 daemon with N library)
* Regression testing across supported version combinations

Decision
--------

ABI compatibility for the IPC layer is intentionally deferred for the initial
pre-stable phase. Per machine, only one valid library-daemon combination is
supported until the API stabilises. After stabilisation, a versioned wire format
will be introduced — this decision will be revisited and finalised at that point.

Consequences
------------

**Positive:**

* Simplified implementation during pre-stable phase — no protocol versioning overhead
* Reduced testing surface — only matching version pairs need validation
* Faster initial development cycle — breaking changes can be made freely
* Clearer deployment model for early adopters — single version per machine

**Negative:**

* Library and daemon must currently be updated together as a single unit
* Cannot have multiple applications using different library versions on the same machine
* No graceful degradation when versions mismatch during the deferred phase

Alternatives Considered
-----------------------

FlatBuffers
^^^^^^^^^^^

FlatBuffers is the primary candidate for the versioned wire format once
stabilisation is reached.

Advantages
""""""""""

* **Schema evolution** — fields can be added with default values without breaking
  existing serialised data; removed fields leave a gap that is safely skipped.
* **Zero-copy access** — FlatBuffers tables are accessed in-place from the
  shared-memory buffer, aligning with the ``IMemoryAllocator`` zero-copy design.
* **Deterministic layout** — table format is fully specified; no hidden heap
  allocation during access.
* **Compact code generation** — generated C++ headers are ``noexcept``-friendly
  and free of ``std::function`` or ``std::string`` members.

Disadvantages
"""""""""""""

* Final choice is deferred; other candidates (Protocol Buffers, Cap'n Proto,
  hand-rolled length-prefixed structs) are not excluded.

Justification for the Decision
------------------------------

The decision to defer ABI compatibility is justified by the current pre-stable phase
of development. Introducing versioning infrastructure before the interfaces are settled
would add maintenance burden without benefit. The FlatBuffers candidate and this
record preserve the intent and analysis so that the versioning work can proceed
efficiently once the stack stabilises.

---

CryptoResourceGuard Lifetime via Daemon-Side Reference Counting
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: CryptoResourceGuard Lifetime via Daemon-Side Reference Counting
   :id: dec_rec__crypto__cry_res_grd_lifetime
   :status: accepted
   :context: doc__crypto_architecture
   :decision: Transient key lifetime is managed exclusively in the daemon via reference counting. The guard holds a type-erased IPC release handle; Create*Context() increments the daemon ref-count atomically. The guard may be destroyed after Create*Context() returns. On client disconnect, the daemon bulk-frees all resources for that client.

   .. :affects: comp__crypto

Transient key lifetime is managed exclusively in the daemon. The daemon ref-counts
every ephemeral key; the client communicates changes via two IPC calls:
``Release(id)`` (guard destructor) and ``Create*Context(config with key_id)``
(context creation).

Context
-------

Transient crypto resources (keys, certificates) produced within an
``IKeyManagementContext`` or ``ICertificateManagementContext`` session are represented by a
``CryptoResourceGuard``. Key lifetime must survive all contexts actively using the
key and be freed deterministically when neither a guard nor a context holds a
reference.

Decision
--------

Key lifetime is managed in the daemon via a per-key reference count:

.. list-table::
   :header-rows: 1
   :widths: 55 45

   * - Event
     - Daemon action
   * - ``GenerateKey`` / ``DeriveKey`` / ``LoadKey`` / etc.
     - Creates key; ref = 1
   * - ``Create*Context(config with key_id)``
     - Validates key alive; ref++
   * - Guard destroyed (``Release(id)`` IPC)
     - ref--; free key if ref == 0
   * - Context destroyed
     - ref-- for each bound key
   * - Client disconnect (crash or normal exit)
     - Daemon bulk-frees all resources for that client

This means:

- The guard carries only the ``CryptoResourceId``
  and a type-erased IPC release handle (``shared_ptr<void>`` internally).
- ``Create*Context()`` sends a single IPC call that validates the key and atomically
  records context ownership. If the guard was released before this call, the daemon
  returns ``kResourceNotFound`` — fail-fast, diagnosable behaviour.
- **Crash safety**: on hard process termination (SIGKILL, power loss), no
  destructors run. The daemon detects the client disconnect and bulk-frees all
  resources. Daemon-side ref-counting is crash-safe by design.
- ``BaseContextConfig`` carries only a ``CryptoResourceId`` for the key.

**Application contract**: The guard must remain alive (``IsActive()`` returns true)
at the moment ``Create*Context()`` is called. After that call returns successfully,
the guard may be destroyed in any order relative to the context.

.. code-block:: cpp

  auto key = key_mgmt->GenerateKey("AES-256").value();
  CipherContextConfig config;
  config.SetAlgorithm("AES-256-GCM").SetKey(key).SetDirection(CipherDirection::kEncrypt);
  // guard must be alive here:
  auto cipher = ctx->CreateCipherContext(config).value();
  // Daemon has incremented the key ref-count. Guard may now be destroyed.
  // ... use cipher ...

Explicit Release and Guard Synchronisation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The daemon is the sole source of truth for resource validity.
The guard's ``active_`` flag is a client-side hint, not a daemon query.

**Normal path — destructor** (no application code needed):

The guard destructor sends ``Release(id)`` IPC when active, silently
swallowing the result (destructors cannot propagate errors).

**Explicit path — synchronous error handling**:

When the application needs to explicitly confirm release before destruction, call
``guard.Release()``:

.. code-block:: cpp

   auto result = guard.Release();  // explicit, returns Result<std::monostate>
   if (result.has_value()) {
       // no-op destructor
   }

**Persist path — copy semantics**:

``IKeyManagementContext::PersistKey(const CryptoResourceId&, slot)`` takes the
ephemeral key by ID (copy semantics). The guard that produced the ID remains
active after ``PersistKey`` returns. The ephemeral copy continues to exist until
the guard is released or goes out of scope; the persisted slot copy is
independent:

.. code-block:: cpp

   auto key = key_mgmt->GenerateKey((GenerateKeyParams{}.SetAlgorithm("AES-256"))).value();
   key_mgmt->PersistKey(slot, key).value();  // key (guard) remains active
   // 'key' still holds the ephemeral copy — explicit Release() or destructor frees it
   // 'slot' is the persistent copy — use slot handle for all future durable operations


``SetKey`` and Implicit Guard Conversion
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``CryptoResourceGuard`` provides an implicit conversion operator to
``const CryptoResourceId&``. All key-accepting config structs expose a single
``SetKey(const CryptoResourceId& k)`` overload. Passing a guard works directly
via this conversion — no extra overload is needed:

.. code-block:: cpp

  auto key = key_mgmt->GenerateKey((GenerateKeyParams{}.SetAlgorithm("AES-256"))).value();
  // guard must be alive when CreateCipherContext is called:
  auto cipher = ctx->CreateCipherContext(
      CipherContextConfig{}.SetAlgorithm("AES-256-GCM").SetKey(key)
                            .SetDirection(CipherDirection::kEncrypt)).value();
  // Daemon incremented key ref-count. Guard may now be independently destroyed.

  cipher->Init(iv);
  cipher->Finalize(out_span);

Consequences
------------

**Positive:**

* Single source of truth for key lifetime: the daemon. No client-side
  ``shared_ptr`` propagation across API boundaries.
* Crash-safe: daemon bulk-frees on disconnect regardless of client destructor state.
* Fail-fast: releasing a guard before ``Create*Context`` is called returns
  ``kResourceNotFound`` — diagnosable, deterministic behaviour.
* ``BaseContextConfig`` carries only ``CryptoResourceId`` — minimal and flat.

**Negative:**

* Guards must remain alive until ``Create*Context()`` returns — an intuitive
  but explicit application contract.
* Daemon must maintain per-key ref-counts for all active ephemeral keys.
  Memory cost is bounded by max concurrent keys (deployment-time constant).

---

Shared-Connection Anchor for Persistent Resource ID Stability
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Shared-Connection Anchor for Persistent Resource ID Stability
   :id: dec_rec__crypto__conn_anchor_persistent_ids
   :status: accepted
   :context: doc__crypto_architecture
   :decision: The IPC connection to the crypto daemon is the anchor for kPersistent resource IDs. All ICryptoStack instances within the same application share a single connection, ensuring that the same resource name always resolves to the same numeric CryptoResourceId regardless of which stack or context resolves it. ID assignment is on-demand per connection, and each application gets its own isolated connection with an independent ID namespace.

   .. :affects: comp__crypto

The application-level daemon connection is a shared anchor across all
``ICryptoStack`` instances within the same application. Persistent resource IDs
(``kPersistent``) are assigned on-demand per connection and remain stable for the
connection's lifetime, independent of any individual ``ICryptoContext``.

Context
-------

Persistent resources (key slots, stored certificates, CRLs) outlive any
individual context or session. Tying the validity of their ``CryptoResourceId``
handle to the lifetime of a specific ``ICryptoContext`` would couple context
lifetime management to resource identifier validity unnecessarily. The desired
property is that a resolved persistent ID remains usable as long as the
application is connected to the daemon — independent of which context or stack
resolved it.

Decision
--------

The **connection** (the underlying transport connection to the crypto daemon)
is the anchor for ``kPersistent`` resource IDs:

* All ``ICryptoStack`` instances within the same application share a single
  connection. Multiple stacks always resolve the same resource name to the
  same numeric ``CryptoResourceId``.
* ID assignment is **on-demand**: a numeric ``id`` is assigned when a resource
  is first resolved by any stack on the connection. Subsequent resolutions of
  the same name by any stack return the identical ``id``.
* Each application gets its own isolated connection with an independent ID
  namespace — IDs are not globally stable across application restarts or
  across different applications. This preserves the security property:
  IDs are per-application-unique and not externally predictable.
* Connection ID tracking is managed by the underlying IPC transport layer
  as an implementation detail, not exposed to library users.

Lifetime Strategy (Deployment Choice)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The connection lifetime is a deployment-level choice between two strategies:

1. **Reference-counted (early cleanup):** Connection is destroyed when the last
   ``ICryptoStack`` referencing it is destroyed. Daemon-side resources are
   freed immediately. Suitable when stacks are short-lived and memory
   footprint must be minimised.
2. **Fixed (application lifetime):** Connection is created once at application
   startup and destroyed when the application terminates. Daemon resources
   are held in daemon memory for the application lifetime. Simpler to reason
   about; preferred when stacks are frequently created and destroyed.

Both strategies are implementation details of the transport layer — the
public ``ICryptoStack`` and ``ICryptoContext`` API is identical in either case.
Cross-application connection sharing is **not allowed**;
``IConnectionAnchor`` remains a private implementation type.

Scope
^^^^^

Applies to ``kPersistent`` resources only: ``kKeySlot``, ``kCertificate``,
``kCertSlot``, ``kVerificationTrustStore``. Ephemeral (``kKey``) IDs remain session-scoped
(valid only within the ``IKeyManagementContext`` session that produced them).

IPC Schema
^^^^^^^^^^

Whether per-connection ID assignment and the registry require new proto
messages or can reuse the existing ``CryptoResourceId`` wire format is an
open implementation item for the daemon development to resolve before the
daemon is built.

Consequences
------------

**Positive:**

* Independent context lifetime for persistent resources — ``ICryptoContext``
  can be destroyed after resolution without invalidating the ``CryptoResourceId``.
* Stable, deterministic IDs within an application — same name always resolves
  to the same ``id`` regardless of which stack or context resolves it.
* No security leakage — IDs are per-application-unique, on-demand assigned,
  not globally stable or predictable from outside the application.
* Applications can share resolved ``CryptoResourceId`` values between stacks
  without re-resolving.

**Negative:**

* Daemon must maintain a per-connection ID registry (map from resource name
  to numeric ``id``). Memory cost is bounded by the number of distinct
  persistent resources accessed per application.
* With fixed-lifetime strategy: daemon memory for resolved IDs is held for
  the entire application lifetime even if the IDs are no longer used.

---

``AlgorithmId`` as ``FixedCapacityString<64>``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: AlgorithmId Represented as FixedCapacityString<64>
   :id: dec_rec__crypto__alg_id_fixed_cap_str
   :status: accepted
   :context: doc__crypto_architecture
   :decision: ``AlgorithmId`` is defined as ``FixedCapacityString<64>`` rather than a compile-time enum or std::string, providing open-set extensibility with deterministic stack allocation. 64 bytes covers the longest currently-known PQC identifier (e.g., "SLH-DSA-SHA2-128s") with comfortable headroom. All constructors and assignments are noexcept.

   .. :affects: comp__crypto

``AlgorithmId`` is defined as ``FixedCapacityString<64>`` rather than a
compile-time enum or ``std::string``, providing open-set extensibility with
deterministic stack allocation.

Context
-------

Algorithm identifiers must accommodate current algorithms (e.g., ``"AES-256-GCM"``,
``"SHA-256"``, ``"SLH-DSA-SHA2-128s"``), future PQC schemes, and provider-specific
extensions — an open set that cannot be enumerated at compile time.

Decision
--------

Three candidate representations were evaluated:

1. **``enum class AlgorithmId``** — type-safe, zero overhead, but a *closed* set.
   Adding a new PQC algorithm requires recompiling the library and all callers.
   Incompatible with the extensibility goal and with runtime-configured providers.

2. **``std::string``** — open set, but heap-allocating. Every ``AlgorithmId`` value
   creates at least one heap allocation. Violates MISRA A18-5-1, incompatible with
   ASIL ``noexcept`` destructors, and introduces non-deterministic WCET.

3. **``FixedCapacityString<64>``** — open set, stack-allocated, exception-free
   (oversized input silently truncated, ``truncated()`` flag set). 64 bytes covers
   the longest currently-known PQC identifier (``"SLH-DSA-SHA2-128s"`` = 18 chars)
   with comfortable headroom. All constructors and assignments are ``noexcept``.

``FixedCapacityString<64>`` (option 3) was selected. The same rationale applies to
``ResourceId`` (``FixedCapacityString<64>``) and ``ProviderInfo::name``
(``FixedCapacityString<32>``).

Consequences
------------

**Positive:**

* Zero heap allocation for any algorithm or resource identifier.
* Open set — new PQC algorithms deploy at daemon level; no library recompile needed.
* ``noexcept`` constructors and assignments — compatible with ASIL containers.
* ``GetAlgorithm()``, ``GetAllowedAlgorithm()``, ``GetPublicKeyAlgorithm()`` are
  now ``const noexcept``, enabling use in safety-annotated code.

**Negative:**

* 64-byte fixed storage regardless of actual string length (minor waste for short names).
* Silent truncation on overflow — callers must check ``truncated()`` when constructing
  from untrusted input.
* No compile-time algorithm validation — typos become runtime errors.

---

Synchronous-Only IPC Model
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Synchronous-Only IPC Model
   :id: dec_rec__crypto__synchronous_ipc
   :status: accepted
   :context: doc__crypto_architecture
   :decision: All IPC calls between the client library and the crypto daemon are synchronous (blocking). No callback, future, or async-notify pattern is exposed in the V1 public API.

   .. :affects: comp__crypto

All IPC calls between the client library and the crypto daemon are synchronous
(blocking). No callback, future, or async-notify pattern is exposed in the V1
public API.

Context
-------

A synchronous model blocks the calling thread for the full IPC round-trip plus
provider execution. The alternatives introduce heap usage, threading complexity,
or event-loop coupling that are incompatible with MISRA and automotive middleware
requirements.

Decision
--------

All IPC calls are synchronous (blocking). Asynchronous alternatives were evaluated
and rejected:

* **Future/Promise API** — ``Result<std::future<T>>`` return types, daemon uses a
  worker-thread pool. This would result in higher code complexity.
* **Callback model** — caller provides a ``std::function<void(Result<T>)>`` invoked
  on completion. ``std::function`` violates MISRA A18-5-1 (heap). Custom fixed-size
  delegate types possible but add significant complexity.
* **Polling / event-loop** — caller polls a completion token. Couples the crypto API
  to the application event loop; not idiomatic for automotive middleware.

Consequences
------------

**Positive:**

* Simple, predictable call semantics — no threading model imposed on callers.
* Full ``Result<T>`` error propagation on every call.
* MISRA-compliant — no ``std::function``, no heap, no thread creation in library.
* Operation timeouts (``dec_rec__crypto__two_layer_timeout``) provide bounded
  blocking behaviour — the calling thread never blocks indefinitely.

**Negative:**

* Thread blocks for full operation duration including IPC + provider execution.
* Potential priority inversion in RTOS environments with high-priority callers.
* Cannot pipeline or batch multiple crypto operations.
* Future async API (``GenerateKeyAsync``) must be added as an extension;
  The daemon-side ref-count model (see ``dec_rec__crypto__cry_res_grd_lifetime``)
  naturally accommodates async key generation: the daemon can atomically bind the
  key to the context when the async result is consumed.

---

Context ``Reset()`` for Streaming Context Reuse
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Context Reset() for Streaming Context Reuse
   :id: dec_rec__crypto__context_reset_reuse
   :status: accepted
   :context: doc__crypto_architecture
   :decision: ``IStreamingContext`` exposes a ``Reset()`` method returning the context to

   .. :affects: comp__crypto

``IStreamingContext`` exposes a ``Reset()`` method returning the context to
post-construction state after ``Finalize()``, preserving key, algorithm, and config
bindings. This avoids repeated factory + IPC overhead for same-configuration
repeated operations.

Context
-------

Streaming contexts (hash, sign, verify, encrypt, decrypt, MAC, AEAD) follow the
``Init()`` → ``Update()`` * → ``Finalize()`` state machine. Without reuse, each
new operation requires: (1) ``ICryptoContext::Create*Context()`` IPC call,
(2) ``Init()`` IPC call. For high-frequency operations (e.g., per-frame hashing,
per-message MAC), this doubles the IPC overhead.

Decision
--------

``Reset()`` is added to ``IStreamingContext``. Alternatives evaluated:

* **Destroy and re-create** — simplest, but doubles IPC cost per operation.
* **``Reset()`` on ``IStreamingContext``** — single IPC call to the daemon to clear
  provider-side state; key, algorithm, config, and session handle remain valid.
  State machine transitions: ``kFinalized`` → ``kCreated`` on success.
  ``kContextResetFailed`` (``0x01070003``) reported on daemon-side failure.
* **Context pooling in the library** — a pool of pre-created contexts returned to
  callers. Adds ~200 LOC of pool management, thread-safety concerns, and a fixed
  pool bound that may be too large or too small for different deployments.

Consequences
------------

**Positive:**

* Halves IPC round-trips for high-frequency same-configuration operations.
* No API surface change — ``Reset()`` is additive; callers that destroy and
  re-create continue to work unchanged.
* Key, algorithm, and config bindings preserved — no re-configuration needed.
* Single additional error code (``kContextResetFailed``) for daemon failure path.

**Negative:**

* Daemon must track context state and clear provider-side buffers on ``Reset()``.
* Callers must ensure ``Finalize()`` is called before ``Reset()``; calling
  ``Reset()`` in ``kUpdating`` state returns ``kInvalidOperation``.

---

Two-Layer Per-Call Timeout with Daemon-Side Enforcement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Two-Layer Per-Call Timeout with Daemon-Side Enforcement
   :id: dec_rec__crypto__two_layer_timeout
   :status: accepted
   :context: doc__crypto_architecture
   :decision: Two-layer timeout model selected for bounded behaviour at both layers.

   .. :affects: comp__crypto

Operation timeouts are enforced at two layers — a stack-wide default in
``CryptoStackConfig`` and a per-context override in ``BaseContextConfig`` with an
explicit ``DisableTimeout()`` escape — with the daemon as the enforcement point.
Client threads unblock on timeout; timed-out contexts transition to ``kError``.

Context
-------

Without timeouts, a hung HSM or stalled IPC channel blocks the calling thread
indefinitely — a safety violation for ISO 26262 ASIL functions. A single global
timeout is insufficient because some legitimate operations (e.g., RSA-4096 key
generation on software providers) require more time than typical operations.
Client-side-only timeouts fail to release daemon-held resources when the deadline
expires.

Decision
--------

Three timeout models were evaluated:

1. **Client-side only (``std::future::wait_for``)** — client unblocks after
   deadline, but the daemon continues executing the stalled operation, holding
   the resource. Does not provide bounded daemon resource usage.

2. **Daemon-side only (watchdog thread per context)** — daemon kills stalled
   operations after timeout and notifies client via error response. Provides
   bounded resource usage but requires the daemon to maintain one watchdog
   timer per in-flight context.

3. **Two-layer: client deadline + daemon enforcement** — client passes
   timeout value on each IPC call; daemon enforces the deadline server-side.
   If deadline expires, daemon transitions context to error, releases provider
   resources, and returns ``kOperationTimedOut`` to client. ``DisableTimeout()``
   is available for legitimately long operations (e.g., RSA-4096 key generation
   on software providers).

Model 3 was selected for bounded behaviour at both layers.

Consequences
------------

**Positive:**

* Guaranteed bounded execution — no call blocks indefinitely.
* Daemon-side enforcement means provider resources are released on timeout,
  not just the client thread.
* Per-context override allows fine-grained tuning without changing global config.
* ``DisableTimeout()`` supports legitimate long-running operations without
  disabling safety globally.
* Satisfies ISO 26262 Part 6 Table 1 (bounded execution time for safety functions).

**Negative:**

* Daemon must maintain a per-context deadline and cancel infrastructure.
* ``DisableTimeout()`` is a safety escape hatch; misuse (e.g., in Safety paths)
  must be justified in the application's safety case.
* Two-layer design adds complexity compared to a single global timeout.

---

``KeyOperationPermission`` as a Capability Bitmask
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: KeyOperationPermission as a Capability Bitmask
   :id: dec_rec__crypto__key_op_permission_bitmask
   :status: accepted
   :context: doc__crypto_architecture
   :decision: Per-key usage restrictions are encoded as a ``KeyOperationPermission`` bitmask (named bit-flag capabilities: ``kEncrypt``, ``kDecrypt``, ``kSign``, ``kVerify``, ``kDerive``, ``kWrap``, ``kExport``, ``kGenerate``). The daemon enforces the bitmask at context creation time; operations not permitted by the key's bitmask return ``kKeyOperationNotPermitted``.

   .. :affects: comp__crypto

Per-key usage restrictions are encoded as a ``KeyOperationPermission`` bitmask
(named bit-flag capabilities: ``kEncrypt``, ``kDecrypt``, ``kSign``, ``kVerify``,
``kDerive``, ``kWrap``, ``kExport``, ``kGenerate``). The daemon enforces the bitmask
at context creation time; operations not permitted by the key's bitmask return
``kKeyOperationNotPermitted``.

Context
-------

A key provisioned for signing must not be usable for encryption or export.
Enforcing usage restrictions at the API level prevents misuse even if the caller
has a valid resource handle. The representation must be heap-free and extensible
to support future operations without breaking existing code.

Decision
--------

Three designs were evaluated:

1. **``std::unordered_set<KeyOperation>``** — flexible but heap-allocating.
   Violates MISRA A18-5-1, incompatible with ASIL ``noexcept`` requirements.

2. **``KeyPermissions`` struct with boolean flags** — type-safe, stack-allocated,
   but verbose (one field per operation). Extending to a new operation requires
   a breaking ABI change.

3. **Bitmask (``uint32_t`` or ``enum class`` with ``operator|``)** — compact,
   heap-free, trivially copyable, extensible (new bits added without breaking
   existing code). Standard pattern in OS capability models (POSIX, seL4).

The bitmask (option 3) was selected for compactness and extensibility.

Consequences
------------

**Positive:**

* Compact representation — one ``uint32_t`` field in key metadata.
* Extensible — new operations add a new named bit; existing bitmasks remain valid.
* Daemon enforces at context creation — enforcement point is in the trusted boundary.
* Two-layer access control: *who* (``ResolveResource()`` ACL, uid) and
  *what* (``KeyOperationPermission`` bitmask per key).

**Negative:**

* Bitmask operations (``&``, ``|``, ``~``) are less type-safe than a method API;
  callers can accidentally construct invalid combinations.
* No runtime check that a bitmask value is a valid combination of named bits
  (mitigated by providing named constants and ``operator|`` overloads).

---

Unified Cipher Context (No Encrypt/Decrypt or Symmetric/Asymmetric Split)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Unified Cipher Context Rather Than Separate Encrypt/Decrypt Plus Symmetric/Asymmetric Split
   :id: dec_rec__crypto__unified_enc_dec_contexts
   :status: accepted
   :context: doc__crypto_architecture
   :decision: A single ``ICipherContext`` type is used for both encryption and decryption, with direction configured via ``CipherContextConfig``. Sign, verify, MAC, and AEAD are each separate context types under the ``IStreamingContext`` hierarchy. The algorithm identifier and key type determine whether the operation is symmetric or asymmetric at runtime. Separate ``SymmetricEncryptContext`` / ``AsymmetricEncryptContext`` types were rejected for increased complexity without benefit.

   .. :affects: comp__crypto

Encrypt and decrypt share a single ``ICipherContext`` (direction set via
``CipherContextConfig``). Sign, verify, MAC, and AEAD are each a separate context
type under the ``IStreamingContext`` hierarchy. The algorithm identifier and key
type determine whether the operation is symmetric or asymmetric at runtime.
Separate ``SymmetricEncryptContext`` / ``AsymmetricEncryptContext`` types were
rejected.

Context
-------

A split design creates a separate class per algorithm family. Adding PQC KEM
support requires a new class even if the streaming interface is identical. This
increases include weight and virtual dispatch hierarchy depth without benefit,
and makes the API surface grow with the algorithm set.

Decision
--------

Three designs were evaluated:

1. **Symmetric/Asymmetric split** — mirrors algorithm families at the type level.
   Callers must select the correct context type; runtime algorithm selection within
   a family is still possible. Adds N context types per new algorithm family.
   Increases include weight and virtual dispatch hierarchy depth.

2. **Unified context per operation** — ``ICipherContext`` (encrypt + decrypt unified),
   ``ISignContext``, ``IVerifySignatureContext``, ``IMacContext``, ``IAeadContext``.
   Algorithm and key type determine behaviour. Adding ML-KEM or ML-DSA requires
   no new context type — only a new algorithm name string and provider support.

3. **Single universal context** — one ``ICryptoOperationContext`` with a mode
   parameter. Rejects the SRP; makes misuse easier (e.g., calling ``Sign()`` on a
   context configured for encryption). Rejected for API clarity reasons.

Design 2 was selected for the balance of clarity and extensibility.

Consequences
------------

**Positive:**

* Flat, stable hierarchy — five concrete context types regardless of algorithm count.
* PQC extensibility — ML-KEM, ML-DSA, SLH-DSA require no new context types.
* Each context enforces its own state machine; misuse (e.g., ``Update()`` before
  ``Init()``) returns a typed error regardless of algorithm.
* Consistent ``Init()`` / ``Update()`` / ``Finalize()`` / ``Reset()`` pattern
  across all operations simplifies caller code.

**Negative:**

* Algorithm-specific overloads (e.g., ``ICipherContext::Init(iv)`` vs.
  ``IStreamingContext::Init()``) require ``using`` declarations to suppress
  name-hiding warnings (see §3.5 in the evaluation report).
* AEAD tag handling (``SetTag()`` / ``GetTag()``) cannot be expressed identically
  to non-AEAD operations — ``IAeadContext`` requires additional methods.

---

``IMemoryAllocator`` Separated from ``ICryptoStack``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: IMemoryAllocator Separated from ICryptoStack
   :id: dec_rec__crypto__memory_allocator_separation
   :status: accepted
   :context: doc__crypto_architecture
   :decision: ``IMemoryAllocator`` is a standalone interface independent of ``ICryptoStack``. It represents the data plane, can be injected into components that need only memory management, and enables isolated unit testing — none of which are possible if it is coupled to the control-plane ``ICryptoStack``.

   .. :affects: comp__crypto

``IMemoryAllocator`` is a standalone interface independent of ``ICryptoStack``.
It represents the data plane, can be injected into components that need only
memory management, and enables isolated unit testing — none of which are possible
if it is coupled to the control-plane ``ICryptoStack``.

Context
-------

The crypto module uses shared memory as the zero-copy data plane between the
application and the crypto daemon. A naive design would expose memory allocation
directly through ``ICryptoStack``, coupling the data plane to the control-plane
IPC object. Three reasons motivated a separate interface:

1. **Architectural independence of data plane and control plane** — the memory
   subsystem operates independently of IPC: buffers can be allocated, written,
   and passed to providers without any IPC call. Coupling allocation to
   ``ICryptoStack`` would obscure this separation.

2. **Independent injection** — components that need only memory management
   (e.g., a buffer pool, a serialiser) can receive an ``IMemoryAllocator``
   without depending on the full ``ICryptoStack`` interface. This is consistent
   with the Interface Segregation Principle and reduces unnecessary coupling
   in the component graph.

3. **Isolated unit testing** — by taking ``IMemoryAllocator`` as a dependency,
   individual components can be tested with a mock or stub allocator without
   standing up an ``ICryptoStack`` or a daemon connection.

Decision
--------

``IMemoryAllocator`` is defined as a standalone interface independent of
``ICryptoStack``. Applications obtain both objects separately; the memory allocator
is the data plane and the crypto stack is the control plane. Cross-application
connection sharing is not supported; each application has its own allocator instance.

Consequences
------------

**Positive:**

* Data-plane and control-plane concerns are visibly separated in the API.
* Components that allocate buffers do not depend on ``ICryptoStack``.
* Unit tests for memory-dependent components are cheaper and hermetic.
* The zero-copy path (``kProviderCompatible`` allocation) is a data-plane concern
  and sits cleanly on ``IMemoryAllocator`` without polluting ``ICryptoStack``.

**Negative:**

* Applications must obtain and manage two objects (``ICryptoStack`` + ``IMemoryAllocator``)
  where a monolithic interface would require only one.

---

Control Plane IPC Boundary Copy with Daemon-Internal Zero-Copy References
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Control Plane IPC Boundary Copy with Daemon-Internal Zero-Copy References
   :id: dec_rec__crypto__ipc_boundary_copy
   :status: accepted
   :context: doc__crypto_architecture
   :decision: The control plane IPC layer on the daemon side shall create exactly one owning copy of all incoming request data at the deserialization boundary. All subsequent daemon-internal processing shall operate on non-owning references into that single owned copy. This prevents time-of-check-time-of-use (TOCTOU) attacks on control information while minimising memory copies within the daemon. The data plane is explicitly excluded — it carries only opaque data payloads and may use zero-copy transfer.

The control plane IPC layer on the daemon side shall create exactly one owning
copy of all incoming request data at the deserialization boundary. All subsequent
daemon-internal processing shall operate on non-owning references into that single
owned copy. This prevents time-of-check-time-of-use (TOCTOU) attacks on control
information while minimising memory copies within the daemon. The data plane is
explicitly excluded — it carries only opaque data payloads and may use zero-copy transfer.

Context
-------

This decision applies to the **control plane** only — the channel carrying
operation requests, responses, and their parameters (key identifiers, algorithm
names, operation codes, session IDs, in-band data).

The **data plane** is **out of scope** and may use zero-copy (e.g., shared
memory). The data plane carries only opaque payloads (plaintext, ciphertext) —
not control information that the daemon validates or routes upon — so TOCTOU
modification cannot cause the daemon to mis-route an operation, use the wrong
key, or bypass access control. At worst the provider processes corrupted input,
equivalent to the client submitting bad data in the first place.

Control plane requests carry parameters from an untrusted client. The daemon
must decide whether to work directly from the transport buffer or copy first.

Consequences
------------

**Positive:**

* Eliminates TOCTOU on control information.
* One copy at ingress, zero through the handler chain, one at egress.
* Clear ownership — the request structure owns; all handlers borrow.
* Data plane stays zero-copy for bulk payloads.

**Negative:**

* Mandatory copy per control plane request, even when the transport buffer is
  safe (deliberate performance-for-security trade-off; overhead is small since
  the control plane carries only metadata and small in-band buffers).
* Two representations needed in the protocol types: owning types at the IPC
  boundary, non-owning views internally.

Alternatives Considered
-----------------------

1. **Zero-copy end-to-end** — read directly from the transport buffer. Vulnerable
   to TOCTOU: a client could swap a key ID or algorithm name between validation
   and use.

2. **Copy at every layer boundary** — excessive allocation; e.g., three copies of
   the same hash input across IPC adapter, mediator, and provider.

3. **Single copy at the control plane IPC boundary, references thereafter** — the
   deserialization layer copies all mutable parameters into daemon-owned memory.
   Downstream layers receive const references and use non-owning views.

Strategy 3 was selected.

Justification for the Decision
------------------------------

Control information determines *which* operation runs, *with which key*, *using
which algorithm*. If the daemon reads this from a buffer still writable by the
client, the client can mutate it between validation and use (TOCTOU). A single
owning copy at the IPC boundary makes the request immutable from the client's
perspective.

Non-owning references within the daemon are safe because:

* The owned request data outlives the entire synchronous processing chain.
* All downstream handlers receive it as const.
* Processing is single-threaded per request.

The data plane does not carry control information, so TOCTOU cannot redirect
operations — zero-copy is safe there by design.

---

Per-Operation Parameter Structs with Dual Overloads
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Per-Operation Parameter Structs with Dual Overloads
   :id: dec_rec__crypto__per_op_params
   :status: proposed
   :context: doc__crypto_architecture
   :decision: Key management operations (``GenerateKey``, ``DeriveKey``, ``AgreeKey``, ``UnwrapKey``, ``ImportKey``, ``WrapKey``) are encapsulated in dedicated fluent-builder parameter structs. Dual overloads support both ephemeral keys (returning ``CryptoResourceGuard``) and direct-to-slot writes (returning ``bool``). KDF configuration is represented as a structured ``KdfParameters`` type rather than opaque byte spans, providing type safety and extensibility.

   .. :affects: comp__crypto

Each key management operation accepts parameters via a dedicated fluent-builder
struct (``GenerateKeyParams``, ``DeriveKeyParams``, ``AgreeKeyParams``,
``WrapKeyParams``, ``UnwrapKeyParams``, ``ImportKeyParams``). Dual overloads
support both ephemeral and persistent slot targets. KDF configuration is
expressed as a structured ``KdfParameters`` type containing typed fields for
all supported KDFs.

Context
-------

Key operations have complex parameter needs: algorithm selection, permission
bitmasks, exportability flags, KDF configuration, IV, AAD, wrapping algorithm,
peer public key data, and format specifiers. These parameters must be passed
safely and extensibly to support both ephemeral keys (returned to the caller)
and direct-to-slot writes (persisted in the daemon).

Decision
--------

Six dedicated parameter structs are provided:

* ``GenerateKeyParams`` — algorithm, permissions, slot size
* ``DeriveKeyParams`` — algorithm, permissions, KDF config, salt, label
* ``AgreeKeyParams`` — peer public key, algorithm, permissions
* ``WrapKeyParams`` — wrapping algorithm, IV, AAD
* ``UnwrapKeyParams`` — format specifier, permissions
* ``ImportKeyParams`` — algorithm, permissions, format specifier

Each struct is a fluent builder with named setters (``SetAlgorithm()``,
``SetPermissions()``, etc.), enabling readable call sites.

Dual overloads are provided for all key-producing operations:

* **Ephemeral overload**: ``Result<CryptoResourceGuard> XxxKey(const XxxxKeyParams&)``
* **Persistent overload**: ``Result<std::monostate> XxxKey(const CryptoResourceId& target_slot, const XxxxKeyParams&)``

The ``target_slot`` parameter is always first in slot-targeting overloads,
consistent with ``PersistKey(target_slot, ephemeral_key)``.

KDF configuration is replaced with a structured ``KdfParameters`` struct
containing typed fields (salt, label, iteration count, output length) for
all supported KDFs: HKDF, TLS 1.2 PRF, TLS 1.3 HKDF, PBKDF2, SP800-108.
Opaque byte spans are no longer used for KDF parameters.

Alternatives Considered
-----------------------

Single Fat Config Struct
^^^^^^^^^^^^^^^^^^^^^^^^

One ``KeyOperationConfig`` for all operations, with optional fields for each
mode. This is rejected: most fields are unused for any given operation, creating
confusion and enabling invalid parameter combinations at compile time. A per-operation
struct enforces that only valid parameters are set.

Separate Named Methods
^^^^^^^^^^^^^^^^^^^^^^

Methods like ``GenerateKeyToSlot()`` instead of overloads. This is rejected:
it doubles the API surface without adding clarity. Overloads are distinguished
by return type (``CryptoResourceGuard`` vs ``bool``) and by the presence of
``target_slot`` as the first parameter, providing clear intent.

Builder Pattern on Context
^^^^^^^^^^^^^^^^^^^^^^^^^^^

A fluent chain on the context object (e.g., ``key_mgmt->Generate().Algorithm("AES-256").Execute()``).
This is rejected: it requires runtime validation of missing required fields.
A params-struct approach catches missing required fields at compile time via
member initialization (the daemon performs final validation).

Consequences
------------

**Positive:**

* Named fields and fluent builders eliminate parameter-order confusion and
  enable readable call sites with self-documenting intent.
* Adding new optional fields to a params struct is non-breaking; existing
  callers continue to compile unchanged.
* Structured ``KdfParameters`` provides compile-time type safety for KDF
  configuration (salt, label, iteration count) where opaque byte spans did not.
* Dual overloads cleanly separate ephemeral key creation (RAII guard return)
  from persistent slot writes (boolean return), with consistent calling convention.
* Span fields (peer public key, wrapped data, import key data, IV, AAD)
  reference caller-owned memory — zero-copy for large buffers (PQC public keys
  can reach 1–2 KB).

**Negative:**

* Six additional parameter struct types increase compilation includes if not
  forward-declared.
* Callers must construct a params struct even for simple operations:
  ``GenerateKeyParams{}.SetAlgorithm("AES-256")`` is more verbose than a
  single factory call with a string argument.
* Span fields in params structs have lifetime constraints — referenced data
  must outlive the struct. This is documented but not enforced at compile time.
