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

.. _crypto_key_management_details:

Key Management Architecture
===========================

This document explains the key management subsystem of ``score::mw::crypto``
in detail: how keys come into being, how they are stored, how their lifetime
is managed across multiple clients, and how they are bound to a cryptographic
operation context.  A MAC operation is used as the running example because it
touches every layer of the subsystem.

.. contents::
   :local:
   :depth: 2

Architecture Overview
---------------------

The daemon key management stack has four layers:

.. list-table:: Key Management Layers
   :header-rows: 1
   :widths: 20 80

   * - Layer
     - Responsibility
   * - **Interface layer** (``interfaces/``)
     - Pure abstractions: ``IKeyFactory``, ``IKeyHandler``, ``IKeySlotHandler``,
       ``key_types.hpp``, ``key_management_operations.hpp``.  No provider-specific code.
   * - **Slot registry layer** (``slot/``)
     - ``KeySlotConfig`` — per-slot algorithm, provider IDs, access policy, provider
       parameters.  ``SlotRegistry`` — central slot registry with UID access control
       and atomic usage counting.  ``AccessPolicyEnforcer`` — all access decisions
       centralized in one place.  ``DeploymentLoader`` / ``DeploymentWriter`` — façades
       that delegate to format-specific implementations under ``slot/deployment/``
       (see `Deployment Descriptor`_ below).
   * - **Core orchestration layer** (``core/``)
     - ``KeyRegistry`` — per-provider deduplication map of live key nodes.
       ``KeyManagementService`` — DataNode lifecycle (register / load-or-share / bind /
       release), provider routing, and crash cleanup.
   * - **Data-node layer** (``nodes/``)
     - ``KeyEntry`` — sole owner of an ``IKeyHandler``; reference-counted across
       clients.  ``KeyDataNode`` — lightweight RAII guard in the client tree;
       holds a ``shared_ptr<KeyEntry>`` and triggers release on destruction.
       ``KeySlotDataNode`` — ~24-byte resolved-slot reference, no config copy.

The composition root ``KeyManagementModule`` wires these layers at daemon startup and
injects the shared ``KeyManagementService`` into every provider.

Class Diagram
-------------

The following diagram shows the key class relationships:

.. uml:: key_management_class_diagram.puml
   :align: center
   :caption: Key Management — Class Diagram
   :alt: UML class diagram for the key management subsystem.

Sequence Diagrams
-----------------

The following sequence diagram set illustrates daemon startup, slot resolution,
key generation, key load with deduplication, MAC context creation with key
binding, MAC streaming, and crash cleanup:

.. uml:: key_management_sequence_diagrams.puml
   :align: center
   :caption: Key Management — Sequence Diagrams
   :alt: UML sequence diagrams for key management operations.

Key Lifecycle
-------------

Keys enter the daemon through either of two paths and leave via an explicit
release or client-crash cleanup.

Slot resolution
~~~~~~~~~~~~~~~

Before a key can be loaded the application resolves a slot name to a
``DataNodeId``:

1. The client sends ``RESOLVE_RESOURCE(slot_name, kKeySlot)`` to the mediator.
2. ``MediatorImpl`` calls ``SlotRegistry::ResolveAppResource(slot_name,
   client_id)`` which checks the UID-to-resource map and delegates to
   ``ResolveSlot``.  ``AccessPolicyEnforcer::CheckSlotAccess`` validates that
   ``client_id`` is in the slot's ``allowed_uids`` list.
3. A ``KeySlotDataNode(slot_handle, slot_registry)`` is stored in the
   ``DataManager`` under the client's session node.  The node is small (~24
   bytes) — it holds only the ``SlotHandle`` index and a shared pointer to the
   ``SlotRegistry``; no ``KeySlotConfig`` is copied.
4. The node's ``DataNodeId`` is returned to the client as the slot handle for
   subsequent operations.

Key generation (ephemeral)
~~~~~~~~~~~~~~~~~~~~~~~~~~

When the client calls ``KeyManagementContext::GenerateKey`` the IPC path is:

1. ``KEY_GENERATE`` reaches ``MediatorImpl::ForwardSingleOperation`` and is
   dispatched to the ``ContextDataNode``'s handler
   (``OpenSslKeyManagementHandler`` or ``Pkcs11KeyManagementHandler``).
2. The handler delegates to its ``KeyManagementExecutor::HandleGenerate``.
3. ``IKeyFactory::GenerateKey(KeyGenerationRequest)`` is called:

   - **OpenSSL**: ``RAND_bytes`` → heap-allocated buffer →
     ``OpenSslKeyHandler``
   - **PKCS#11**: ``C_GenerateKey`` with ``CKA_TOKEN=false`` (session key) →
     ``Pkcs11KeyHandler``

4. ``KeyManagementService::RegisterKeyMaterial`` is called with the new
   handler:

   - A ``KeyEntry`` is created (owns the ``IKeyHandler``).
   - ``KeyRegistry::RegisterEphemeralKey`` assigns a ``KeyRegistryId`` and
     stores the node.
   - A ``KeyDataNode`` is added under the calling context node in the
     ``DataManager``.  Its constructor calls ``key_entry->AddRef(client_id)``
     (ref-count = 1).

5. The ``DataNodeId`` of the ``KeyDataNode`` is returned to the client as a
   ``CryptoResourceGuard`` wrapping a ``kKey`` resource.

Loading a pre-deployed slot key (with deduplication)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the client calls ``KeyManagementContext::LoadKey(slot_node_id)``:

1. ``KEY_LOAD`` is forwarded to the provider handler's executor.
2. ``KeyManagementExecutor::HandleLoad`` calls
   ``KeyManagementService::ResolveSlotForOperation(client_id, slot_node_id)``
   which returns ``SlotResolution{config*, slot_handle}``.
3. ``KeyManagementService::LoadOrShare`` is called:

   - ``KeyRegistry::FindBySlot(slot_handle)`` checks whether the slot is
     already loaded.
   - **Already loaded**: the existing ``KeyEntry`` is reused; a new
     ``KeyDataNode`` is added to the current client's tree and its constructor
     calls ``key_entry->AddRef(client_id)``.  No provider I/O occurs.
   - **First load**: ``IKeySlotHandler::LoadKey(*config)`` is called (file
     read or PKCS#11 ``C_FindObjects``), a new ``KeyEntry`` is created,
     ``KeyRegistry::RegisterSlotKey`` stores it, and a ``KeyDataNode`` is
     added as before.

This deduplication is critical for PKCS#11 tokens, where loading the same
token object twice would either produce a redundant handle or fail.

Key release
~~~~~~~~~~~

Explicit:
   The client calls ``CryptoResourceGuard::~CryptoResourceGuard`` on the key
   guard, which sends ``KEY_RELEASE``.  The executor calls
   ``KeyManagementService::ReleaseKeyMaterial(client_id, ref_node_id)`` →
   ``DataManager::deleteNode`` → ``~KeyDataNode()`` →
   ``key_entry->Release(client_id)``.  If that was the last reference, the
   unregister callback fires: ``KeyRegistry::Unregister(registry_id)`` drops
   the registry's ``shared_ptr``, destroying the ``KeyEntry``:
   ``IKeyHandler::Release()`` zeroizes key material.

Implicit (context close):
   ``CTX_CLOSE`` calls ``DataManager::deleteNode`` on the
   ``ContextDataNode``.  All child ``KeyDataNode`` entries (bound via
   ``BindKeyToContext``) are cascade-deleted in the same call, triggering the
   same chain.

Client crash:
   ``DataManager::deleteClientNodes(client_id)`` performs a post-order tree
   traversal, deleting all nodes in the client's subtree (cascade destruction
   of ``KeyDataNode`` entries).  ``KeyManagementService::CleanupClient``
   is also called as a safety net — it iterates every ``KeyRegistry`` and
   calls ``Release(client_id)`` on every ``KeyEntry`` that still references
   that client.

MAC Operation Example
---------------------

This section traces a complete HMAC-SHA256 operation from application code
down to the OpenSSL ``HMAC_CTX``.

Step 1 — Resolve the key slot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: cpp

   // Application code (client side)
   auto stack = CreateCryptoStack(stack_config).value();
   auto ctx   = stack->CreateCryptoContext().value();

   // Resolve the pre-deployed HMAC key slot
   auto slot = ctx->ResolveResource("HmacProductionSlot",
                                    ResourceType::kKeySlot).value();
   // slot is a CryptoResourceGuard wrapping type=kKeySlot

**Daemon side**: ``RESOLVE_RESOURCE("HmacProductionSlot", kKeySlot)`` →
``SlotRegistry::ResolveAppResource`` → ``AccessPolicyEnforcer::CheckSlotAccess``
→ ``KeySlotDataNode`` stored in ``DataManager`` → ``slot_node_id`` returned.

Step 2 — Load the key
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: cpp

   // Create a key management context and load the key explicitly.
   // This step allows reuse of the same key across multiple MAC contexts.
   auto km = ctx->CreateKeyManagementContext(KeyManagementContextConfig{}).value();
   auto key_guard = km->LoadKey(slot).value();
   // key_guard wraps type=kKey, persistence=kPersistent

**Daemon side**:

1. ``KEY_LOAD`` is forwarded to ``OpenSslKeyManagementHandler::Execute`` (OpenSSL
   provider context).
2. ``KeyManagementExecutor::HandleLoad`` → ``ResolveSlotForOperation`` →
   ``LoadOrShare``:

   - ``KeyRegistry::FindBySlot`` returns ``nullptr`` (first load).
   - ``FileBackedSlotHandler::LoadKey(config)`` reads the key file at the path
     stored in ``config.deployment_path`` (via ``DeploymentLoader``) and
     constructs an ``OpenSslKeyHandler``.
   - ``KeyRegistry::RegisterSlotKey`` stores the new ``KeyEntry``
     (``ref_count = 0``).
   - ``CreateKeyDataNode`` creates a ``KeyDataNode`` under the key-management
     context node; its constructor calls ``key_entry->AddRef(client_id)``
     and sets ``ref_count = 1``.

3. ``key_ref_node_id`` returned to client → ``CryptoResourceGuard``.

Step 3 — Create the MAC context (context creation with key binding)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: cpp

   MacContextConfig mac_cfg;
   mac_cfg.SetAlgorithm("HMAC-SHA256").SetKey(key_guard);
   auto mac = ctx->CreateMacContext(mac_cfg).value();

**Daemon side** — ``CTX_CREATE(type="MAC", algo="HMAC-SHA256",
provider=SOFTWARE, key_node_id=key_ref_node_id)``:

1. **Provider routing**: ``KeyManagementService::ResolveTargetProvider(
   client_id, SOFTWARE, key_ref_node_id)`` examines the ``KeyEntry``'s
   ``provider_id`` (``"openssl"``). Since the key lives in OpenSSL and the
   requested type is ``SOFTWARE``, the resolved provider is ``"openssl"``.

2. **Handler creation**: ``ProviderManager::GetProvider("openssl")`` →
   ``ICryptoHandlerFactory::CreateHandler("MAC", "HMAC-SHA256")`` → ``new
   MacHandler(MacExecutor, "HMAC-SHA256")``.

3. **Context node**: ``DataManager::addChildNode`` creates a ``ContextDataNode``
   wrapping the ``MacHandlerImpl``; the ``DataNodeId`` becomes
   ``context_node_id``.

4. **Key binding**: ``KeyManagementService::BindKeyToContext(client_id,
   context_node_id, key_ref_node_id, "openssl")``:

   - The ``KeyDataNode`` is located via ``DataManager::getNodeAccessor``.
   - A *new* ``KeyDataNode`` is added as a child of the ``ContextDataNode``;
     its constructor calls ``key_entry->AddRef(client_id)``, incrementing
     ``ref_count`` to 2.
   - Returns ``KeyBindingResult{key_handler_sptr, resolved_node_id}``.

5. **Initialization**: ``MediatorImpl`` builds:

   .. code-block:: cpp

      InitializationParams params{
          .client_id       = client_id,
          .context_node_id = context_node_id,
          .provider_id     = 0,  // numeric ID assigned by ProviderManager
          .key_node_id     = key_ref_node_id,
          .bound_key_handler = key_binding_result.key_handler.get()
                               // non-owning raw pointer, valid during init only
      };

   Then calls ``MacHandlerImpl::InitializeContext(params)``.

6. **Handler initialization** (``MacHandlerImpl::InitializeContext``):

   - Validates ``m_algorithm == "HMAC-SHA256"``.
   - Creates ``HMAC_CTX_new()``.
   - Checks ``params.bound_key_handler != nullptr``.
   - Verifies ``bound_key_handler->GetProviderId() == 0`` (numeric ID; type-safety
     without RTTI).
   - **Downcast**: ``static_cast<const OpenSslKeyHandler*>(
     params.bound_key_handler)`` → safe because the ProviderId tag was
     verified.
   - Calls ``GetRawKeyBytes(key_len)`` to obtain a direct pointer to the
     heap-allocated key material.
   - ``HMAC_Init_ex(m_ctx, key_bytes, key_len, EVP_sha256(), nullptr)``
     initializes the HMAC context; OpenSSL copies the key material
     internally.

At the end of ``CTX_CREATE`` the daemon returns ``context_node_id`` to the
client.  The key bytes have been loaded into the ``HMAC_CTX``; the
``OpenSslKeyHandler`` retains the authoritative copy until it is released.

Step 4 — Perform MAC operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: cpp

   mac->Update(span_of_data);
   mac->Update(more_data);
   auto mac_tag = mac->Finalize().value();

**Daemon side** — each ``Update`` becomes ``MAC_UPDATE``:

1. ``MediatorImpl::ForwardSingleOperation`` looks up the ``ContextDataNode``
   by ``context_node_id`` → ``MacHandlerImpl::Execute(MAC_UPDATE, params)``.
2. ``MacExecutor::Execute`` validates the stream transition
   (``IDLE → STREAM_INIT`` on first update; ``STREAM_INIT → STREAM_ACTIVE``
   on subsequent updates) and calls ``MacHandlerImpl::UpdateMac(dataToMac)``.
3. The handler extracts raw bytes via ``ExtractBufferData`` then calls
   ``HMAC_Update(m_ctx, data, len)`` to feed data into the running HMAC.

``MAC_FINAL``:

1. ``MacExecutor`` validates ``STREAM_INIT/ACTIVE → IDLE`` transition.
2. ``MacHandlerImpl::FinalizeMac`` → ``HMAC_Final(m_ctx, output, &len)``
   writes the 32-byte HMAC-SHA256 tag into the client-provided
   ``VirtualMemoryBuffer``.

Step 5 — Release resources
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: cpp

   mac.reset();       // ~MacContext() → CTX_CLOSE
   key_guard.reset(); // ~CryptoResourceGuard() → KEY_RELEASE

**CTX_CLOSE** (``mac.reset()``):
   ``DataManager::deleteNode(client_id, context_node_id)`` cascade-deletes:

   - ``ContextDataNode`` destroyed.
   - Child ``KeyDataNode`` (bound at step 3) destroyed:
     calls ``key_entry->Release(client_id)`` → ``ref_count = 1``.
   - HMAC context freed via ``MacHandlerImpl::~MacHandlerImpl`` →
     ``HMAC_CTX_free``.

**KEY_RELEASE** (``key_guard.reset()``):
   ``DataManager::deleteNode(client_id, key_ref_node_id)`` destroys the
   original ``KeyDataNode`` (from step 2):
   calls ``key_entry->Release(client_id)`` → ``ref_count = 0`` → unregister
   callback → ``KeyRegistry::Unregister(registry_id)`` → registry drops
   its ``shared_ptr`` → ``~KeyEntry()`` → ``IKeyHandler::Release()``
   (``OPENSSL_cleanse`` + ``delete[]``).

The key material is now securely zeroized.

Thread Safety
-------------

The key management subsystem uses a three-level lock hierarchy:

.. list-table:: Lock Hierarchy
   :header-rows: 1
   :widths: 15 35 50

   * - Level
     - Lock
     - Protects
   * - 1 (highest)
     - ``DataManager::m_mutex``
     - Node tree structure: add, delete, lookup
   * - 2
     - ``KeyRegistry::m_mutex`` (per provider)
     - ``m_keys`` map and ``m_slot_to_id`` slot index — independent per
       provider, so OpenSSL and PKCS#11 registries never contend
   * - 3 (lowest)
     - ``KeyEntry::m_ref_mutex``
     - ``m_referencing_clients`` vector

**Rule**: never acquire a lower-level lock while holding a higher-level
lock.  In practice:

- ``ReleaseKeyMaterial`` calls ``DataManager::deleteNode`` (acquires Level 1).
- The resulting ``~KeyDataNode`` calls ``key_entry->Release`` (Level 3)
  *after* the ``DataManager`` lock is released.
- The unregister callback calls ``KeyRegistry::Unregister`` (Level 2) only
  after ref-count reaches zero — at that point no DataManager lock is held.

``KeyEntry::m_ref_count`` is ``std::atomic<uint32_t>`` for lock-free
increment/decrement; the ``m_ref_mutex`` only serializes the
``m_referencing_clients`` vector updates inside ``AddRef`` / ``Release``.

Multi-Client Key Deduplication
-------------------------------

When multiple client processes resolve and load the **same** slot
simultaneously:

.. code-block:: text

   App1: RESOLVE_RESOURCE("HmacSlot") → slot_node_id_A
   App2: RESOLVE_RESOURCE("HmacSlot") → slot_node_id_B   (independent node)
   App3: RESOLVE_RESOURCE("HmacSlot") → slot_node_id_C

   App1: KEY_LOAD(slot_node_id_A) → key_ref_node_id_1  (first load → LoadKey)
   App2: KEY_LOAD(slot_node_id_B) → key_ref_node_id_2  (slot loaded → reuse)
   App3: KEY_LOAD(slot_node_id_C) → key_ref_node_id_3  (slot loaded → reuse)

   KeyRegistry: 1 × KeyEntry (ref_count=3)

Each ``KeyDataNode`` is owned by the respective client's tree.
``key_entry->Release`` is called three times (once per client when the
``KeyDataNode`` destructs); only the last call triggers destruction and
zeroization.

**Concurrent load race**: if two threads reach ``LoadOrShare`` before either
has registered, both call ``IKeySlotHandler::LoadKey``.  The first call to
``KeyRegistry::RegisterSlotKey`` wins; the losing thread detects the
conflict, looks up the winning node via ``FindBySlot``, and creates a
``KeyDataNode`` on it.  The losing ``IKeyHandler`` is released
immediately — no key material leaks.

Access Control
--------------

.. _pkcs11_session_management:

PKCS#11 Session Management
--------------------------

The PKCS#11 provider manages sessions, login state, and key object lifetime
differently from the OpenSSL provider.  This section documents the design
decisions and their rationale.

Session Pools
~~~~~~~~~~~~~

Each ``Pkcs11Provider`` maintains two pools of PKCS#11 sessions — one for
Read-Only (RO) and one for Read-Write (RW) operations.  The pools are
protected by ``m_poolMutex`` so that the gRPC thread pool can acquire and
release sessions concurrently.

Session acquisition:

1. ``AcquireSession`` scans the pool for an idle session.
2. If no idle session exists and the pool is below its hard limit (from
   ``C_GetTokenInfo.ulMaxSessionCount``), a new session is opened via
   ``C_OpenSession``.
3. For ``kUser`` access, ``TokenAuthGuard::EnsureUserState`` is called after
   the session is acquired, ensuring ``C_Login`` is called once per
   module-slot pair.

Session key pinning
~~~~~~~~~~~~~~~~~~~

PKCS#11 v2.40 §5.7 states that **session objects** (``CKA_TOKEN=false``) are
destroyed when the session that created them is closed.  They are visible to
all sessions of the same application, but the *creating* session must remain
open.

This means ``GenerateKey`` and ``ImportKey`` must **not** release the session
used to call ``C_GenerateKey`` / ``C_CreateObject``.  The session handle is
stored alongside the key object handle in ``Pkcs11KeyStore``.

Token objects (``CKA_TOKEN=true``) loaded via ``C_FindObjects`` do not have
this constraint — their lifetime is independent of any session.

Thread-safe login state
~~~~~~~~~~~~~~~~~~~~~~~

``TokenAuthGuard`` maintains a reference-counted login state:

- ``EnsureUserState``: if ``m_activeUserCount == 0``, calls ``C_Login``;
  otherwise increments the counter.  Protected by ``m_mutex``.
- ``OnUserHandlerReleased``: decrements the counter; calls ``C_Logout``
  when it reaches zero.  Protected by ``m_mutex``.

The mutex is essential because the gRPC daemon's thread pool can dispatch
concurrent crypto operations that each require a logged-in session.

Session validation
~~~~~~~~~~~~~~~~~~

Before executing a cryptographic operation, the handler calls
``Pkcs11Provider::ValidateSession(session)`` which invokes
``C_GetSessionInfo``.  If the session has become invalid (e.g. device
removal), the operation returns ``kSessionInvalid`` immediately instead of
propagating a cryptic PKCS#11 error code.

Multi-Token Coexistence
~~~~~~~~~~~~~~~~~~~~~~~

The ``Pkcs11ProviderFactory`` supports multiple tokens from the same
PKCS#11 library (e.g. multiple SoftHSM slots).  Each ``Pkcs11TokenEntry``
in ``Pkcs11Config`` becomes a separate ``Pkcs11Provider`` instance that
shares the ``Pkcs11Module`` (and thus ``C_Initialize`` is called once).

The visitor pattern drives configuration:

.. code-block:: cpp

   config.GetPkcs11Config().PopulateDefaults();
   auto factory = std::make_unique<Pkcs11ProviderFactory>();
   config.GetPkcs11Config().Configure(*factory);  // visitor call
   manager.RegisterFactory(std::move(factory));

``Pkcs11Config::Configure()`` converts each ``Pkcs11TokenEntry`` to a
``Pkcs11ProviderConfig`` and calls ``factory.SetTokenConfigs()``; the
entire mapping logic lives in ``pkcs11_token_config.cpp`` and does not
leak into ``daemon.cpp`` or ``config.hpp``.

Each provider has its own session pool, its own ``TokenAuthGuard``, and
its own ``Pkcs11KeyStore``.  Login state, sessions, and key registrations
are fully isolated between tokens.

Access Control
--------------

Access decisions are centralized in ``AccessPolicyEnforcer``.  The enforcer
is called at two independent points:

1. **Slot resolution** (``SlotRegistry::ResolveSlot``): verifies
   ``client_id`` is in ``config.access_policy.allowed_uids``.
2. **Slot write operations** (generate-to-slot, import-to-slot):
   ``CheckWritePermission`` verifies membership in
   ``config.access_policy.allowed_write_uids``.
3. **Operation permission** (before any crypto use):
   ``CheckOperationPermission`` validates the required permission bits (e.g.
   ``kMac``) against ``config.allowed_operations``.
4. **Provider access** (before write):
   ``CheckProviderAccess(config, provider_id, is_write)`` — writes are only
   allowed via the primary provider (``provider_ids[0]``); reads may use any
   listed provider.

This "defense in depth" ensures that even if a request bypasses the
mediator's routing, the enforcer rejects unauthorized operations.

Configuration
-------------

Each key slot is described by a ``KeySlotConfig``:

.. list-table:: KeySlotConfig Fields
   :header-rows: 1
   :widths: 25 15 60

   * - Field
     - Type
     - Description
   * - ``slot_name``
     - ``string``
     - Human-readable unique name used in ``ResolveResource``
   * - ``algorithm``
     - ``string``
     - Algorithm string (e.g. ``"HMAC-SHA256"``, ``"AES-256-GCM"``)
   * - ``provider_names``
     - ``vector<ProviderName>``
     - Config-time: ordered list of human-readable provider names from JSON. Index 0 is primary.
   * - ``provider_ids``
     - ``vector<ProviderId>``
     - Runtime: ordered list of numeric IDs resolved from ``provider_names`` by ``ResolveProviderIds()``. Index 0 = primary (sole writer); others = read-only.
   * - ``allowed_operations``
     - ``KeyOperationPermission``
     - Bitmask: ``kMac``, ``kEncrypt``, ``kDecrypt``, ``kSign``, …
   * - ``access_policy``
     - ``AccessPolicy``
     - ``allowed_uids``, ``allowed_write_uids``
   * - ``deployment_path``
     - ``string``
     - Absolute filesystem path to the key's deployment file.
       Read by ``DeploymentLoader::Load()`` at slot load time.
   * - ``deployment_format``
     - ``string``
     - Serialization format token (e.g. ``"kv"``). The ``DeploymentLoader``
       façade maps this string to a concrete ``IDeploymentLoader`` implementation
       (see `Deployment Descriptor`_).

.. _Deployment Descriptor:

Deployment Descriptor
~~~~~~~~~~~~~~~~~~~~~

All dynamic per-slot data that is too volatile to bake into a compiled catalog
is stored in a deployment descriptor file referenced by
``KeySlotConfig::deployment_path``.  The file is read at slot load time by
``DeploymentLoader`` and written back after a key update by ``DeploymentWriter``.

**Format-extensible design**

The ``DeploymentLoader`` / ``DeploymentWriter`` classes are thin façades.  After
validating the path they delegate to a format-specific implementation that
implements ``IDeploymentLoader`` / ``IDeploymentWriter``:

.. code-block:: text

   slot/
     deployment_loader.hpp/.cpp        ← façade (public API unchanged for all callers)
     deployment_writer.hpp/.cpp        ← façade
     deployment/
       deployment_path_utils.hpp       ← IsDeploymentPathSafe() — shared guard
       i_deployment_loader.hpp         ← pure-virtual interface
       i_deployment_writer.hpp         ← pure-virtual interface
       kv/
         kv_deployment_loader.hpp/.cpp ← current implementation
         kv_deployment_writer.hpp/.cpp
       json/                           ← reserved (add JsonDeploymentLoader when needed)
       flatbuffer/                     ← reserved

To add a new format: implement ``IDeploymentLoader`` / ``IDeploymentWriter`` under
``slot/deployment/<format>/``, then add one ``if``-branch in each façade ``.cpp``
and one dep in ``slot/deployment/BUILD``.  No other files change.

**Key=value format (``"kv"``) — file layout**

.. code-block:: ini

   # comments are ignored; blank lines are ignored
   [metadata]
   availability    = active
   provisioned_at  = 2025-11-03T08:42:00Z
   update_counter  = 1
   hash            = sha256:a1b2c3d4...
   kek.keyslotname = vehicle/master-key
   kek.algo        = AES-256-GCM
   kek.iv          = 0102030405060708090a0b0c

   [key]
   key_path   = /etc/crypto/keys/hmac.bin
   key_format = raw
   # key = <hex or base64 plain-text key — testing/dev only, not for production>

**Well-known metadata keys** (``metadata_keys`` namespace in ``key_slot_config.hpp``):

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Key
     - Meaning
   * - ``availability``
     - Slot state override: ``"active"`` | ``"disabled"`` | ``"unavailable"``
   * - ``provisioned_at``
     - ISO-8601 UTC timestamp of last successful key provisioning
   * - ``update_counter``
     - Monotonically increasing decimal string; incremented on every key replacement
   * - ``hash``
     - Hex-encoded digest of the key material (e.g. ``"sha256:a1b2..."``)
   * - ``kek.keyslotname``
     - Slot name of the Key Encryption Key used to wrap/unwrap this key
   * - ``kek.algo``
     - Algorithm of the Key Encryption Key (e.g. ``"AES-256-GCM"``)
   * - ``kek.iv``
     - Hex-encoded IV for KEK operations

**Well-known deployment keys** (``deployment_keys`` namespace in ``key_slot_config.hpp``):

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Key
     - Meaning
   * - ``key_path``
     - Filesystem path to the key material file (file-backed providers)
   * - ``key_format``
     - Encoding of the file: ``"raw"``, ``"pem"``, ``"der"``
   * - ``key``
     - Plain-text key material (hex/base64). **For testing/development only.**
   * - ``pkcs11.label``
     - PKCS#11 ``CKA_LABEL`` (HSM providers)
   * - ``pkcs11.object_id``
     - PKCS#11 ``CKA_ID`` as hex string
   * - ``pkcs11.object_class``
     - ``"secret_key"``, ``"private_key"``, or ``"public_key"``
   * - ``tee.key_id``
     - TEE / PSA persistent key identifier
   * - ``psa.key_id``
     - PSA Crypto key identifier (uint32 as decimal string)
