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

.. _crypto_provider_architecture:

Provider Architecture
=====================

The daemon hosts two parallel provider families — **Score** (software-oriented,
currently backed by OpenSSL) and **PKCS#11** (hardware token / SoftHSM). Both
families implement the same ``IProvider`` / ``IProviderFactory`` interfaces and
are registered with ``ProviderManager`` through an identical visitor-pattern
bootstrapping sequence.

.. uml:: provider_architecture.puml
   :align: center
   :caption: Daemon Provider Architecture — Score and PKCS#11 families, handler hierarchy, and configuration flow.
   :alt: UML class diagram of the provider architecture.

Provider Families
-----------------

Score Provider Family
~~~~~~~~~~~~~~~~~~~~~

The score family (``provider/score_provider/``) provides typed abstract handler
bases that sit between the generic ``IHandler`` interface and concrete
implementations:

- ``ScoreHashHandler`` owns a ``HashExecutor`` that drives the stream state
  machine (``HASH_INIT`` → ``HASH_UPDATE`` → ``HASH_FINALIZE``).
- ``ScoreMacHandler`` owns a ``MacExecutor`` with the equivalent MAC state machine.
- ``ScoreKeyManagementHandler`` delegates to a shared ``KeyManagementExecutor``
  (from ``provider/executors/``).

Concrete providers (e.g. ``openssl/``) inherit from these bases and override
only the typed crypto primitive methods (``InitHash``, ``UpdateHash``,
``FinalizeHash``). They do not re-implement the state machine logic.

PKCS#11 Provider Family
~~~~~~~~~~~~~~~~~~~~~~~

The PKCS#11 family (``provider/pkcs11/``) implements ``IHandler`` directly.
Each handler translates generic operation requests into PKCS#11 C API calls
against a token. Shared key management logic is provided via the same
``KeyManagementExecutor`` used by the score family.

Shared Operation Constants
~~~~~~~~~~~~~~~~~~~~~~~~~~

``handler/operations/hash_handler_operations.hpp`` and
``handler/operations/mac_handler_operations.hpp`` define the ``OperationAction``
integer constants (``HASH_INIT``, ``HASH_UPDATE``, ``HASH_FINALIZE``,
``MAC_INIT``, etc.) that identify each IPC operation.
Both provider families include these headers directly — the constants are not
specific to any algorithm family or provider.

Hash Algorithm Contract
~~~~~~~~~~~~~~~~~~~~~~~

Hash contexts expose a provider-neutral interface. The daemon resolves the
requested algorithm against the provider selected for the deployment and
returns ``CryptoErrorCode::kUnsupportedAlgorithm`` when that provider cannot
perform it. The daemon does not silently substitute another algorithm or digest
size. Algorithm availability can therefore differ between deployments without
changing the public hash interface.

The digest size required by a resolved algorithm is exposed through the hash
context, allowing callers to allocate an output buffer without relying on
provider-specific metadata.

Both streaming and single-shot operations accept empty input. A streaming
caller may invoke ``Init()`` followed directly by ``Finalize()`` without an
intermediate ``Update()``; the result is the standard digest of the empty byte
sequence.

SHA-1 and MD5 are not exposed by the high-level Crypto API because no supported
use case requires these cryptographically weak algorithms.

An insufficient output buffer is a retryable finalization error. Provider
adapters must either detect this condition before consuming the digest state or
preserve the active provider operation when reporting it. Other provider or
transport errors must be handled according to their returned error code; callers
must not assume that every failure preserves a streaming operation.

Provider Configuration
~~~~~~~~~~~~~~~~~~~~~~

Provider configuration is split into four layers. Each layer has a distinct
owner and is resolved at a different point during build or daemon startup.

1. Provider-family topology — build time
   The set of provider families that can exist in a given daemon binary is
   decided by compile-time bool flags. The master family flags are
   ``score_crypto_score_backend_enabled`` for the Score provider family and
   ``score_crypto_pkcs11_backend_enabled`` for the PKCS#11 provider family. Their
   corresponding config settings are exposed to the code as
   ``SCORE_CRYPTO_SCORE_BACKEND_ENABLED`` and ``SCORE_CRYPTO_PKCS11_BACKEND_ENABLED``. The Score
   family also has the per-backend flag ``score_crypto_score_openssl_enabled``,
   exposed as ``SCORE_BACKEND_OPENSSL_ENABLED``, which controls whether the
   OpenSSL backend is included in the active Score backend list. A flag can be
   overridden at build time to exclude a family or backend from the daemon
   binary. ``ProviderManagerFactory`` creates the corresponding backend factory
   for every configured family that is compiled in.

2. Provider-specific parameters — config file / defaults
   Each family parses its own parameters from the daemon configuration:

   - ``ScoreProviderConfig`` (``score_provider/score_provider_config.hpp``)
     holds one ``ScoreProviderEntry`` per score backend. An entry contains the
     provider name, the backend implementation tag (for example ``"openssl"``),
     and the provider type (``SOFTWARE``, ``HARDWARE``, ``SPECIALIZED``).
     ``ScoreProviderConfig::ParseConfig(config)`` populates entries from the config
     file; when no config is present it falls back to the active backends
     discovered at compile time.

   - ``Pkcs11Config`` (``pkcs11/pkcs11_token_config.hpp``) holds one
     ``Pkcs11TokenEntry`` per token. An entry contains the token label, model,
     user PIN, provider name, provider type, and session cleanup strategy.
     ``Pkcs11Config::ParseConfig(config)`` reads these values from the daemon config.

3. Construction policy — ``ProviderConstructionPolicy``
   ``ProviderManagerFactory`` applies this policy before invoking backend
   factories. Each entry identifies a provider by its stable ``ProviderName``
   and specifies whether construction is enabled and whether registration is
   required for daemon startup. An empty policy permits all providers exposed
   by compiled-in backends. A non-empty policy permits only explicitly enabled
   entries.

   A required provider must be constructed and registered. It need not complete
   eager initialization during startup; providers such as hardware modules may
   use deferred initialization and become available on a later lookup.

   An enabled provider that is not required is optional. Its construction,
   registration, or initialization failure is retained for diagnostics but does
   not prevent daemon startup when another provider is registered and all
   explicit routing targets are satisfied. Startup fails if no provider can be
   registered.

   Integrators configure required and optional providers independently from
   routing. For example:

   .. code-block:: cpp

      auto& construction = config.GetProviderConstructionPolicy();
      construction.AddProvider({"OPENSSL", true, true});
      construction.AddProvider({"hsm_slot_1", true, false});

   This configuration requires ``OPENSSL`` to be registered and permits the HSM
   provider without making its registration a startup requirement. Parsing this
   typed policy from deployment configuration is handled separately from the
   policy model.

4. Runtime routing policy — ``ProviderRoutingPolicy``
   After registration, ``ProviderManager`` applies this independent policy to
   select providers at runtime. It contains:

   - Explicit default providers for ``CryptoProviderType`` categories.
   - The category preference used to derive ``DEFAULT`` when it is not explicit.
   - Per-capability category preferences and whether routing may fall back to a
     capable provider outside those preferences.

   Explicit mappings use stable ``ProviderName`` values rather than runtime
   ``ProviderId`` values. A ``DEFAULT`` mapping may select any provider, while
   category-specific mappings must match the category declared when the
   provider was registered. When several providers have the same category,
   an explicit category mapping is preferred; otherwise registration order
   provides the deterministic implicit default. The category default is also
   tried first for capability routing within that category. The default
   routing policy preserves the standard ``HARDWARE`` → ``SOFTWARE`` preference
   for cryptographic and key-management capabilities and ``SOFTWARE`` →
   ``HARDWARE`` for certificate management. A routing rule may also require a
   combination of capabilities; the selected provider must advertise every bit.

Construction and routing policies do not define provider resource limits or
caller authorization. Provider-specific operation limits belong to the provider
implementation. Authorization to use a provider belongs to the daemon access
control component.

Parsing provider-specific deployment configuration into the standard daemon
configuration and resolving application-scoped resource identifiers to
configured providers are separate concerns. The policy types described here
consume resolved provider names and do not implement either concern.

Registration and availability are separate states. Registration assigns a
stable ``ProviderId`` exactly once. ``ProviderManager::Initialize()`` makes
an initial initialization attempt, but a registered provider may remain
temporarily unavailable after startup. A provider lookup retries initialization
using the same ``ProviderId`` and serializes concurrent attempts.
``IProvider::IsInitialized()`` reports state only; it does not initialize the
provider.

Backend factories return ``ProviderFactoryResult`` rather than collapsing the
outcome into a single error. This preserves partial success and per-provider
failure details for startup diagnostics. ``ProviderManagerFactory`` evaluates
those results against the construction policy, treats a missing required
provider or an unsatisfied explicit routing target as fatal, and shuts down any
providers already registered before returning a startup error. A configuration
that registers no provider is reported as provider unavailable rather than as
an unspecified internal error. Individual factory and provider failures remain
available through ``ProviderManager`` and are logged during startup.

Configuration flow
^^^^^^^^^^^^^^^^^^

.. code-block:: text

   Config::ParseConfig()
        │
   ProviderManagerFactory::Create(config)
        │
        ├── Validate ProviderConstructionPolicy and ProviderRoutingPolicy
        │
        ├── CreateScoreProviderFactory(config)
        │      ScoreProviderConfig::ParseConfig(config)  ──► ScoreProviderEntry list
        │      filter entries with ProviderConstructionPolicy
        │      ScoreProviderFactory(ScoreProviderFactoryConfig)
        │      CreateAndRegister(manager) ──► ProviderId assigned once
        │
        ├── CreatePkcs11ProviderFactory(config)
        │      Pkcs11Config::ParseConfig(config)         ──► Pkcs11TokenEntry list
        │      filter entries with ProviderConstructionPolicy
        │      Pkcs11ProviderFactory(Pkcs11ProviderFactoryConfig)
        │      CreateAndRegister(manager) ──► ProviderId assigned once
        │
        ├── Verify required providers were registered
        │
        └── provider_manager->Initialize()
               │
               ├── InitializeAll()
               │      provider->Initialize(context)
               │
               └── BuildTypeMappings(ProviderRoutingPolicy.typeToProviderName)
                 resolve registered names → runtime ProviderId

On a later request, ``ProviderManager::GetProvider(...)`` checks
``IsInitialized()`` and retries ``Initialize(context)`` when necessary.
Failed providers remain registered, but unavailable providers are not
returned to callers.

Directory Layout
----------------

.. code-block:: text

   provider/
   ├── i_provider.hpp                     ← IProvider interface
   ├── i_provider_factory.hpp             ← IProviderFactory interface
   ├── provider_manager.hpp/.cpp          ← Provider registry & lifecycle
   ├── provider_manager_factory.hpp/.cpp  ← Build-time factory wiring
   ├── handler/
   │   ├── i_handler.hpp                  ← Handler interface
   │   ├── i_crypto_handler_factory.hpp   ← Factory interface
   │   ├── handler_init_params.hpp
   │   ├── context_data_node.hpp
   │   ├── operations/
   │   │   ├── hash_handler_operations.hpp  ← Shared hash OperationAction constants
   │   │   └── mac_handler_operations.hpp   ← Shared MAC OperationAction constants
   │   └── src/
   │       ├── handler_utils.hpp/.cpp
   │       └── context_data_node.cpp
   ├── executors/
   │   ├── key_mgmt_executor.hpp/.cpp     ← Shared KM executor (both families)
   │   ├── key_mgmt_context.hpp
   │   └── key_mgmt_request_parser.hpp
   ├── score_provider/
   │   ├── score_provider_config.hpp/.cpp ← Config / visitor
   │   ├── score_provider_factory.hpp/.cpp
   │   ├── score_provider.hpp             ← Abstract base provider
   │   ├── score_backend_adapter.hpp      ← Backend adapter interface
   │   ├── operations/                    ← Score*Handler + *Executor bases
   │   │   ├── hash/
   │   │   ├── mac/
   │   │   ├── key_management/
   │   │   └── factory/
   │   └── openssl/                       ← OpenSSL concrete provider
   │       ├── provider_openssl.hpp/.cpp
   │       ├── operations/                ← OpenSsl*Handler implementations
   │       ├── key_management/            ← OpenSslKeyHandler, OpenSslKeyFactory
   │       └── detail/
   └── pkcs11/                            ← PKCS#11 provider family
       ├── pkcs11_token_config.hpp/.cpp   ← Token config / visitor
       ├── pkcs11_provider_factory.hpp/.cpp
       ├── pkcs11_provider.hpp/.cpp
       ├── pkcs11_module.hpp/.cpp
       ├── pkcs11_session_guard.hpp
       ├── operations/
       ├── key_management/
       └── detail/
