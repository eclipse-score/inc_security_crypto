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

Hash algorithm identifiers are case-sensitive wire-level values. The standard
algorithm name and the identifier passed to ``HashContextConfig`` are distinct:

.. list-table:: Hash algorithms prepared for Baselibs migration
   :header-rows: 1

   * - Standard name
     - Canonical API identifier
     - Digest size
     - OpenSSL mapping
     - PKCS#11 mapping
   * - SHA-256
     - ``SHA256``
     - 32 bytes
     - ``EVP_sha256``
     - ``CKM_SHA256``
   * - SHA-384
     - ``SHA384``
     - 48 bytes
     - ``EVP_sha384``
     - ``CKM_SHA384``
   * - SHA-512
     - ``SHA512``
     - 64 bytes
     - ``EVP_sha512``
     - ``CKM_SHA512``

OpenSSL support is determined from the provider's EVP mapping. PKCS#11 support
requires both a daemon mapping and a token that implements the corresponding
mechanism. A configured hardware provider therefore may reject an algorithm
that the software provider supports; the daemon must return an explicit error
rather than silently select another algorithm or digest size.

For PKCS#11, ``Pkcs11HandlerFactory`` resolves the canonical identifier to a
``CK_MECHANISM_TYPE`` and calls ``C_GetMechanismInfo`` for the provider's
selected slot before acquiring a session or constructing the hash handler. A
mechanism is accepted for hashing only when its returned flags include
``CKF_DIGEST``; merely being listed by the token is not sufficient.
``CKR_MECHANISM_INVALID`` is reported to the client as
``CryptoErrorCode::kUnsupportedAlgorithm``; other PKCS#11 query failures are
translated through the daemon error mapping.

Both streaming and single-shot operations accept empty input. A streaming
caller may invoke ``Init()`` followed directly by ``Finalize()`` without an
intermediate ``Update()``; the result is the standard digest of the empty byte
sequence.

SHA-224, SHA-1, and MD5 remain available for compatibility with existing
callers but are not approved targets for new Baselibs migrations. SHA-3, SHAKE,
CRC32, and CRC32 AUTOSAR are outside the current hash provider contract.

Baselibs Migration Boundary
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The algorithm mapping for consumers moving from ``score/hash`` is:

.. list-table:: Baselibs to Crypto hash mapping
   :header-rows: 1

   * - Baselibs value
     - Crypto identifier
     - Crypto usage
   * - ``HashAlgorithm::kSha256``
     - ``SHA256``
     - ``IHashContext`` streaming or single-shot
   * - ``HashAlgorithm::kSha384``
     - ``SHA384``
     - ``IHashContext`` streaming or single-shot
   * - ``HashAlgorithm::kSha512``
     - ``SHA512``
     - ``IHashContext`` streaming or single-shot

The Crypto API returns raw digest bytes into a caller-owned buffer. Baselibs
``Hash``, ``TypedHash``, hexadecimal conversion, and ``std::istream`` helpers are
not reproduced here. A migrating consumer reads stream chunks and calls
``Update()`` itself, and owns any representation adapter it still requires.

.. list-table:: Baselibs API migration guide
   :header-rows: 1

   * - Baselibs API
     - Crypto API
     - Migration note
   * - ``HashCalculatorFactory::CreateHashCalculator(algorithm)``
     - ``ICryptoContext::CreateHashContext(config)``
     - Put the canonical string identifier in ``HashContextConfig`` and handle
       context-creation errors.
   * - ``IHashCalculator::Update(data)``
     - ``IHashContext::Init()`` followed by ``Update(data)``
     - ``Init`` is explicit and ``Update`` may be called zero or more times.
   * - ``IHashCalculator::Finalize()``
     - ``IHashContext::Finalize(output)``
     - Allocate caller-owned output using ``GetDigestSize`` and consume only
       the returned byte count.
   * - ``IHashCalculatorFactory::CalculateHash(algorithm, data)``
     - ``IHashContext::SingleShot(input, output)``
     - Context creation is separate from execution, which permits reuse.
   * - ``CalculateHash(algorithm, std::istream&)`` and
       ``UpdateFromStream(std::istream&)``
     - Caller-managed read loop plus ``Update``
     - Stream ownership, chunk sizing, read errors, and maximum-read behavior
       remain the consumer's responsibility.
   * - ``Hash`` / ``TypedHash`` result objects
     - Raw digest in caller-owned ``span<uint8_t>``
     - Preserve any algorithm tag, fixed-size wrapper, equality policy, or
       serialization in a consumer-side adapter.
   * - Baselibs hexadecimal helpers
     - Consumer-owned encoding adapter
     - Do not hex-encode bytes before passing them to the hash operation.

An undersized ``Finalize`` output is retryable: the caller may supply a larger
buffer and call ``Finalize`` again without replaying the input. Other provider or
transport errors must be handled according to their returned error code; callers
must not assume that every failure preserves a streaming operation.

This mapping does not include CRC variants or the Baselibs native safety SHA-256
implementation. The client, IPC/shared-memory transport, daemon, and provider
path described here is QM functionality and is not an ISO 26262-qualified
replacement unless the complete deployed path is independently qualified.

Provider Configuration
~~~~~~~~~~~~~~~~~~~~~~

Provider configuration is split into three layers. Each layer is owned by a
separate config type and resolved at a different point during daemon startup.

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

3. Runtime enablement and type mapping — ``ProviderInitConfig``
   After all factories have created and registered their providers,
   ``ProviderManager::Initialize()`` applies ``ProviderInitConfig`` to decide:

   - Which registered providers are eligible. Disabled providers are excluded
     before backend registration.
   - Which provider is the default for each ``CryptoProviderType``
     (``DEFAULT``, ``SOFTWARE``, ``HARDWARE``, ``SPECIALIZED``).

   ``ProviderInitConfig`` identifies providers by their stable
   ``ProviderName`` (for example ``"OPENSSL"`` or ``"hsm_slot_1"``), not by the
   runtime ``ProviderId`` assigned during registration. This keeps the
   configuration stable across restarts and independent of registration order.

   If the daemon config does not supply a ``ProviderInitConfig``,
   ``ProviderManager`` creates a default one that enables every registered
   provider and selects defaults using the preference order
   ``HARDWARE`` → ``SOFTWARE``.

Registration and availability are separate states. Registration assigns a
stable ``ProviderId`` exactly once. ``ProviderManager::Initialize()`` makes
an initial initialization attempt, but an individual provider may remain
unavailable without preventing optional providers from being registered.
A provider lookup retries initialization using the same ``ProviderId`` and
serializes concurrent attempts. ``IProvider::IsInitialized()`` reports state
only; it does not initialize the provider.

Configuration flow
^^^^^^^^^^^^^^^^^^

.. code-block:: text

   Config::ParseConfig()
        │
        ├── ScoreProviderConfig::ParseConfig(config)  ──► ScoreProviderEntry list
        │
        └── Pkcs11Config::ParseConfig(config)         ──► Pkcs11TokenEntry list
        │
   ProviderManagerFactory::Create(config)
        │
        ├── CreateScoreProviderFactory(config)
        │      ScoreProviderFactory(ScoreProviderFactoryConfig)
        │      CreateAndRegister(manager) ──► ProviderId assigned once
        │
        ├── CreatePkcs11ProviderFactory(config)
        │      Pkcs11ProviderFactory(Pkcs11ProviderFactoryConfig)
        │      CreateAndRegister(manager) ──► ProviderId assigned once
        │
        └── provider_manager->Initialize()
               │
               ├── InitializeAll()
               │      provider->Initialize(context)
               │
               └── BuildTypeMappings(ProviderInitConfig.typeToProviderName)
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
