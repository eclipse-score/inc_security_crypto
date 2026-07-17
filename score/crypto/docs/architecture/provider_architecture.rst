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
   :caption: Daemon Provider Architecture — Score and PKCS#11 families, handler hierarchy, and config visitor pattern.
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

Provider Configuration
~~~~~~~~~~~~~~~~~~~~~~

Provider configuration is split into three layers. Each layer is owned by a
separate config type and resolved at a different point during daemon startup.

1. Provider-family topology — build time
   The set of provider families that can exist in a given daemon binary is
decided by compile-time flags (for example ``SCORE_BACKEND_ENABLED`` and
``SCORE_CRYPTO_PKCS11_ENABLED``). ``ProviderManagerFactory`` registers a factory
for every family that is compiled in.

2. Provider-specific parameters — config file / defaults
   Each family parses its own parameters from the daemon configuration:

   - ``ScoreProviderConfig`` (``score_provider/score_provider_config.hpp``)
     holds one ``ScoreProviderEntry`` per score backend. An entry contains the
     provider name, the backend implementation tag (for example ``"openssl"``),
     and the provider type (``SOFTWARE``, ``HARDWARE``, ``SPECIALIZED``).
     ``ScoreProviderConfig::ParseConfig()`` populates entries from the config
     file; when no config is present it falls back to the active backends
     discovered at compile time.

   - ``Pkcs11Config`` (``pkcs11/pkcs11_token_config.hpp``) holds one
     ``Pkcs11TokenEntry`` per token. An entry contains the token label, model,
     user PIN, provider name, provider type, and session cleanup strategy.
     ``Pkcs11Config::ParseConfig()`` reads these values from the daemon config.

   Both config classes use only standard-library types in their public headers
   so that the top-level ``Config`` class can own them without pulling in
   backend-specific headers.

3. Runtime enablement and type mapping — ``ProviderInitConfig``
   After all factories have created and registered their providers, and after
   every provider has been initialized, ``ProviderManager::Initialize()`` loads
   ``ProviderInitConfig`` to decide:

   - Which registered providers are enabled. Disabled providers are shut down
     and removed from lookup tables.
   - Which provider is the default for each ``CryptoProviderType``
     (``DEFAULT``, ``SOFTWARE``, ``HARDWARE``, ``SPECIALIZED``).

   ``ProviderInitConfig`` identifies providers by their stable
   ``ProviderName`` (for example ``"OPENSSL"`` or ``"hsm_slot_1"``), not by the
   runtime ``ProviderId`` assigned during registration. This keeps the
   configuration stable across restarts and independent of registration order.

   If the daemon config does not supply a ``ProviderInitConfig``,
   ``ProviderManager`` creates a default one that enables every successfully
   initialized provider and selects defaults using the preference order
   ``HARDWARE`` → ``SOFTWARE``.

Configuration flow
^^^^^^^^^^^^^^^^^^

.. code-block:: text

   Config::ParseConfig()
        │
        ├── ScoreProviderConfig::ParseConfig()  ──► ScoreProviderEntry list
        │
        └── Pkcs11Config::ParseConfig()         ──► Pkcs11TokenEntry list
        │
   ProviderManagerFactory::Create(config)
        │
        ├── CreateScoreProviderFactory(config)
        │      ScoreProviderConfig::Configure(ScoreProviderFactory)
        │
        ├── CreatePkcs11ProviderFactory(config)
        │      Pkcs11Config::Configure(Pkcs11ProviderFactory)
        │
        └── provider_manager->Initialize()
               │
               ├── CreateProviders()   ← factories create & RegisterProvider()
               ├── InitializeAll()     ← providers initialize
               │
               ├── ApplyEnablement(ProviderInitConfig.providers)
               │      shut down / hide disabled providers
               │
               └── BuildTypeMappings(ProviderInitConfig.typeToProviderName)
                      resolve names → runtime ProviderId

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
