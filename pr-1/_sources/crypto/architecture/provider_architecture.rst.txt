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
  machine (``HASH_INIT`` → ``HASH_UPDATE`` → ``HASH_FINISH``).
- ``ScoreMacHandler`` owns a ``MacExecutor`` with the equivalent MAC state machine.
- ``ScoreKeyManagementHandler`` delegates to a shared ``KeyManagementExecutor``
  (from ``provider/executors/``).

Concrete providers (e.g. ``openssl/``) inherit from these bases and override
only the typed crypto primitive methods (``StartHash``, ``UpdateHash``,
``FinishHash``). They do not re-implement the state machine logic.

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
integer constants (``HASH_INIT``, ``HASH_UPDATE``, ``HASH_FINISH``,
``MAC_INIT``, etc.) that identify each IPC operation.
Both provider families include these headers directly — the constants are not
specific to any algorithm family or provider.


Directory Layout
----------------

.. code-block:: text

   provider/
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
   │   ├── score_provider.hpp/.cpp        ← Abstract base provider
   │   ├── operations/
   │   │   ├── hash/                      ← ScoreHashHandler + HashExecutor
   │   │   ├── mac/                       ← ScoreMacHandler + MacExecutor
   │   │   ├── key_management/            ← ScoreKeyManagementHandler
   │   │   └── factory/                   ← ScoreHandlerFactory
   │   └── openssl/                       ← OpenSSL concrete provider
   │       ├── provider_openssl.hpp/.cpp
   │       ├── openssl_provider_factory.hpp/.cpp
   │       ├── operations/                ← OpenSsl*Handler implementations
   │       ├── key_management/            ← OpenSslKeyHandler, OpenSslKeyFactory
   │       └── detail/
   ├── pkcs11/                            ← PKCS#11 provider family
   └── src/
       └── provider_manager.cpp
