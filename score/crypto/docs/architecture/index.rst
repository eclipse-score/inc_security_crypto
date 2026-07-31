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

.. _component_architecture_template:

Component Architecture
======================

.. document:: Crypto Architecture
   :id: doc__crypto_architecture
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__cmpt_request_dummy

.. workproduct:: Component Request Dummy
   :id: wp__cmpt_request_dummy
   :version: 1
   :status: draft

Overview
--------

The ``score::crypto`` module provides a provider-agnostic C++ (>=17) middleware
interface for cryptographic operations, key management, certificate lifecycle, and
shared memory allocation. It follows a client-daemon architecture where the
client library communicates with a daemon process over IPC.

The API is organized around a single runtime handle type —
``CryptoResourceId`` — that encapsulates a daemon-assigned 64-bit identifier,
resource type, persistence semantics, and owning provider index. Applications
resolve human-readable string identifiers to ``CryptoResourceId`` handles once,
then use these compact numeric handles for all subsequent operations.

Key design principles:

- **Provider-agnostic**: Operations work identically across hardware (HSM, TEE)
  and software (OpenSSL, SoftHSM) providers
- **PQC-ready**: ``AlgorithmId`` uses strings for extensibility, supporting
  ML-KEM, ML-DSA, SLH-DSA, XMSS, LMS, and SHAKE algorithms
- **Ephemeral-by-default keys**: All key generation produces ephemeral keys;
  explicit ``PersistKey()`` promotes to persistent storage
- **Zero-copy data plane**: Provider-compatible shared memory enables
  zero-copy from application through daemon to crypto device
- **Backward-compatible extensibility**: All configs use default constructors
  with fluent builders; new optional fields never break existing callers

Requirements Linked to Component Architecture
---------------------------------------------

.. This section will be populated with requirement traceability links.

.. needtable:: Overview of Component Requirements
   :style: table
   :columns: title;id
   :filter: search("comp_arch_sta__archdes$", "fulfils_back")
   :colwidths: 70,30

.. toctree::
   :maxdepth: 2
   :caption: Architecture Details

   component_architecture
   api_architecture
   api_description
   dynamic_architecture
   interfaces
   provider_architecture
   key_management_details
   chklst_arc_inspection
   design_decisions


Static Architecture
-------------------

The components are designed to cover the expectations from the feature architecture
(i.e. if already exists a definition it should be taken over and enriched).

.. code-block:: rst

   .. comp:: Crypto
      :id: comp__crypto
      :security: YES
      :safety: QM
      :status: invalid
      :implements:

.. image:: component_overview.png
   :align: center
   :scale: 75

.. TODO: Merge the below description into more appropriate sections when more details are available.

Provider Layer
--------------

The provider layer decouples the daemon from concrete cryptographic library implementations
through two complementary abstractions:

``IProvider``
   The single entry-point into one cryptographic back-end (e.g. OpenSSL, a PKCS#11 token).
   Exposes ``GetCryptoHandlerFactory()``, ``GetKeyFactory()``, and ``GetKeySlotHandler()``.
   Lifecycle is managed by ``ProviderManager``.

``IProviderFactory``
   A pure-virtual factory interface with a single method
   ``bool CreateAndRegister(ProviderManager&)``.
   Concrete implementations encapsulate the construction and registration of one or more
   related ``IProvider`` instances.  Factories are registered externally
   (daemon bootstrapper) via ``ProviderManager::RegisterFactory()`` and called in
   registration order during ``ProviderManager::Initialize()``.

``ScoreProviderFactory``
   Top-level factory for the **score interface family**.  Accepts a vector of
   ``ScoreProviderEntry`` values in a complete ``ScoreProviderFactoryConfig``
   snapshot (default: single OpenSSL entry).
   ``CreateAndRegister()`` resolves each configured implementation tag against
   the active compile-time backend adapters and registers the resulting provider
   under its configured name and type.

``Pkcs11ProviderFactory``
   Accepts a complete ``Pkcs11ProviderFactoryConfig`` snapshot containing the
   parsed ``Pkcs11TokenEntry`` values. The daemon bootstrapper passes this
   snapshot when constructing the factory:

   .. code-block:: cpp

        Pkcs11ProviderFactoryConfig factory_config{
           config.GetPkcs11Config().GetConfig()};
        auto factory = std::make_unique<Pkcs11ProviderFactory>(
           std::move(factory_config));
      manager.RegisterFactory(std::move(factory));

   ``CreateAndRegister`` creates a single shared ``Pkcs11Module`` (so
   ``C_Initialize`` is invoked exactly once regardless of token count),
   then constructs and registers one ``Pkcs11Provider`` per entry as
   ``CryptoProviderType::HARDWARE``.

   The factory performs the ``Pkcs11TokenEntry`` to
   ``Pkcs11ProviderConfig`` conversion internally (filling labels, PIN, and
   cleanup strategy). This keeps the conversion within the PKCS#11 subsystem
   and keeps PKCS#11 implementation details out of the daemon bootstrapper.

   **Multi-token coexistence**: multiple ``Pkcs11TokenEntry`` entries in
   ``Pkcs11Config`` produce one ``Pkcs11Provider`` per token.
   All providers from the same factory share a single ``Pkcs11Module``
   (``C_Initialize`` / ``C_Finalize`` is called once), but each provider
   maintains its own session pools, ``TokenAuthGuard``, and
   ``Pkcs11KeyStore``.  Login state and key registrations are fully isolated.
   This design supports scenarios such as separate SoftHSM slots for
   different trust domains within the same process.

   For session lifecycle details see
   :ref:`pkcs11_session_management` in the key management details.

``ProviderManager``
   Aggregates all registered providers and routes requests by ``ProviderId`` or
   ``CryptoProviderType``.  After all factories have been called, ``Initialize()``
   applies the daemon configuration and calls ``Initialize()`` on every provider.

Dynamic Architecture
--------------------

The typical interaction sequence between Application, Client Library, and Crypto Daemon:

.. uml:: typical_usage_sequence.puml
   :align: center
   :scale: 75

See :ref:`crypto_dynamic_architecture` for detailed usage flows including
pre-deployed key paths, ephemeral key generation, context reuse, PQC signing,
certificate verification, and timeout configuration.

Interfaces
----------

See :ref:`crypto_interfaces` for the full interface descriptions.

Design Decisions
----------------

See :ref:`crypto_design_decisions` for the full design decision records.
