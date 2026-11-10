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

Component Architecture Documentation
====================================

.. document:: IAV Primula Architecture
   :id: doc__iav_primula_architecture
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__component_arch
   :tags: iav_primula


Overview
--------

The IAV Primula integration connects the C++ crypto daemon to the Rust
post-quantum cryptography library through a C-compatible interface.
``PrimulaBackendAdapter`` supplies the creation metadata used by the provider
factory to create and register the specialized Primula provider. Its
key-management, signing, and verification handlers call the Rust FFI entry
points.

The adapter advertises Primula as ``SPECIALIZED``. During registration,
however, ``ScoreProviderFactory`` uses the configured ``providerType``;
therefore, the provider configuration must select ``SPECIALIZED``.

The provider and routing skeleton is implemented. The Rust cryptographic entry
points are placeholders that return ``IavStatusUnsupportedAlgorithm``;
therefore, ML-DSA and ML-KEM operations currently produce no cryptographic
results.

Requirements Linked to Component Architecture
---------------------------------------------

.. needtable:: IAV Primula Component Requirements
   :style: table
   :types: comp_req
   :filter: "comp_req__iav_primula__" in id
   :columns: title;id;status
   :colwidths: 45,40,15

Description
-----------

The integration contains the following architectural elements:

- ``PrimulaBackendAdapter`` exposes creation metadata for the ``primula``
  backend. ``ScoreProviderFactory`` uses its creator when a configured provider
  entry selects ``primula`` as its implementation.
- ``IavPrimulaProvider`` owns the Primula key factory and creates the
  operation-handler factory.
- The key-management, signing, and verification handlers translate daemon
  requests into calls to the IAV Primula C-compatible interface.
- ``iav_primula_ffi.h`` and ``src/ffi.rs`` form the boundary between the C++
  daemon and Rust.
- The concrete ML-DSA and ML-KEM implementation behind the Rust FFI is not
  connected.

Design constraints:

- Keep the C-compatible interface stable across the C++ and Rust boundary.
- Register Primula as a specialized provider for post-quantum algorithms.
- Keep Rust key representations hidden behind opaque handles.

Rationale Behind Architecture Decomposition
*******************************************

The decomposition follows registration, request-routing, and language
boundaries. The backend adapter isolates provider creation, while the provider
and its handlers adapt crypto-daemon requests to the stable C-compatible
interface. The FFI boundary keeps Rust implementation details out of the C++
daemon and allows a concrete PQC backend to be added without changing daemon
callers.

Static Architecture
-------------------

The static view describes the stable C-compatible boundary between the crypto
daemon and the Rust library. It covers the exported interface, shared status
and algorithm identifiers, and opaque key handles.

.. comp:: IAV Primula
   :id: comp__iav_primula
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :belongs_to: feat__mtef
   :consists_of: comp__iav_primula_backend_adapter,
      comp__iav_primula_daemon_provider,
      comp__iav_primula_c_abi,
      comp__iav_primula_rust_ffi,
      comp__iav_primula_pqc_backend

.. comp_arc_sta:: IAV Primula Static View
   :id: comp_arc_sta__iav_primula__sv
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :belongs_to: comp__iav_primula
   :fulfils: comp_req__iav_primula__provide_c_abi,
      comp_req__iav_primula__stable_status_codes,
      comp_req__iav_primula__stable_algorithm_ids,
      comp_req__iav_primula__opaque_key_handles

   .. needarch::
      :scale: 50
      :align: center

      {{ draw_component(need(), needs) }}

Dynamic Architecture
--------------------

.. comp_arc_dyn:: IAV Primula Dynamic View
   :id: comp_arc_dyn__iav_primula__dv
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :belongs_to: comp__iav_primula
   :fulfils: comp_req__iav_primula__ml_dsa_operations,
      comp_req__iav_primula__ml_kem_operations,
      comp_req__iav_primula__validate_algorithm_ids,
      comp_req__iav_primula__pointer_length_validation,
      comp_req__iav_primula__protect_output_buffers,
      comp_req__iav_primula__kem_output_buffers,
      comp_req__iav_primula__verification_outcomes,
      comp_req__iav_primula__key_handle_lifecycle

   The crypto daemon requests an operation handler. For SIGN and VERIFY,
   ``IavPrimulaHandlerFactory`` validates that the requested algorithm is a
   supported PQC signature algorithm before creating the corresponding handler.
   KEM requests use the key-management handler, and
   ``IavPrimulaKeyFactory`` validates the KEM algorithm.

   The selected handler translates the request into a call through
   ``iav_primula_ffi.h`` to ``src/ffi.rs``. The current Rust entry point
   returns ``IavStatusUnsupportedAlgorithm`` before cryptographic processing
   because no concrete PQC implementation is connected.

Interfaces
----------

.. real_arc_int:: IAV Primula C-compatible interface
   :id: real_arc_int__iav_primula__c_abi
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp
   :fulfils: comp_req__iav_primula__provide_c_abi,
      comp_req__iav_primula__stable_status_codes,
      comp_req__iav_primula__stable_algorithm_ids,
      comp_req__iav_primula__opaque_key_handles

   The interface declares signature key generation, public-key export,
   signing, verification, KEM key generation, KEM public-key export,
   encapsulation, decapsulation, and key destruction. It exchanges stable
   status and algorithm identifiers and exposes keys through opaque handles.

Internal Components
-------------------

.. comp:: Primula Backend Adapter
   :id: comp__iav_primula_backend_adapter
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :belongs_to: feat__mtef

   Exposes the ``primula`` backend identifier and provider-creator callback.
   ``ScoreProviderFactory`` invokes the callback for a matching configured
   provider entry.

.. comp:: Primula Daemon Provider
   :id: comp__iav_primula_daemon_provider
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :belongs_to: feat__mtef

   Owns the Primula key factory and creates handlers that route SIGN,
   VERIFY, and KEM-related key-management requests to the
   C-compatible interface.

.. comp:: IAV Primula C ABI Boundary
   :id: comp__iav_primula_c_abi
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :belongs_to: feat__mtef

   Defines the public function signatures, status values, algorithm
   identifiers, and opaque key-handle type used across the C++ and
   Rust boundary.

.. comp:: IAV Primula Rust FFI Layer
   :id: comp__iav_primula_rust_ffi
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :belongs_to: feat__mtef

   Exports the C-compatible symbols from Rust. Its cryptographic
   entry points currently return ``IavStatusUnsupportedAlgorithm``
   without performing cryptographic processing.

.. comp:: Planned IAV Primula PQC Backend
   :id: comp__iav_primula_pqc_backend
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :belongs_to: feat__mtef

   Represents the concrete ML-DSA and ML-KEM implementation expected
   behind the Rust FFI. This backend is not connected in the current
   implementation.
