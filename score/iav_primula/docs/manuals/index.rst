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

IAV Primula Integration Manual
==============================

.. document:: IAV Primula Integration Manual
   :id: doc__iav_primula_integration_manual
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__training_path[version==1]
   :tags: iav_primula

This manual explains how to configure and use the current IAV Primula provider
skeleton and describes the limitations that integrators must consider.

Scope and Current Status
------------------------

The current implementation provides registration, provider selection, handler
routing, key-management integration, and a C/Rust FFI for ML-DSA and ML-KEM.

It is an integration skeleton, not a functional PQC implementation. The Rust
cryptographic entry points return ``IavStatusUnsupportedAlgorithm``; therefore,
key generation, signing, verification, encapsulation, and decapsulation do not
currently produce cryptographic results.

Provider Availability and Registration
--------------------------------------

The Primula adapter is included in the active score-provider backend list. At
daemon startup, ``ScoreProviderConfig::ParseConfig()`` enumerates the linked
backends and creates the Primula entry automatically with:

- provider implementation: ``primula``
- provider name: ``PRIMULA``
- default provider type: ``SPECIALIZED``

The current parser does not read these values from an external configuration
file. ``ScoreProviderFactory`` registers the provider using the values in the
generated entry.

Provider Selection Limitation
-----------------------------

The public ``ProviderType`` API currently exposes default, hardware, software,
and preferred variants, but it does not expose a specialized-provider value.
Consequently, a client cannot explicitly select Primula by provider type.
Registration alone does not guarantee that a default request is routed to
Primula; daemon-internal lookup by provider name or identifier is separate from
the public selection API.

Recognized Algorithms
---------------------

The routing and FFI interfaces recognize these algorithm identifiers:

- ``ML-DSA-44``, ``ML-DSA-65``, and ``ML-DSA-87`` for signatures
- ``ML-KEM-512``, ``ML-KEM-768``, and ``ML-KEM-1024`` for key encapsulation

Recognition means that the integration layer can validate and route the
identifier. It does not mean that the current Rust placeholder implements the
algorithm.

Build Integration
-----------------

Primula is linked when both Bazel flags
``//score/crypto/src/backend:score_crypto_score_backend_enabled`` and
``//score/crypto/src/backend:score_crypto_score_primula_enabled`` are true.
Both flags are enabled by default.

The C declarations are provided by
``//score/iav_primula:iav_primula_ffi_headers``, and the Rust symbols are linked
from ``//score/iav_primula:iav_primula_staticlib``. The daemon provider target
depends on both targets.

Expected Runtime Behavior
-------------------------

If a request reaches a current Primula FFI entry point, it returns
``IavStatusUnsupportedAlgorithm``. The C++ integration maps this to an
unsupported-algorithm or operation-failed result, depending on the call path.
Applications must treat either result as a failed operation and must not use an
output key, signature, ciphertext, or shared secret.

The placeholder functions do not dereference their input pointers or write to
output buffers. ``iav_key_destroy()`` is currently a no-op because no native key
objects are created.

FFI Usage Rules
---------------

Code that integrates directly with ``iav_primula_ffi.h`` shall:

- treat ``iav_primula_key_handle`` as opaque and never inspect its contents;
- release every successfully generated handle with ``iav_key_destroy()``;
- provide valid input pointers for every non-empty input;
- initialize each output-length value with the corresponding buffer capacity;
- use an output only after ``IavStatusOk`` and the returned length have been
  validated; and
- treat ``IavStatusVerificationFailed`` as an invalid signature, not as an
  internal execution failure.

These rules describe the stable interface contract intended for the future
backend as well as the C++ integration code.

Developer Verification
----------------------

Run the Primula-specific tests with:

.. code-block:: bash

   bazel test //score/iav_primula/tests:ffi_test \
     //score/crypto/src/daemon/provider/score_provider/iav_primula/tests:iav_primula_key_management_test \
     //score/crypto/src/daemon/provider/score_provider/iav_primula/tests:iav_primula_signature_test \
     //score/crypto/src/daemon/provider/score_provider/iav_primula/tests:iav_primula_verification_test \
     //score/crypto/src/daemon/provider/score_provider/iav_primula/tests/integration_tests:iav_primula_application_integration_test

These tests cover registration, validation, routing, status mapping, and current
placeholder behavior. They do not demonstrate ML-DSA or ML-KEM cryptographic
correctness.
