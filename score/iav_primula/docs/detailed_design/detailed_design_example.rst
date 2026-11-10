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

IAV Primula Detailed Design
===========================

.. document:: IAV Primula Detailed Design
   :id: doc__iav_primula_detailed_design
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__sw_implementation
   :tags: iav_primula

Detailed Design for Component: IAV Primula
==========================================

Description
-----------

The implementation spans the C++ Primula provider and the Rust FFI library.
The C++ units register the provider, select handlers, validate daemon requests,
manage key objects, and translate FFI status values into daemon errors.
``iav_primula_ffi.h`` defines the language boundary, while ``src/ffi.rs``
exports its Rust symbols.

The registration and routing units are implemented. The Rust cryptographic
functions remain placeholders that return ``IavStatusUnsupportedAlgorithm``.

Design constraints:

- Keep the C ABI, status values, and algorithm identifiers stable.
- Keep provider-specific behavior behind the daemon's generic provider,
  handler, and key-management interfaces.
- Validate algorithms, key ownership, pointers, and output sizes before
  accepting operation results.
- Keep native key handles under single ownership and destroy them through
  ``iav_key_destroy()``.

Current unit split:

- ``backend/score_provider/iav_primula/primula_backend_adapter.*``:
  exposes provider-creation metadata.
- ``iav_primula_provider.*`` and ``operations/factory/*``:
  initialize the provider and select operation handlers.
- ``operations/sign/*`` and ``operations/verify/*``:
  validate operation state and call the signature FFI functions.
- ``key_management/*``:
  manage key ownership and route key generation and KEM operations.
- ``include/iav_primula_ffi.h``:
  declares the stable C-compatible interface.
- ``src/ffi.rs``:
  exports the Rust ABI symbols and currently contains placeholder operations.

Rationale Behind Decomposition into Units
******************************************
The unit boundaries follow responsibility and language boundaries. The backend
adapter handles provider discovery, the provider and handler factory integrate
with daemon abstractions, operation handlers implement SIGN and VERIFY routing,
and the key-management units own keys and route KEM requests.

The C-compatible header separates the C++ units from the Rust FFI. This keeps
Rust representation details out of the daemon and provides a stable connection
point for the planned PQC implementation.

Static Diagrams for Unit Interactions
-------------------------------------

The unit dependency chain is:

``PrimulaBackendAdapter`` → ``IavPrimulaProvider`` →
``IavPrimulaHandlerFactory`` or ``IavPrimulaKeyFactory`` →
operation-specific handler → ``iav_primula_ffi.h`` → ``src/ffi.rs`` →
planned PQC backend.

The component architecture provides the static component view. The final
dependency in this chain is currently absent because the concrete PQC backend
is not connected.

Dynamic Design for SIGN and VERIFY
-----------------------------------

The SIGN and VERIFY flow is:

1. The daemon requests a handler for a PQC signature algorithm.
2. ``IavPrimulaHandlerFactory`` validates the algorithm and creates the
   corresponding handler.
3. The handler validates its key and operation inputs.
4. The handler calls ``iav_sign()`` or ``iav_verify()`` through the C ABI.
5. The returned ``iav_status`` is translated into a daemon result.

The current flow reaches step 4, where the Rust placeholder returns
``IavStatusUnsupportedAlgorithm``. No signature is generated or verified.

Dynamic Design for Key Generation and KEM
-----------------------------------------

The key-management flow is:

1. ``IavPrimulaKeyFactory`` validates the requested PQC algorithm.
2. Key generation calls the ML-DSA or ML-KEM FFI generation function.
3. On success, the public key is exported and the native handle is wrapped in
   ``IavPrimulaKeyHandler``.
4. Encapsulation validates a public ML-KEM key, allocates ciphertext and
   shared-secret buffers, and calls ``iav_kem_encapsulate()``.
5. Decapsulation validates a private ML-KEM handle and ciphertext, then calls
   ``iav_kem_decapsulate()``.
6. Successful shared secrets are wrapped in
   ``IavPrimulaSharedSecretHandler``; failures are mapped to daemon errors.

Currently, key generation, public-key export, encapsulation, and decapsulation
return ``IavStatusUnsupportedAlgorithm`` at the Rust FFI boundary. No native
key or shared secret is produced.

FFI Representation
------------------

The Rust functions use ``extern "C"`` and ``#[no_mangle]`` so their exported
symbols and calling convention match ``iav_primula_ffi.h``. The
``iav_status`` and ``iav_algorithm`` enums use ``#[repr(C)]`` with fixed
numeric values shared with the C declarations.

``iav_primula_key_handle`` is opaque. C++ code may pass its pointer through
the defined interface but cannot access its Rust representation.

The current cryptographic entry points ignore their parameters and return
``IavStatusUnsupportedAlgorithm``. They do not dereference input pointers or
write output buffers. ``iav_key_destroy()`` is currently a no-op.

Ownership, Buffer, and Error Handling
-------------------------------------

A successful key-generation call is intended to transfer ownership of the
opaque key handle to C++. ``IavPrimulaKeyHandler`` stores that handle and must
release it through ``iav_key_destroy()``.

Callers provide output buffers and their capacities to the FFI. The FFI reports
the produced length through the corresponding output-length pointer. Invalid
pointers, insufficient buffer capacity, unsupported algorithms, and internal
failures are represented by distinct ``iav_status`` values.
