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

IAV Primula Requirements
########################

.. document:: IAV Primula Requirements
   :id: doc__iav_primula_requirements
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__requirements_comp[version==1]
   :tags: iav_primula

Scope
=====

This document specifies requirements for the IAV Primula Rust library
and its C-compatible interface, including interface compatibility,
status codes, algorithm identifiers, caller responsibilities, and
the build environment.

It records current implementation limitations separately from required
behavior. Provider registration and request routing within the crypto
daemon are outside the scope of this component requirements document.

Functional Requirements
-----------------------

.. comp_req:: Provide a C-compatible interface
   :id: comp_req__iav_primula__provide_c_abi
   :version: 1
   :reqtype: Interface
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   The IAV Primula component shall expose the functions declared in
   ``score/iav_primula/include/iav_primula_ffi.h`` through a C-compatible
   interface. The Rust implementation shall match the header's function
   names, parameter types, return types, and calling convention.

.. comp_req:: Preserve status code values
   :id: comp_req__iav_primula__stable_status_codes
   :version: 1
   :reqtype: Interface
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   The IAV Primula component shall use identical status code names
   and numeric values in the Rust implementation and C header.
   The following values shall remain unchanged:

   - ``IavStatusOk`` = 0
   - ``IavStatusInvalidArgument`` = 1
   - ``IavStatusBufferTooSmall`` = 2
   - ``IavStatusUnsupportedAlgorithm`` = 3
   - ``IavStatusVerificationFailed`` = 4
   - ``IavStatusCryptoFailure`` = 5

.. comp_req:: Preserve algorithm identifier values
   :id: comp_req__iav_primula__stable_algorithm_ids
   :version: 1
   :reqtype: Interface
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   The IAV Primula component shall use identical algorithm identifier
   names and numeric values in the Rust implementation and C header.
   The following values shall remain unchanged:

   - ``IavAlgorithmMlDsa44`` = 1
   - ``IavAlgorithmMlDsa65`` = 2
   - ``IavAlgorithmMlDsa87`` = 3
   - ``IavAlgorithmMlKem512`` = 10
   - ``IavAlgorithmMlKem768`` = 11
   - ``IavAlgorithmMlKem1024`` = 12

.. comp_req:: Keep key handles opaque
   :id: comp_req__iav_primula__opaque_key_handles
   :version: 1
   :reqtype: Interface
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   The IAV Primula component shall represent keys at the C-compatible
   interface through the opaque ``iav_primula_key_handle`` type.
   The public C header shall not expose the internal representation
   of a key handle.

.. comp_req:: Protect caller-provided output buffers
   :id: comp_req__iav_primula__protect_output_buffers
   :version: 1
   :reqtype: Interface
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   For cryptographic operations with an available implementation,
   each output-buffer length parameter shall specify the buffer
   capacity on input and the number of bytes written on success.

   The component shall not write beyond the supplied capacity.
   If the capacity is insufficient, it shall return
   ``IavStatusBufferTooSmall`` without producing a truncated
   cryptographic result.

.. comp_req:: Release resources when destroying a key
   :id: comp_req__iav_primula__key_handle_lifecycle
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   For a valid key handle returned by successful key generation,
   ``iav_key_destroy()`` shall release all backend resources
   associated with that handle.

.. comp_req:: Distinguish signature verification outcomes
   :id: comp_req__iav_primula__verification_outcomes
   :version: 1
   :reqtype: Interface
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   When signature verification completes, ``iav_verify()`` shall
   return ``IavStatusOk`` for a valid signature and
   ``IavStatusVerificationFailed`` for an invalid signature.

   ``iav_verify()`` shall return
   ``IavStatusVerificationFailed`` only when verification was
   performed and the signature was determined to be invalid.
   It shall not use this status when verification could not be
   performed.

.. comp_req:: Provide ML-DSA signature operations
   :id: comp_req__iav_primula__ml_dsa_operations
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   For supported ML-DSA algorithm identifiers, the IAV Primula
   component shall provide operations to generate a key pair,
   export its public key, sign a message, and verify a signature
   through the C-compatible interface.

.. comp_req:: Provide ML-KEM operations
   :id: comp_req__iav_primula__ml_kem_operations
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   For supported ML-KEM algorithm identifiers, the IAV Primula
   component shall provide operations to generate a key pair,
   export its public key, encapsulate a shared secret, and
   decapsulate a ciphertext through the C-compatible interface.

.. comp_req:: Validate pointer and length parameters
   :id: comp_req__iav_primula__pointer_length_validation
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   Before accessing memory, the IAV Primula component shall validate
   required pointer parameters. It shall also reject a null data
   pointer when its associated length is greater than zero.

   These invalid arguments shall result in
   ``IavStatusInvalidArgument``. The component shall not dereference
   a null pointer.

.. comp_req:: Validate all encapsulation output buffers before writing
   :id: comp_req__iav_primula__kem_output_buffers
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   Before writing an ML-KEM encapsulation result, the IAV Primula
   component shall validate the capacities of both the ciphertext
   buffer and the shared-secret buffer.

   If either buffer is insufficient, the operation shall return
   ``IavStatusBufferTooSmall`` without producing a partial
   encapsulation result.

.. comp_req:: Reject unsupported algorithm identifiers
   :id: comp_req__iav_primula__validate_algorithm_ids
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   Each operation that accepts an algorithm identifier shall verify
   that the identifier is supported for that operation.

   An unsupported identifier shall result in
   ``IavStatusUnsupportedAlgorithm`` and shall not cause key material
   or output buffers to be modified.

Current Implementation Status
-----------------------------

The Rust implementation exposes C-compatible entry points.
The C header and Rust library currently define matching entry-point
signatures, status codes, and algorithm identifiers. Existing Rust
tests verify the numeric enumeration values and confirm that the
placeholder operations return ``IavStatusUnsupportedAlgorithm``.

Key generation, public-key export, signing, signature verification,
and KEM encapsulation and decapsulation are currently placeholders
that return ``IavStatusUnsupportedAlgorithm``.

These entry points do not currently perform cryptographic operations
or produce cryptographic outputs. The ``iav_key_destroy()`` function
currently performs no action.

Assumption of Use Requirements
------------------------------

.. aou_req:: Integrate through the C-compatible interface
   :id: aou_req__iav_primula__c_abi_integration
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: invalid

   The integrating application shall include ``iav_primula_ffi.h``
   corresponding to the linked IAV Primula library and shall call
   the library through its declared C-compatible interface.

.. aou_req:: Check status before using cryptographic outputs
   :id: aou_req__iav_primula__check_operation_status
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: invalid

   The integrating application shall check the status returned by
   each cryptographic operation. When the status is not
   ``IavStatusOk``, it shall not use output buffers or returned
   key handles as successful results of that operation.

.. aou_req:: Manage generated key handle ownership
   :id: aou_req__iav_primula__key_handle_ownership
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: invalid

   The integrating application shall release each successfully
   generated key handle exactly once through ``iav_key_destroy()``
   when it is no longer needed. It shall not use the handle after
   destruction.

Environmental Requirements
--------------------------

.. aou_req:: Build environment supports Rust 2021
   :id: aou_req__iav_primula__rust2021_build_env
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: invalid
   :tags: environment

   The integrating project shall provide a Bazel build environment
   with the Rust rules and toolchain needed to build the IAV Primula
   targets defined in ``score/iav_primula/BUILD`` using Rust edition
   2021.

.. needextend:: "c.this_doc()"
   :+tags: iav_primula
