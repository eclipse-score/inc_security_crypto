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

Crypto Requirements
###################

.. document:: Crypto Requirements
   :id: doc__crypto_requirements
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__requirements_comp[version==1]

Hash Functionality
==================

The requirements in this section specify behavior provided by the Crypto
component's hash API. They do not make qualification claims about a complete
deployed system.

.. comp_req:: Support SHA-2 hash algorithms
   :id: comp_req__crypto__hash_algorithms
   :version: 1
   :reqtype: Functional
   :derived_from: feat_req__sec_crypt__hashing_algo_sha2
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto

   The Crypto component shall provide SHA-256, SHA-384, and SHA-512 hash
   operations through the canonical algorithm identifiers ``SHA256``,
   ``SHA384``, and ``SHA512`` respectively.

.. comp_req:: Provide streaming hash operation
   :id: comp_req__crypto__hash_streaming
   :version: 1
   :reqtype: Functional
   :derived_from: feat_req__sec_crypt__hashing
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto

   The Crypto component shall support incremental hashing through the ordered
   ``Init()``, zero or more ``Update()``, and ``Finalize()`` operations.

.. comp_req:: Provide single-shot hash operation
   :id: comp_req__crypto__hash_single_shot
   :version: 1
   :reqtype: Functional
   :derived_from: feat_req__sec_crypt__hashing
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto

   The Crypto component shall support hashing an input buffer through
   ``SingleShot()`` and shall produce the same digest as the corresponding
   streaming operation.

.. comp_req:: Report hash digest size
   :id: comp_req__crypto__hash_digest_size
   :version: 1
   :reqtype: Interface
   :derived_from: feat_req__sec_crypt__hashing
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto

   The Crypto component shall report digest sizes of 32, 48, and 64 bytes for
   ``SHA256``, ``SHA384``, and ``SHA512`` respectively.

.. comp_req:: Reject undersized hash output buffers
   :id: comp_req__crypto__hash_output_buffer
   :version: 1
   :reqtype: Interface
   :derived_from: feat_req__sec_crypt__hashing
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto

   The Crypto component shall reject a hash operation when the caller-provided
   output buffer is smaller than the digest size of the configured algorithm.
   For a streaming operation, this validation error shall not consume the
   active digest state, allowing ``Finalize()`` to be retried with a sufficient
   output buffer.

.. comp_req:: Reject unsupported hash algorithms
   :id: comp_req__crypto__hash_unsupported_algorithm
   :version: 1
   :reqtype: Functional
   :derived_from: feat_req__sec_crypt__hashing
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto

   The Crypto component shall report an unsupported-algorithm error when a hash
   algorithm cannot be resolved by the selected provider and shall not substitute
   a digest size or another algorithm.

.. comp_req:: Maintain provider-equivalent hash results
   :id: comp_req__crypto__hash_provider_parity
   :version: 1
   :reqtype: Functional
   :derived_from: feat_req__sec_crypt__hashing
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto

   For each hash algorithm supported by multiple providers, those providers
   shall produce identical digests for identical input bytes.

.. comp_req:: Honor preferred-provider fallback
   :id: comp_req__crypto__hash_provider_fallback
   :version: 1
   :reqtype: Functional
   :derived_from: feat_req__sec_crypt__sw_fallback
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto

   When a hash context requests a preferred provider category, the Crypto
   component shall use the corresponding fallback category only if the preferred
   provider is unavailable or does not support the requested hash algorithm.

.. comp_req:: Reset reusable hash contexts
   :id: comp_req__crypto__hash_context_reset
   :version: 1
   :reqtype: Functional
   :derived_from: feat_req__sec_crypt__hashing
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto

   The Crypto component shall allow an initialized or completed hash context to
   be reset to the idle state without changing its algorithm or provider binding.

.. needextend:: "c.this_doc()"
   :+tags: crypto
