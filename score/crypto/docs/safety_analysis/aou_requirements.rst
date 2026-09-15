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

AoU Component Requirements
===========================

.. document:: Crypto Component AoU
   :id: doc__crypto_comp_aou
   :version: 1
   :status: draft
   :safety: ASIL_B
   :security: YES
   :realizes: wp__requirements_comp_aou

Hash Assumptions of Use
-----------------------

.. aou_req:: Use canonical hash identifiers
   :id: aou_req__crypto__canonical_hash_identifiers
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid

   The component user shall select SHA-256, SHA-384, and SHA-512 with the
   canonical identifiers ``SHA256``, ``SHA384``, and ``SHA512``. Hyphenated
   aliases such as ``SHA-256`` are not part of the current API contract.

.. aou_req:: Allocate hash output from the reported digest size
   :id: aou_req__crypto__hash_output_buffer
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid

   The component user shall provide a writable output buffer whose size is at
   least the value returned by ``IHashContext::GetDigestSize()`` and shall use
   the returned byte count when consuming the digest. A returned digest size of
   zero indicates that the daemon query failed and shall be treated as an
   operation failure rather than as a valid output size.

.. aou_req:: Verify provider and mechanism availability
   :id: aou_req__crypto__hash_provider_availability
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid

   The integrator shall ensure that the selected provider is configured and
   available. For a PKCS#11 provider, the selected token shall advertise the
   required SHA mechanism. Applications shall handle an unsupported-algorithm or
   provider-unavailable result without assuming a silent provider fallback.

.. aou_req:: Keep caller-owned buffers valid for each hash call
   :id: aou_req__crypto__hash_buffer_lifetime
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid

   The component user shall keep input and output buffers valid and unmodified
   for the duration of the corresponding synchronous ``Update()``,
   ``Finalize()``, or ``SingleShot()`` call.

.. aou_req:: Handle daemon and operation failures
   :id: aou_req__crypto__hash_failure_handling
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid

   The component user shall check every returned ``Result`` and define an
   application-level reaction for daemon unavailability, operation timeout,
   provider failure, invalid stream state, and insufficient output buffer.

.. aou_req:: Do not claim safety qualification for the current hash path
   :id: aou_req__crypto__hash_not_safety_qualified
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: ASIL_B
   :status: valid

   The integrator shall not use the current client, IPC and shared-memory,
   daemon, and OpenSSL or PKCS#11 hash path as an ISO 26262-qualified safety
   mechanism unless the complete deployed path has been independently qualified
   and the resulting safety case explicitly permits that use.

.. aou_req:: Restrict new migrations to approved hash algorithms
   :id: aou_req__crypto__hash_legacy_algorithms
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid

   New Baselibs migrations shall use ``SHA256``, ``SHA384``, or ``SHA512``.
   Existing SHA-224, SHA-1, and MD5 provider support is retained only for
   compatibility and shall not be interpreted as a recommendation for new use.

.. needextend:: "c.this_doc()"
   :+tags: crypto
