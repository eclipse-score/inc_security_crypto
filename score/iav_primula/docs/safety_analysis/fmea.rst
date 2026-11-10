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


FMEA (Failure Modes and Effects Analysis)
=========================================

.. document:: IAV Primula FMEA
   :id: doc__iav_primula_fmea
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__sw_component_fmea
   :tags: iav_primula

.. note::
   The component is classified ``QM``. This analysis covers failure modes of the
   current provider registration, routing, key-management, and C/Rust FFI
   skeleton. No functional PQC backend is connected.

Failure Mode List
-----------------

.. list-table:: Fault Models for sequence diagrams
    :header-rows: 1
    :widths: 10,20,10,20

    * - ID
      - Failure Mode
      - Applicability
      - Rationale
    * - MF_01_01
      - request is not received
      - yes
      - Registration or routing failure can prevent a request from reaching the
        Primula handler. The operation must fail without producing output.
    * - MF_01_02
      - request is received too late
      - no
      - No timing requirement is allocated to the current ``QM`` component.
    * - MF_01_03
      - request is received too early
      - no
      - The current interfaces use synchronous calls without an early-arrival
        protocol state.
    * - MF_01_04
      - request is not received correctly by all recipients
      - no
      - A Primula operation is routed to one handler; no fan-out distribution is
        implemented.
    * - MF_01_05
      - request data is corrupted
      - yes
      - Invalid algorithms, keys, pointers, or lengths can cross the integration
        boundary. Validation and non-success status values prevent their results
        from being accepted.
    * - MF_01_06
      - result is not returned
      - yes
      - Handler or FFI failure can prevent completion. The caller must treat an
        absent result as an operation failure.
    * - MF_01_07
      - result is returned unintentionally
      - no
      - The component does not autonomously initiate operations or emit
        cryptographic results.
    * - CO_01_01
      - minimum size or capacity boundary is violated
      - yes
      - Undersized algorithm data or output capacity can make an operation
        invalid. Handlers validate fixed algorithm sizes, and the FFI contract
        provides ``IavStatusBufferTooSmall``.
    * - CO_01_02
      - maximum size or capacity boundary is violated
      - yes
      - Oversized or inconsistent key, signature, ciphertext, and output lengths
        must be rejected before a result is accepted.
    * - EX_01_01
      - processing produces an incorrect result
      - yes
      - Incorrect routing, status mapping, or output-length handling could make a
        failed operation appear successful. Callers accept output only after
        checking ``IavStatusOk`` and the expected length.
    * - EX_01_02
      - processing is too slow
      - no
      - No execution-time requirement is allocated to the current ``QM``
        component.
    * - EX_01_03
      - processing is too fast
      - no
      - No minimum execution-time constraint is allocated.
    * - EX_01_04
      - loss of execution
      - yes
      - Provider, handler, or FFI failure can prevent an operation from
        completing. The failure must be reported without usable output.
    * - EX_01_05
      - processing changes to an arbitrary process
      - no
      - The component has no process-control mode or autonomous state transition.
    * - EX_01_06
      - processing does not complete
      - no
      - Current Rust placeholders return immediately and the C++ routing paths
        contain no unbounded loop. Reassess when a PQC backend is connected.

FMEA
----

No formal ``comp_saf_fmea`` entries are required because no safety requirements
are allocated to this ``QM`` component. The table records applicable integration
failure modes and the current error-handling measures.

The placeholder backend fails operations with
``IavStatusUnsupportedAlgorithm`` and produces no cryptographic output.
Re-evaluate the failure modes and add formal entries when a functional PQC
backend or safety-relevant requirements are introduced.
