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
   Current component scope is ``QM`` and contains only deterministic in-process
   string return behavior. The generic fault model is recorded as not applicable
   for this baseline.

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
      - message is not received (is a subset/more precise description of MF_01_05)
      - no
      - No inter-component messaging in current scope.
    * - MF_01_02
      - message received too late (only relevant if delay is a realistic fault)
      - no
      - No timing-critical communication path in current scope.
    * - MF_01_03
      - message received too early (usually not a problem)
      - no
      - No timing-dependent message protocol is implemented.
    * - MF_01_04
      - message not received correctly by all recipients (different messages or messages partly lost). Only relevant if the same message goes to multiple recipients.
      - no
      - No fan-out message distribution exists.
    * - MF_01_05
      - message is corrupted
      - no
      - No message transport layer in current scope.
    * - MF_01_06
      - message is not sent
      - no
      - No send operation is implemented.
    * - MF_01_07
      - message is unintended sent
      - no
      - Component does not emit external messages.
    * - CO_01_01
      - minimum constraint boundary is violated
      - no
      - No numerical safety boundary handling in current scope.
    * - CO_01_02
      - maximum constraint boundary is violated
      - no
      - No numerical safety boundary handling in current scope.
    * - EX_01_01
      - Process calculates wrong result(s) (subset of data corruption faults)
      - no
      - Function returns a fixed literal without algorithmic processing.
    * - EX_01_02
      - processing too slow (only relevant if timing is considered)
      - no
      - No timing requirement allocated to current baseline function.
    * - EX_01_03
      - processing too fast (only relevant if timing is considered)
      - no
      - No minimum timing constraint allocated.
    * - EX_01_04
      - loss of execution
      - no
      - Not safety-relevant in current ``QM`` scope.
    * - EX_01_05
      - processing changes to arbitrary process
      - no
      - No process control behavior is implemented.
    * - EX_01_06
      - processing is not complete (infinite loop)
      - no
      - Function body is finite and constant.

FMEA
----

No ``comp_saf_fmea`` entries are required for the current baseline.
Re-evaluate this document once safety-relevant behavior is introduced.