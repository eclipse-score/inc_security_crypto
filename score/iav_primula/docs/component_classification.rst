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

Component Classification
========================

.. note:: Document header

.. document:: IAV Primula Component Classification
   :id: doc__iav_primula_comp_class
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__sw_component_class
   :tags: iav_primula

| Classification of ``iav_primula``
|
| GitHub: ``https://github.com/eclipse-score/inc_security_crypto/tree/main/score/iav_primula``
|
| Additional documentation considered:
| - ``docs/index.rst``
| - ``docs/requirements/requirements.rst``
| - ``docs/architecture/component_architecture.rst``


Step 1: Determine (P): the uncertainty of the Processes applied
---------------------------------------------------------------

| Apply the process measures to determine (P).
| The result of a process measure shall have as outcome [HE, PE, NE]
| - HE: High Evidence
| - PE: Partly Evidence but Manageable
| - NE: No Evidence

.. list-table:: Determine (P)
        :header-rows: 1

        * - Id
          - Indicator for applying process
          - Result
          - Rationale for result

        * - 1
          - Are rules, state-of-the art processes applied for the design, implementation and verification?
          - HE
          - Project rules are applied to the C++ provider integration, Rust 2021
            FFI library, Bazel targets, tests, and documentation structure.

        * - 2
          - Are requirements available?
          - HE
          - Initial component requirements are documented.

        * - 3
          - Are specifications for functionalities and properties available (architecture)?
          - HE
          - Initial component architecture documentation is available.

        * - 4
          - Are design specifications available?
          - HE
          - Detailed design covers the current provider and FFI integration
            skeleton.

        * - 5
          - Are configuration specification and data available, if applicable?
          - HE
          - No dedicated configuration data is currently required.

        * - 6
          - Are verification measures including tests and reports available?
          - HE
          - FFI tests and C++ provider tests cover enumeration values, registration,
            routing, validation, error mapping, and placeholder behavior. They do
            not verify cryptographic correctness.


| (P=1) shall be selected when none of the determined process measures indicate PE or NE.
| (P=2) shall be selected when at least one of the determined process measures indicate PE or NE, but the gaps evaluated are acceptable, means
|       the risk of systematic faults due to these gaps is sufficiently low or manageable by mitigating the gaps.
| (P=3) in all other cases.

``iav_primula`` is determined as ``P=1``


Step 2: Determine (C): the uncertainty of finding systematic faults based on the Complexity
-------------------------------------------------------------------------------------------

| Apply the complexity measures to determine (C).
| The result of a complexity measure shall have as outcome [NH, HM, NM]
| - NH: Not High
| - HM: High but Manageable
| - NM: high and Not Manageable
|
| **Complexity measure for programming languages: C++ and RUST**

.. list-table:: Determine (C) for C++ and RUST
    :header-rows: 1

    * - Id
      - Indicator for high Complexity
      - Complexity measure Tool
      - Result
      - Number

    * - 1
      - High amount of Lines of Code
      - Physical source-line count across the production Rust, C++, and header
        units; comments and header lines are included as a conservative upper
        bound.
      - NH
      - 17 production units with 1,642 physical lines.

    * - 2
      - Unsafe Rust or unchecked FFI memory access
      - Search for Rust ``unsafe`` blocks and review raw-pointer use at the C ABI.
      - NH
      - 0 Rust ``unsafe`` blocks; the placeholder entry points do not dereference
        their raw-pointer parameters.

    * - 3
      - Tests exist for the implemented integration behavior
      - Count Rust ``#[test]`` cases and C++ ``TEST`` cases; review their scope.
      - NH
      - 36 tests: 2 Rust FFI tests and 34 C++ provider/integration tests. They
        cover the skeleton but not cryptographic correctness.

    * - 4
      - High amount of public function interfaces
      - Count exported ``extern "C"`` entry points.
      - NH
      - 9 C ABI functions.

    * - 5
      - High amount of function parameters
      - Maximum parameter count among C ABI entry points.
      - NH
      - 7 parameters for ``iav_kem_encapsulate()``.


| (C=1) shall be selected when none of the determined complexity measures indicate HM or NM.
| (C=2) shall be selected when at least one of the determined complexity measures indicate HM or NM, but the gaps evaluated are acceptable, means
|       the risk of systematic faults due to these gaps is sufficiently low in the context of the project or manageable by mitigating the gaps.
| (C=3) in all other cases.
|

``iav_primula`` is determined as ``C=1``


Step 3: Determine (CLAS_OUT): the classification outcome
--------------------------------------------------------

| Select CLAS_OUT depending on the determined values of (C) and (P)

+-------+-----------------------+
| ( C ) | ( P )                 |
+-------+-------+-------+-------+
|       |  1    |  2    |  3    |
+=======+=======+=======+=======+
| 1     |  Q    |  Q    | QR    |
+-------+-------+-------+-------+
| 2     |  QR   | QR    | QR    |
+-------+-------+-------+-------+
| 3     |  QR   | QR    | NQ    |
+-------+-------+-------+-------+

``iav_primula`` is classified as ``CLAS_OUT=Q``


Step 4: Document all results and rationale for choosing (P) and (C) and (CLAS_OUT)
----------------------------------------------------------------------------------
This document


Step 5: Based on (CLAS_OUT) select the activities
-------------------------------------------------

| As soon as the change request containing this is in status "Accepted", the module safety plan for the component development is adapted based on the following: (select according to above result)
| - Q: Follow the processes for qualification of software components in a safety context.
| - QR: Follow the process for pre-existing software architectural elements
| - NQ: Do no use this element in safety context
