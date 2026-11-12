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

Crypto Documentation
====================

This repository provides the cryptographic services of the Eclipse S-CORE
:need:`feat__security_crypto`.
The Crypto module offers applications a common interface for key management,
symmetric and asymmetric cryptography, hashing, digital signatures, and
certificate handling, and post-quantum cryptography, with support for software
and hardware-backed cryptographic providers. Its scope is cryptographic services,
rather than all use cases covered by Security & Crypto.

Feature Documentation
---------------------

The feature documentation describes Crypto's architecture, safety and security
planning, and analyses.

.. toctree::
   :maxdepth: 1

   /docs/features/index

.. needtable::
   :filter: docname is not None and docname.startswith("docs/features/")
   :style: table
   :types: document
   :columns: title;id;safety;security;status
   :colwidths: 25,35,15,15,15
   :sort: title

Module Documentation
--------------------

The module documentation covers the implementation overview, manuals, safety and
security management, and verification report.

.. toctree::
   :maxdepth: 1

   /docs/module/index
   /docs/verification_report/module_verification_report

.. needtable::
   :filter: docname is not None and docname.startswith(("docs/module/", "docs/verification_report/"))
   :style: table
   :types: document
   :columns: title;id;safety;security;status
   :colwidths: 25,35,15,15,15
   :sort: title

Component Documentation
-----------------------

The component documentation provides requirements, architecture, detailed design,
and analyses for the individual components of the Crypto module.

.. toctree::
   :maxdepth: 1

   /docs/components/index

.. needtable::
   :filter: docname is not None and docname.startswith(("score/crypto/", "score/cryptoki/", "score/iav_primula/"))
   :style: table
   :types: document
   :columns: title;id;safety;security;status
   :colwidths: 25,35,15,15,15
   :sort: title

.. _quick-start-building-testing:

Quick Start - Building and Testing
-----------------------------------

To build the entire module:

.. code-block:: bash

   bazel build //score/...

To run all tests:

.. code-block:: bash

   bazel test //score/...

Module Build Configuration
--------------------------

The ``project_config.bzl`` file at the root of the module defines metadata used by Bazel macros.
This file controls build behavior and project-specific settings. It should follow the S-CORE definition.
See `S-CORE user guide for project_config.bzl <https://eclipse-score.github.io/score/main/users_guide/building_simple_application/first_score_module.html#project-config-bzl>`_ for details.

The configuration enables conditional build behavior:

* **Language-specific tools**: For C++ code, tools like ``clang-tidy`` are used; for Rust code, ``clippy`` is used
* **Safety level**: The ASIL level affects safety-related build settings and validation
* **Source code languages**: The build system optimizes for the configured languages
