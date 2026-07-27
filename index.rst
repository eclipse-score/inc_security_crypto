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
=====================

This documentation describes the structure, usage, and configuration of the Crypto module in this repository, following the `SCORE module folder structure <https://eclipse-score.github.io/score/main/contribute/general/folder.html#module-folder-structure>`_ and the `SCORE building blocks concept <https://eclipse-score.github.io/process_description/main/general_concepts/score_building_blocks_concept.html>`_.

.. contents:: Table of Contents
   :depth: 2
   :local:

Overview
--------

This repository documents the Crypto module implementation, including its build, test, documentation, safety and security management, verification, and release workflows.
It provides the documentation artifacts needed for the Crypto module, including the component architecture documentation in :doc:`/score/crypto/docs/architecture/component_architecture` and the detailed design documentation in :doc:`/score/crypto/docs/detailed_design/detailed_design_example`.


Module Documentation
--------------------

The Crypto module provides a cryptographic middleware stack for automotive ECUs, including client-side APIs, a crypto daemon, provider integration, and supporting safety and security documentation.

The sections below provide the module-level documentation structure for these Crypto-specific artifacts, and additional content should be added in the relevant sections for feature architecture, safety analysis, security analysis, manuals, and related work products.

.. code-block:: rst

   .. mod:: Crypto Module
      :id: mod__crypto_module
      :includes: comp__crypto_component


   .. mod_view_sta:: Crypto Module Static View
      :id: mod_view_sta__crypto__module
      :includes: comp__crypto_component

      .. needarch::
         :scale: 50
         :align: center

         {{ draw_module(need(), needs) }}


.. toctree::
   :maxdepth: 1

   docs/index
   docs/manuals/index
   docs/release/release_note
   docs/features/index
   docs/safety_mgt/index
   docs/security_mgt/index
   docs/verification_report/module_verification_report


Component Documentation
-----------------------

For documentation of individual components within this module:

.. toctree::
   :maxdepth: 1

   score/crypto/docs/index
   score/iav_primula/docs/index
   score/crypto/src/daemon/data_manager/docs/index

Architecture Modeling Reference
--------------------------------

A reference for modeling the Crypto architecture in Sphinx Needs can be found in

.. toctree::
   :maxdepth: 1

   examples/docs/architecture_modeling_example


Please note that this is a reference model for using Sphinx Needs for architecture modeling, not the canonical architecture documentation for the Crypto module. The actual architecture documentation of the Crypto components and features should follow the provided guidance and module-specific content.


.. _quick-start-building-testing:

Quick Start - Building and Testing
==================================

To build the entire module:

.. code-block:: bash

   bazel build //score/...

To run all tests:

.. code-block:: bash

   bazel test //score/...


To run only component or feature integration tests:

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
