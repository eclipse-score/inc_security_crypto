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

This documentation describes the structure, usage and configuration of the Bazel-based C++/Rust module template according to the `SCORE module folder structure <https://eclipse-score.github.io/score/main/contribute/general/folder.html#module-folder-structure>`_ and the `SCORE building blocks concept <https://eclipse-score.github.io/process_description/main/general_concepts/score_building_blocks_concept.html>`_.

.. contents:: Table of Contents
   :depth: 2
   :local:

Overview
--------

This repository provides a standardized setup for projects using **C++** or **Rust** and **Bazel** as a build system.
It integrates best practices for build, test, CI/CD and documentation.
It also provides an example for the documentation of an module with all necessary artifacts for safety and security management, verification and release management.
It also provides the component architecture template snippets in :doc:`/score/crypto/docs/architecture/component_architecture`.
It also provides an example of documenting detailed design in :doc:`/score/crypto/docs/detailed_design/detailed_design_example`.


Module Documentation
--------------------

<Brief description of the module and the implemented feature(s).>

<Module sphinx documentation template snippets for the module. The directives and their parameters
should be updated according to the module and it's components. Further documentation of the module
and the implemented feature(s) should be added in the respective sections of the documentation
(e.g., feature architecture, safety analysis, security analysis, manuals, etc.) following the provided
templates and guidelines.>

.. code-block:: rst

   .. mod:: Module Name
      :id: mod__module_name
      :includes: comp__component_name_template


   .. mod_view_sta:: Module Name Static View
      :id: mod_view_sta__feature_name__module_name
      :includes: comp__component_name_template

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

Architecture Modeling Example
-----------------------------

An example of modeling architecture in Sphinx Needs can be found in

.. toctree::
   :maxdepth: 1

   examples/docs/architecture_modeling_example


Please note, that is not a template for architecture documentation, but an example of how to use Sphinx Needs for architecture modeling. The architecture documentation of the components and features of the module should follow the provided templates and guidelines.


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
