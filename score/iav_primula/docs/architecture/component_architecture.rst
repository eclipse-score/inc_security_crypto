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

Component Architecture Documentation
====================================

.. document:: IAV Primula Architecture
   :id: doc__iav_primula_architecture
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__component_arch
   :tags: iav_primula


Overview
--------

The IAV Primula component is a lightweight Rust library exposing one public API
to return a deterministic baseline message.

Requirements Linked to Component Architecture
---------------------------------------------

.. code-block:: none

   .. needtable:: Overview of Component Requirements
      :style: table
      :columns: title;id
      :filter: search("comp_arch_sta__archdes$", "fulfils_back")
      :colwidths: 70,30

Description
-----------

The component currently has no internal sub-components. Public API and
implementation are both located in ``src/main.rs``.

Design constraints:

- Keep API deterministic and side-effect free.
- Keep implementation simple for initial onboarding and traceability.

Rationale Behind Architecture Decomposition
*******************************************

No decomposition into lower-level components is introduced in this initial
version because complexity is low and responsibilities are clear.

.. note:: Common decisions across components / cross cutting concepts is at the higher level.

Static Architecture
-------------------

The components are designed to cover the expectations from the feature architecture
(i.e. if already exists a definition it should be taken over and enriched).

A component can optional also consist of lower level components to further structure the architecture. The component and its static views can also optionally use interfaces provided by other components.

.. comp:: IAV Primula
   :id: comp__iav_primula
   :version: 1
   :security: YES
   :safety: QM
   :status: valid
   :belongs_to: feat__mtef

.. comp_arc_sta:: IAV Primula Static View
   :id: comp_arc_sta__iav_primula__sv
   :version: 1
   :security: YES
   :safety: QM
   :status: valid
   :belongs_to: comp__iav_primula
   :fulfils: comp_req__iav_primula__provide_hello_message

   .. needarch::
      :scale: 50
      :align: center

      {{ draw_component(need(), needs) }}

Dynamic Architecture
--------------------

.. comp_arc_dyn:: IAV Primula Dynamic View
   :id: comp_arc_dyn__iav_primula__dv
   :version: 1
   :security: YES
   :safety: QM
   :status: valid
   :belongs_to: comp__iav_primula
   :fulfils: comp_req__iav_primula__provide_hello_message

   Caller invokes ``get_hello_message()`` and receives the constant baseline
   string response immediately.

Interfaces
----------

.. real_arc_int:: Public hello message interface
   :id: real_arc_int__iav_primula__get_hello_message
   :version: 1
   :security: NO
   :safety: QM
   :status: valid
   :language: rust

Internal Components
-------------------

No internal components are defined in this baseline version.

.. note::
   Architecture can be split into multiple files. At component level the public interfaces to be used by the user and tester to be shown.
