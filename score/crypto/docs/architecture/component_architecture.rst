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

.. document:: Crypto Component Architecture
   :id: doc__crypto_comp_architecture
   :status: draft
   :safety: ASIL_B
   :security: YES
   :realizes: wp__component_arch


Overview
--------

<Brief summary of the architecture.>

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

<General Description>

<Design Decisions - For the documentation of the decision the :need:`gd_temp__change_decision_record` can be used.>

<Design Constraints>

Rationale Behind Architecture Decomposition
*******************************************

Mandatory: A motivation for the decomposition or reason for not further splitting it into internal components.

.. note:: Common decisions across components / cross cutting concepts is at the higher level.

Static Architecture
-------------------

The components are designed to cover the expectations from the feature architecture
(i.e. if already exists a definition it should be taken over and enriched).

A component can optional also consist of lower level components to further structure the architecture. The component and its static views can also optionally use interfaces provided by other components.

.. code-block::

   .. comp:: Crypto Component
      :id: comp__mod_temp_crypto
      :security: YES
      :safety: ASIL_B
      :status: valid
      :consists_of:
      :belongs_to: feat__mtef

.. code-block::

   .. comp_arc_sta:: Crypto Component (Static View)
      :id: comp_arc_sta__mod_temp_crypto__sv
      :security: YES
      :safety: ASIL_B
      :status: valid
      :belongs_to: comp__mod_temp_crypto
      :fulfils: comp_req__mod_temp_crypto__some_title

      .. needarch::
         :scale: 50
         :align: center

         {{ draw_component(need(), needs) }}

Dynamic Architecture
--------------------

.. code-block::

   .. comp_arc_dyn:: Dynamic View
      :id: comp_arc_dyn__mod_temp_crypto__dv
      :security: YES
      :safety: ASIL_B
      :status: valid
      :belongs_to: comp__mod_temp_crypto
      :fulfils: comp_req__mod_temp_crypto__some_title

      Put here a sequence diagram

Interfaces
----------

.. code-block:: rst

   .. real_arc_int:: <Title>
      :id: real_arc_int__<component>__<Title>
      :security: <YES|NO>
      :safety: <QM|ASIL_B>
      :fulfils: <link to component requirement id>
      :language: cpp

Internal Components
-------------------

.. code-block::

   .. comp_arc_sta:: Crypto Component Static View
      :id: comp_arc_sta__mod_temp_crypto__2
      :status: valid
      :safety: ASIL_B
      :security: YES
      :fulfils: comp_req__mod_temp_crypto__some_title
      :belongs_to: comp__mod_temp_component_example_2

      No architecture but detailed design

.. note::
   Architecture can be split into multiple files. At component level the public interfaces to be used by the user and tester to be shown.
