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

.. _definition_architectural_design:

Example model of architectural design
#####################################

This chapter only serves as an example how an architecture could be modeled in *Sphinx Needs*. All the needs are required to print the views which are displayed in the Static- and Interface Views. In the actual process this files would be split into multiple different files:

Feature Architecture File
=========================

.. note:: The feature and the logical interfaces are normally defined in the platform repo (`features folder <https://eclipse-score.github.io/score/main/features/index.html>`_) and imported from there as sphinx needs objects. In this example it is defined here only, to hold the example consistent.

.. feat:: Feature 1
   :id: feat__mtef
   :security: YES
   :safety: QM
   :status: valid
   :includes: logic_arc_int__example_feature__if_1, logic_arc_int__example_feature__if_2, logic_arc_int__example_feature__if_3

   This is the example feature which shall normally defined in the platform repo.

.. feat_arc_sta:: Feature 1 Static View
   :id: feat_arc_sta__example_feature__sta
   :security: YES
   :safety: QM
   :status: valid
   :includes: logic_arc_int__example_feature__if_1, logic_arc_int__example_feature__if_2, logic_arc_int__example_feature__if_3
   :fulfils: feat_req__example_feature__example_req
   :belongs_to: feat__mtef

   .. needarch::
      :scale: 50
      :align: center

      {{ draw_feature(need(), needs) }}

.. Logical Interfaces

.. logic_arc_int:: Logical Interface 1
   :id: logic_arc_int__example_feature__if_1
   :security: YES
   :safety: ASIL_B
   :status: valid
   :fulfils: feat_req__example_feature__example_req

   .. needarch::
      :scale: 50
      :align: center

      {{ draw_interface(need(), needs) }}


.. logic_arc_int:: Logical Interface 2
   :id: logic_arc_int__example_feature__if_2
   :security: YES
   :safety: ASIL_B
   :status: valid
   :fulfils: feat_req__example_feature__example_req

   .. needarch::
      :scale: 50
      :align: center

      {{ draw_interface(need(), needs) }}


.. logic_arc_int:: Logical Interface 3
   :id: logic_arc_int__example_feature__if_3
   :security: YES
   :safety: ASIL_B
   :status: valid
   :fulfils: feat_req__example_feature__example_req


.. Logical Interface Operation

.. logic_arc_int_op:: Logical Operation 1
   :id: logic_arc_int_op__example_feature__op_1
   :security: YES
   :safety: ASIL_B
   :status: valid
   :included_by: logic_arc_int__example_feature__if_1

.. logic_arc_int_op:: Logical Operation 2
   :id: logic_arc_int_op__example_feature__op_2
   :security: YES
   :safety: ASIL_B
   :status: valid
   :included_by: logic_arc_int__example_feature__if_1

.. logic_arc_int_op:: Logical Operation 3
   :id: logic_arc_int_op__example_feature__op_3
   :security: YES
   :safety: ASIL_B
   :status: valid
   :included_by: logic_arc_int__example_feature__if_2

.. logic_arc_int_op:: Logical Operation 4
   :id: logic_arc_int_op__example_feature__op_4
   :security: YES
   :safety: ASIL_B
   :status: valid
   :included_by: logic_arc_int__example_feature__if_2

.. logic_arc_int_op:: Logical Operation 5
   :id: logic_arc_int_op__example_feature__op_5
   :security: YES
   :safety: ASIL_B
   :status: valid
   :included_by: logic_arc_int__example_feature__if_3

.. logic_arc_int_op:: Logical Operation 6
   :id: logic_arc_int_op__example_feature__op_6
   :security: YES
   :safety: ASIL_B
   :status: valid
   :included_by: logic_arc_int__example_feature__if_3

.. logic_arc_int_op:: Logical Operation 7
   :id: logic_arc_int_op__example_feature__op_7
   :security: YES
   :safety: ASIL_B
   :status: valid
   :included_by: logic_arc_int__example_feature__if_3

.. logic_arc_int_op:: Logical Operation 8
   :id: logic_arc_int_op__example_feature__op_8
   :security: YES
   :safety: ASIL_B
   :status: valid
   :included_by: logic_arc_int__example_feature__if_3


Module View File
================

.. mod:: Module 1
   :id: mod__mtef_archex_module_1
   :security: YES
   :safety: ASIL_B
   :status: valid
   :includes: comp__mod_temp_component_example_1, comp__mod_temp_component_example_2

   This is Module 1.

.. mod_view_sta:: Module 1 Static View
   :id: mod_view_sta__example_feature__1
   :includes: comp__mod_temp_component_example_1, comp__mod_temp_component_example_2

   .. needarch::
      :scale: 50
      :align: center

      {{ draw_module(need(), needs) }}

.. mod:: Module 2
   :id: mod__mtef_archex_module_2
   :security: YES
   :safety: ASIL_B
   :status: valid
   :includes: comp__mod_temp_component_example_3

   This is Module 2.

.. mod_view_sta:: Module 2 Static View
   :id: mod_view_sta__example_feature__2
   :includes: comp__mod_temp_component_example_3

   .. needarch::
      :scale: 50
      :align: center

      {{ draw_module(need(), needs) }}

Feature or Component Architecture File(s)
=========================================

.. comp:: Component 1
   :id: comp__mod_temp_component_example_1
   :security: YES
   :safety: ASIL_B
   :status: valid
   :implements: logic_arc_int__example_feature__if_1
   :consists_of: comp__mod_temp_archex_sub_component_1, comp__mod_temp_archex_sub_component_2, comp__mod_temp_archex_sub_component_3
   :belongs_to: feat__mtef

   Example Component 1 description.

.. comp:: Component 2
   :id: comp__mod_temp_component_example_2
   :security: YES
   :safety: ASIL_B
   :status: valid
   :implements: logic_arc_int__example_feature__if_2
   :belongs_to: feat__mtef

   Example Component 2 description.

.. comp:: Component 3
   :id: comp__mod_temp_component_example_3
   :security: YES
   :safety: QM
   :status: valid
   :implements: logic_arc_int__example_feature__if_3
   :belongs_to: feat__mtef

   Example Component 3 description.

.. comp_arc_sta:: Component 1 Static View
   :id: comp_arc_sta__example_feature__comp_1
   :status: valid
   :safety: ASIL_B
   :security: NO
   :belongs_to: comp__mod_temp_component_example_1
   :fulfils: comp_req__example_feature__example_req

   .. needarch::
      :scale: 50
      :align: center

      {{ draw_component(need(), needs) }}

.. Subcomponents

.. comp:: Component 1_1
   :id: comp__mod_temp_archex_sub_component_1
   :status: valid
   :safety: ASIL_B
   :security: NO
   :uses: logic_arc_int__example_feature__if_2
   :implements: logic_arc_int__example_feature__if_1
   :belongs_to: feat__mtef

.. comp:: Component 1_2
   :id: comp__mod_temp_archex_sub_component_2
   :status: valid
   :safety: ASIL_B
   :security: NO
   :uses: logic_arc_int__example_feature__if_2
   :implements: logic_arc_int__example_feature__if_2
   :belongs_to: feat__mtef

.. comp:: Component 1_3
   :id: comp__mod_temp_archex_sub_component_3
   :status: valid
   :safety: ASIL_B
   :security: NO
   :belongs_to: feat__mtef


Requirements for the Example
=============================

.. Requirements

.. note:: The stakeholder requirements shall be defined in the platform repo (`stakeholder requirements folder <https://eclipse-score.github.io/score/main/requirements/index.html>`_) and imported as sphinx needs objects. Here it is defined only to hold the example together and prevent errors because the sphinx needs meta model have mandatory links to it.

.. stkh_req:: Example Stkh Req
   :id: stkh_req__mtfn__example_req
   :reqtype: Functional
   :safety: ASIL_B
   :security: YES
   :rationale: needed for archdes example
   :status: valid

   The platform shall provide the feature ....

.. note:: The feature requirements shall be defined in the platform repo (in the requirements folder of the (`features <https://eclipse-score.github.io/score/main/features/index.html>`_)) and imported as sphinx needs objects. Here it is defined only to hold the example together and prevent errors because the sphinx needs meta model have mandatory links to it.

.. feat_req:: Example Feature Req
   :id: feat_req__example_feature__example_req
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :derived_from: stkh_req__mtfn__example_req
   :status: valid
   :satisfied_by: feat__mtef

   The feature shall provide the functionality to ....

.. comp_req:: Example Component Req
   :id: comp_req__example_feature__example_req
   :reqtype: Functional
   :security: YES
   :safety: ASIL_B
   :derived_from: feat_req__example_feature__example_req
   :status: valid
   :satisfied_by: comp__mod_temp_component_example_2

   The component shall provide the Logical Operation 4 to get the ..
