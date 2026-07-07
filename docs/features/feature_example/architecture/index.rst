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

.. _feature_architecture_template:

Feature Architecture
====================

.. document:: [Your Feature Name] Architecture
   :id: doc__feature_example_architecture
   :status: draft
   :safety: ASIL_B
   :security: NO
   :realizes: wp__feature_arch
   :tags: template

.. attention::
    The above directive must be updated according to your Feature.

    - Modify ``Your Feature Name`` to be your Feature Name
    - Modify ``id`` to be your Feature Name in upper snake case preceded by ``doc__`` and followed by ``_architecture``
    - Adjust ``status`` to be ``valid``
    - Adjust ``safety``, ``security``  and ``tags`` according to your needs

Overview
--------
<Brief summary>

Description
-----------

<General Description>

<Design Decisions - For the documentation of the decision the :need:`gd_temp__change_decision_record` can be used.>

<Design Constraints>

Requirements
------------

The requirements for the feature architecture are defined in the `requirements` section of the feature documentation in the project repository.

Rationale Behind Architecture Decomposition
*******************************************

Mandatory: A motivation for the decomposition

.. note:: Common decisions across features / cross cutting concepts is at the high level.

Static Architecture
-------------------

<The static architecture of the feature can be described here. It includes the feature architecture diagrams and some descriptions.>

.. note::
   The Architecture can be split into multiple files, it is an high level architecture design
   which can be shown without actual c++/rust interfaces and data types
   and there will be link to internal architecture till code to get actual api descriptions.

.. code-block:: rst

   .. feat_arc_sta:: Feature Static View
      :id: feat_arc_sta__feature_name__static_view
      :security: YES
      :safety: ASIL_B
      :status: invalid
      :fulfils: feat_req__feature_name__some_title
      :includes: logic_arc_int__feature_name__interface_name1
      :belongs_to: feat__feature_name

      .. needarch::
         :scale: 50
         :align: center

         {{ draw_feature(need(), needs) }}

Dynamic Architecture
--------------------

<The dynamic architecture of the feature can be described here. That can include sequence diagrams, state machines, and other dynamic views of the feature.>

.. code-block:: rst

   .. feat_arc_dyn:: Dynamic View
      :id: feat_arc_dyn__feature_name__dynamic_view
      :security: YES
      :safety: ASIL_B
      :status: invalid
      :fulfils: feat_req__feature_name__some_title
      :belongs_to: feat__feature_name

      Put here a sequence diagram

Logical Interfaces
------------------

The logical interfaces of the feature are defined in the `logical interfaces` section of the feature documentation in the project repository.

See `SCORE Features <https://eclipse-score.github.io/score/main/features/index.html>`_ for more information.

Used Components
---------------

The components used by the feature are defined in the `components` section of the module documentation.

See :ref:`component_template` for an example component.
