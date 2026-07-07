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

AoU Feature Requirements
========================

.. document:: [Your Feature Name] Feature AoU
   :id: doc__feature_name_feat_aou
   :status: draft
   :safety: ASIL_B
   :security: NO
   :realizes: wp__requirements_feat_aou
   :tags: template


.. attention::
    The above directive must be updated according to your Feature.

    - Modify ``Your Feature Name`` to be your Feature Name
    - Modify ``id`` to be your Feature Name in upper snake case preceded by ``doc__`` and followed by ``_feat_aou``
    - Adjust ``status`` to be ``valid``
    - Adjust ``safety``, ``security`` and ``tags`` according to your needs


This page contains Assumption of Use requirement snippets that belong to the
template repository.

Feature AoU
-----------

.. code-block:: rst

   .. aou_req:: Some Other Title
      :id: aou_req__feature_name__some_other_title
      :reqtype: Process
      :security: NO
      :safety: ASIL_B
      :status: invalid

      The Feature User shall do xyz to use the feature safely.
