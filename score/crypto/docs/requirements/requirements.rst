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

Crypto Requirements
####################

.. document:: Crypto Requirements
   :id: doc__crypto_requirements
   :version: 1
   :status: draft
   :safety: ASIL_B
   :security: YES
   :realizes: wp__requirements_comp[version==1]



<Headlines (for the list of requirements if structuring is needed)>
===================================================================

Functional Requirements
-----------------------

.. code-block::

   .. comp_req:: Some Title
      :id: comp_req__crypto__func_req_example
      :reqtype: Process
      :security: YES
      :safety: ASIL_B
      :derived_from:
      :status: valid
      :satisfied_by: comp__crypto

      The Component shall do xyz to another component to bring it to this condition at this time

      Note: (optional, not to be verified)


Assumption of Use Requirements
------------------------------

.. aou_req:: Crypto AoU Requirement Example
   :id: aou_req__crypto_aou__next_title
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: ASIL_B
   :status: valid

   The Component User shall do xyz to use the component safely/securely

Environmental Requirements
--------------------------

.. aou_req:: Crypto Environmental Requirement Example
   :id: aou_req__crypto__crypto_env_req_ex
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: ASIL_B
   :status: invalid
   :tags: environment

   The Component shall only be used in a xyz environment to ensure its proper functioning.

Hints
-----

.. attention::
    The above directives must be updated according to your feature requirements.

    - Replace the example content by the real content for your first requirement (according to :need:`gd_guidl__req_engineering`)
    - Set ``safety`` and ``security`` to the right value (ASIL B/QM; YES/NO)
    - Set ``reqtype`` with a link to the right value (<Functional|Interface|Process|Non-Functional>)
    - Add other needed requirements for your feature
    - Set ``status`` to ``valid`` and start the review/merge process

.. needextend:: is_external == False and "crypto" in id
   :+tags: crypto
