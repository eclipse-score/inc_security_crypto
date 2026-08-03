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

IAV Primula Requirements
########################

.. document:: IAV Primula Requirements
   :id: doc__iav_primula_requirements
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__requirements_comp[version==1]
   :tags: iav_primula

Scope
=====

Functional Requirements
-----------------------

.. comp_req:: Provide hello message function
   :id: comp_req__iav_primula__provide_hello_message
   :version: 1
   :reqtype: Functional
   :security: NO
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__iav_primula

   The component shall provide a public Rust function
   ``get_hello_message() -> &'static str``.

.. Note:
   ``get_hello_message()`` shall return the exact value
   ``"Hello World from iav_primula"``.

Assumption of Use Requirements
------------------------------

.. aou_req:: Integrate as Rust library API
   :id: aou_req__iav_primula__rust_lib_api
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid

   The component user shall link the crate ``iav_primula`` and call the public
   API from Rust code.

Environmental Requirements
--------------------------

.. aou_req:: Build environment supports Rust 2021
   :id: aou_req__iav_primula__rust2021_build_env
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid
   :tags: environment

   The component shall be built in an environment that supports Rust edition
   2021, consistent with the component BUILD definition.

.. needextend:: is_external == False and "iav_primula" in id
   :+tags: iav_primula
