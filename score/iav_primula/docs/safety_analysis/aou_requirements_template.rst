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

IAV Primula Component Assumptions of Use
========================================


.. document:: IAV Primula Component AoU
   :id: doc__iav_primula_comp_aou
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__requirements_comp_aou
   :tags: iav_primula

This page summarizes the current Assumptions of Use. Their canonical
requirements and traceability are maintained in the component requirements
document.

Component AoU
-------------

- :need:`aou_req__iav_primula__c_abi_integration`
- :need:`aou_req__iav_primula__check_operation_status`
- :need:`aou_req__iav_primula__key_handle_ownership`
- :need:`aou_req__iav_primula__rust2021_build_env`

These assumptions require integrators to use the C-compatible interface, check
operation status before using outputs, preserve opaque key-handle ownership, and
build the Rust library with Rust 2021 support.
