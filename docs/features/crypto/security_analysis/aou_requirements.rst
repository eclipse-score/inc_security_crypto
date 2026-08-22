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

.. document:: Crypto Feature Security AoU
   :id: doc__crypto_sec_feat_aou
   :version: 1
   :status: draft
   :safety: ASIL_B
   :security: YES
   :realizes: wp__requirements_comp_aou


This page contains Assumption of Use requirement snippets that belong to the
crypto repository.

Feature AoU
-----------


.. aou_req:: pkcs11_dynload: pkcs11.h compatiblity
   :id: aou_req__crypto__sec_pkcs11_h_compatibility
   :reqtype: Process
   :security: YES
   :safety: ASIL_B
   :status: valid

   If pkcs11_dynload is used as backend for the pkcs11 provider, the selected pkcs11.h header 
   shall match the pkcs11 module that will be loaded at runtime.

.. aou_req:: pkcs11_dynload: No use of ALLOW_PKCS11_LIB_OVERRIDE
   :id: aou_req__crypto__sec_no_allow_pkcs11_lib_override
   :reqtype: Process
   :security: YES
   :safety: ASIL_B
   :status: valid
   :tags: environment

   If pkcs11_dynload is used as backend for the pkcs11 provider, the PKCS1111_OVERRIDE mechanism
   shall not be used for series. The pkcs11 module path provided via pkcs11_lib shall be the effective
   and final module that will be loaded at runtime.
   Hint: This option is introduced only for internal use of testing and is not recommended to be used 
   for a series project

.. aou_req:: pkcs11_dynload: Integrity and authenticity of the pkcs11 module
   :id: aou_req__crypto__sec_integrity_authenticity_pkcs11_module
   :reqtype: Process
   :security: YES
   :safety: ASIL_B
   :status: valid
   :tags: environment

   If pkcs11_dynload is used as backend for the pkcs11 provider, the operating system platform shall
   provide integrity and authenticity mechanisms for the specified pkcs11 module.
