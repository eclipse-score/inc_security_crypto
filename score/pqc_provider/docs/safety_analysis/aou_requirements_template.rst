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

AoU Component Requirements Snippets
===================================

This page contains the current Assumptions of Use snippets used by PQC Provider.

Component AoU
-------------

.. code-block:: rst

   .. aou_req:: Integrate as Rust library API
      :id: aou_req__pqc_provider__integrate_as_rust_library_api
      :reqtype: Process
      :security: YES
      :safety: QM
      :status: valid

      The component user shall link the crate ``pqc_provider`` and call the public API from Rust code.

   .. aou_req:: Build environment supports Rust 2021
      :id: aou_req__pqc_provider__build_env_supports_rust_2021
      :reqtype: Process
      :security: YES
      :safety: QM
      :status: valid
      :tags: environment

      The component shall be built in an environment that supports Rust edition 2021.