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

Common Storage
==============

.. comp:: Common Storage
   :id: comp__crypto_common_storage
   :version: 1
   :status: valid
   :safety: QM
   :security: YES
   :belongs_to: feat__security_crypto

The common storage subcomponent provides file I/O and deployment-descriptor
utilities shared by daemon components. Its architecture documents the atomic
replacement contract used for file-backed payloads and KV deployment descriptors.

.. toctree::
   :caption: Common Storage Documentation
   :maxdepth: 1

   architecture/index
