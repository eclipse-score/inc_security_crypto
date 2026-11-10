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


DFA (Dependent Failure Analysis)
================================

.. document:: IAV Primula DFA
   :id: doc__iav_primula_dfa
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__sw_component_dfa
   :tags: iav_primula

.. note::
   The component is classified ``QM``. This analysis covers the current provider
   registration, request routing, key-management integration, and C/Rust FFI
   skeleton. No functional PQC backend is connected.

Dependent Failure Initiators
----------------------------

No safety requirements are allocated to this ``QM`` component, so no formal
``comp_saf_dfa`` entries are required. The following shared dependencies are
nevertheless relevant to integration:

- ``ProviderManager`` and score-provider configuration are shared by provider
  registration and routing. Their failure can make all Primula operations
  unavailable or route requests to another provider.
- The C ABI and its buffers are shared by SIGN, VERIFY, and KEM paths. Invalid
  boundary data can affect multiple operations; callers and handlers must
  validate status values and output lengths before using results.
- The Rust FFI library is common to all Primula cryptographic operations. In the
  current placeholder implementation, it consistently reports
  ``IavStatusUnsupportedAlgorithm`` and produces no cryptographic output.

Re-evaluate dependent failures when a functional PQC backend or safety-relevant
requirements are introduced.
