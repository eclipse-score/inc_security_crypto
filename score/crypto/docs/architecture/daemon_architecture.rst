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

Crypto Daemon Component Architecture
====================================

.. document:: Crypto Daemon Component Architecture
   :id: doc__crypto_daemon_architecture
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__component_arch

.. comp:: Crypto Daemon
   :id: comp__crypto_daemon
   :version: 1
   :status: valid
   :safety: QM
   :security: YES
   :belongs_to: feat__security_crypto
   :consists_of: comp__crypto_key_management, comp__crypto_cert_management, comp__crypto_data_manager

.. comp_arc_sta:: Crypto Daemon Static Architecture
   :id: comp_arc_sta__crypto_daemon__sv
   :version: 1
   :status: valid
   :safety: QM
   :security: YES
   :belongs_to: comp__crypto_daemon

   .. needarch::
      :scale: 50
      :align: center

      {{ draw_component(need(), needs) }}

The daemon owns request handling, resource management, provider dispatch, and
daemon-side key and certificate lifecycles. This decomposition records the
currently documented lower-level components; other daemon packages remain
implementation details in this scoped model.

.. toctree::
   :maxdepth: 1
   :caption: Daemon Subcomponents

   ../../src/daemon/cert_management/docs/index
   ../../src/daemon/data_manager/docs/index
   key_management_architecture
