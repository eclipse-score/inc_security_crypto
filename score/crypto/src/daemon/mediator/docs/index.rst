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

Mediator
========

.. comp:: Mediator
   :id: comp__crypto_mediator
   :version: 1
   :status: valid
   :safety: QM
   :security: YES
   :belongs_to: feat__security_crypto

The mediator is the daemon subcomponent that routes client operations to the
subsystem that serves them. For context creation it decodes the request,
selects the handler, through a registered factory or a provider, and assembles the context node; the other operations it
handles itself or forwards to the context's handler.

.. toctree::
   :caption: Mediator Documentation
   :maxdepth: 1

   requirements/index
   architecture/index
   detailed_design/index
