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

Certificate Management Requirements
===================================

.. document:: Certificate Management Requirements
   :id: doc__crypto_cert_management_requirements
   :version: 1
   :status: valid
   :safety: QM
   :security: YES
   :realizes: wp__requirements_comp[version==1]
   :tags: cert_management, crypto_daemon

Scope
-----

The requirements below describe the daemon component boundary. API
context and mediator requirements are included only where they affect the
component contract.

Functional requirements
-----------------------

.. comp_req:: Manage certificate slots
   :id: comp_req__crypto_cert_management__slots
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_cert_management

   The component shall resolve configured certificate slots and provide
   loading, storage, state, metadata, and release operations through a slot
   handler.

.. comp_req:: Parse provider-neutral certificates
   :id: comp_req__crypto_cert_management__parse
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_cert_management

   The component shall represent parsed certificate bytes as immutable
   ``CertObject`` values containing raw bytes, format, and chain metadata.
   Parsing shall be supplied through the narrow ``ICertParser`` interface.

.. comp_req:: Use one canonical certificate parser
   :id: comp_req__crypto_cert_mgmt__parser_authority
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_cert_management

   The component shall parse all certificates through a single ``ICertParser``
   instance so that a certificate's derived identity does not vary with the
   caller. The supplying provider shall be the one named in the certificate
   configuration when a name is configured, and otherwise the provider selected
   for the certificate-management capability. A configured parser provider that
   cannot supply a parser shall be reported as a configuration failure rather
   than replaced by another provider.

.. comp_req:: Manage trust-store membership
   :id: comp_req__crypto_cert_mgmt__trust_stores
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_cert_management

   The component shall manage named trust stores whose members are typed
   certificate-slot references. Slot changes shall invalidate affected anchor
   caches.

.. comp_req:: Scope trust-store cache refresh to changed members
   :id: comp_req__crypto_cert_mgmt__tstr_cnsstncy
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_cert_management

   A change to one certificate slot shall refresh only the anchor and CRL cache
   entries of trust-store members backed by that slot. Concurrent readers of a
   trust store's anchor and CRL caches shall observe a complete anchor set, and
   never a partially rebuilt set.

.. comp_req:: Persist certificate and CRL state
   :id: comp_req__crypto_cert_management__persistence
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_cert_management

   The component shall persist certificate, CRL, trust-store state, and
   metadata using the shared deployment storage. Certificate and CRL files
   shall be written atomically.

.. comp_req:: Enforce mutation authorization
   :id: comp_req__crypto_cert_mgmt__access_control
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_cert_management

   Certificate-slot and trust-store mutations shall require an explicitly
   authorized client UID. Empty write allowlists shall not grant access.


Dependency expectations
-----------------------

The component persists CRL material alongside the issuing certificate's slot
and exposes it through ``ICertSlotHandler`` / ``ITrustStoreHandler`` for a
verification provider to consume; CRL-based revocation checking itself is
performed by that provider's verification context handler, not by this
component. Certificate signing requests are assembled by a CSR-generation
context handler, which is expected to obtain the issuing signature from an
exportable software key or, for hardware-bound keys, through a cross-context
signing capability supplied by key management, without this component ever
handling private key material. Dispatch of requests to these provider context
handlers is the responsibility of the daemon mediator.

.. needextend:: "c.this_doc()"
   :+tags: cert_management
