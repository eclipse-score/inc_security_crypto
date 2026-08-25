..
   # *******************************************************************************
   # Copyright (c) 2026 Contributors to the Eclipse Foundation
   # SPDX-License-Identifier: Apache-2.0
   # *******************************************************************************

Certificate Management Requirements
===================================

.. document:: Certificate Management Requirements
   :id: doc__crypto_cert_management_requirements
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__cmpt_request_dummy
   :tags: cert_management, crypto_daemon

Scope
-----

The requirements below describe the current daemon component boundary. API
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


Scope boundary
--------------

Hardware-key CSR signing, CRL validation, and mediator routing are outside the
certificate-management storage and lifecycle boundary described here. A
provider integration may supply those capabilities through the corresponding
provider and daemon services.

.. needextend:: "c.this_doc()"
   :+tags: cert_management
