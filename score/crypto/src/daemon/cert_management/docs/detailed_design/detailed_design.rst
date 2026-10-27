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

Certificate Management Detailed Design
======================================

.. document:: Certificate Management Detailed Design
   :id: doc__crypto_cert_management_detailed_design
   :version: 1
   :status: valid
   :safety: QM
   :security: YES
   :realizes: wp__sw_implementation
   :tags: cert_management, detailed_design

Implementation units
--------------------

The component-composition diagram shows the implementation units and their
relationships. ``AccessPolicyEnforcer`` applies UID-based read/write policy;
mutation authorization is default-deny unless writer UIDs are configured.

Storage contract
----------------

A certificate slot uses a KV deployment descriptor with a ``[certificate]``
section and optional ``[certificate_metadata]`` and ``[crl]`` sections. The
certificate and CRL payloads are stored in files referenced by the descriptor.
Descriptor and payload writes use the shared storage utilities; the previous
descriptor remains available until the replacement is complete.

Trust-store update contract
---------------------------

The notification owner and the certificate-slot and CRL mutation paths are
defined in :need:`dec_rec__crypto_cert_mgmt__notify_ownership`.

When a certificate changes, a warm trust-store cache refreshes only the affected
member. For a ``kConditionalExternal`` member, changed content disables the
member until ``AcknowledgeMemberUpdate`` accepts the replacement fingerprint.
Other member kinds retain their enablement state. The member's anchor and CRL
are refreshed separately, so a concurrent reader may briefly see the new
certificate with the previous CRL; each anchor-set entry is replaced atomically
under the handler mutex. A cold cache is populated on the next read.

A CRL-only update refreshes the affected member's CRL from the slot's current
snapshot without reloading its certificate. Disabled members retain no CRL.

Provider boundary and scope
----------------------------

The core component does not depend on OpenSSL or PKCS#11 concrete types, and no
provider is hardcoded as the parsing authority. ``SlotHandlerFactory`` resolves one
canonical ``ICertParser`` for the component: the provider named by
``CertificateConfig::GetParserProviderName`` when one is configured, otherwise the
provider selected for the certificate-management capability. Resolution happens on
first use unless a caller invokes ``Initialize()`` to resolve eagerly; a successful
parser is cached and shared, and a failed resolution is not cached so a later call
retries. A slot handler is created only after the parser is available; slot operations
requiring a handler return the creation error otherwise. Each provider supplies its own
verification and CSR generation handlers, built
on the same provider-neutral ``CertObject`` values. PKCS#11 is expected to supply its
own ``ICertSlotHandler`` for certificate-slot storage. Hardware-key CSR signing is
expected to use a cross-context service without exporting private key material. OCSP
remains a provider-boundary extension.

Use cases
---------

The sequence diagrams below describe individual operations. Shared contracts
and cache behavior are described in the preceding sections; related operations
are cross-referenced where they share a flow.

.. _cert_management_load_certificate:

Loading a certificate from a slot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. uml:: uc_certificate_slot_load.puml

.. _cert_management_write_certificate_slot:

Writing a certificate slot
~~~~~~~~~~~~~~~~~~~~~~~~~~

Replacing a certificate also invalidates its associated CRL. Persistent CRL
updates use the separate refresh path described in
:ref:`Importing a CRL <cert_management_import_crl>`.

.. uml:: uc_certificate_slot_update.puml

.. _cert_management_import_crl:

Importing a CRL
~~~~~~~~~~~~~~~

A certificate replacement invalidates its CRL and refreshes referencing trust
stores as described in :ref:`Writing a certificate slot
<cert_management_write_certificate_slot>`.

Import stores the supplied CRL as given and does not validate it against its
issuer certificate.

.. uml:: uc_crl_import.puml

.. _cert_management_add_trust_store_certificate:

Adding a certificate to a trust store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When CRL propagation is requested, the source CRL may be session-scoped or
persistent, as described in :ref:`Importing a CRL
<cert_management_import_crl>`.

.. uml:: uc_trust_store_member_add.puml

.. _cert_management_verify_certificate:

Verifying a certificate
~~~~~~~~~~~~~~~~~~~~~~~

The certificate resource is loaded as described in
:ref:`Loading a certificate from a slot <cert_management_load_certificate>`;
this sequence focuses on trust-store binding and verification.

.. uml:: uc_certificate_verification.puml
