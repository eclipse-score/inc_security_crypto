..
   # *******************************************************************************
   # Copyright (c) 2026 Contributors to the Eclipse Foundation
   # SPDX-License-Identifier: Apache-2.0
   # *******************************************************************************

Certificate Management Detailed Design
======================================

.. document:: Certificate Management Detailed Design
   :id: doc__crypto_cert_management_detailed_design
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__cmpt_request_dummy
   :tags: cert_management, detailed_design

Implementation units
--------------------

``CertManagementService``
   Coordinates resource resolution, DataManager nodes, certificate registry
   access, slot operations, and trust-store update notifications.

``CertRegistry`` and ``CertEntry``
   Own live certificate entries and share immutable ``CertObject`` values
   between clients and trust stores.

``CertSlotRegistry``
   Stores immutable slot configuration and application resource mappings.

``FileBackedSlotHandler`` and ``CrlHandler``
   Read and write certificate/CRL data using the deployment descriptor and
   shared atomic file I/O. The slot handler delegates parsing to ``ICertParser``.

``TrustStoreManager`` and ``TrustStoreHandler``
   Resolve typed slot memberships, maintain reverse indices, load anchors
   lazily, persist mutable member state, and manage per-client references.

``AccessPolicyEnforcer``
   Applies UID-based read/write policy. Mutation is default-deny when no writer
   UID is explicitly configured.

Data and lifetime model
-----------------------

* ``CertSlotDataNode`` is a client-scoped reference to a configured slot.
* ``CertDataNode`` is a client-scoped reference to a registry-owned
  ``CertEntry``.
* ``TrustStoreDataNode`` is a client-scoped reference to a manager-owned trust
  store.
* ``CertObject`` is immutable and provider-neutral.
* Trust-store anchor contents are loaded on demand. A weak cache avoids
  duplicate certificate objects across active stores.
* Per-client trust-store references prevent one client from evicting another
  client's active anchor cache.

Storage contract
----------------

A certificate slot uses a KV deployment descriptor with a ``[certificate]``
section and optional ``[certificate_metadata]`` and ``[crl]`` sections. The
certificate and CRL payloads are stored in files referenced by the descriptor.
Descriptor and payload writes use the shared storage utilities; the previous
descriptor remains available until the replacement is complete.

Trust-store update contract
---------------------------

After a successful slot certificate update, the service obtains the reverse
membership list and calls ``TrustStoreManager::NotifySlotChanged``. The manager
invalidates the affected ``TrustStoreHandler`` cache. The next ``GetAnchors``
operation reloads the slot and reconstructs its ``CertObject`` through the
injected parser.

Provider boundary and scope
----------------------------

The core component does not depend on OpenSSL or PKCS#11 concrete types.
OpenSSL currently supplies parsing and verification implementations; PKCS#11
supplies a read-only certificate-slot backend. Hardware-key CSR generation,
CRL validation, OCSP, and mediator dispatch are outside this component's
storage and lifecycle scope. Hardware CSR signing must use a cross-context
service without exporting private key material.

.. uml:: ../architecture/cert_management_dynamic.puml
