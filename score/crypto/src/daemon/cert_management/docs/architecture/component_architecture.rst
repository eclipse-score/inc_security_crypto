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

Certificate Management Component Architecture
=============================================

.. document:: Certificate Management Component Architecture
   :id: doc__crypto_cert_management_architecture
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__cmpt_request_dummy
   :tags: cert_management, architecture

.. comp:: Certificate Management Component
    :id: comp__crypto_cert_management
    :version: 1
    :security: YES
    :safety: QM
    :status: valid
    :belongs_to: feat__mtef

Purpose
-------

``cert_management`` is a daemon subcomponent parallel to
``key_management``. It owns certificate and trust-store resource lifecycle;
it does not own private keys or provider-specific cryptographic objects.

Static decomposition
--------------------

The implementation is divided by responsibility:

* ``interfaces/`` contains provider-neutral certificate values, slot and trust
  store contracts, configuration types, and public handles.
* ``core/`` contains ``CertManagementService``, ``CertRegistry``, and
  ``CertEntry``.
* ``nodes/`` contains DataManager nodes for certificate slots, loaded
  certificates, and trust stores.
* ``slot/`` contains slot registration, file-backed storage
  (``FileBackedSlotHandler``), PKCS#11 storage (``Pkcs11CertSlotHandler``),
  deployment dispatch, and co-located CRL storage (``CrlHandler``).
* ``truststore/`` contains trust-store membership, anchor caching, persistence,
  and per-client references.
* ``policy/`` contains the shared slot/trust-store access-policy checks.
* ``query/`` contains ``CertObjectSerializer`` — the single source of IPC
  wire-format encoding for certificate, slot, and trust-store objects. Both
  the executor and the mediator's typed-object handlers depend on this module;
  changing the wire layout requires one edit.
* ``provider/`` supplies parsing and provider-specific context handlers. The
  selected certificate-management provider must expose ``ICertParser``;
  certificate management does not require a particular provider.

.. uml:: cert_management_static.puml

Runtime boundaries
------------------

Resource resolution is client-scoped through the Data Manager. A resolved
certificate slot or trust store is represented by a lightweight DataNode. A
certificate loaded from a slot becomes a ``CertDataNode`` backed by a shared
``CertEntry``. Trust-store anchor content is loaded lazily and cached by
``TrustStoreManager``.

The current provider boundary is intentionally narrow:

* ``ICertParser`` converts DER/PEM bytes into ``CertObject``.
* ``ICertSlotHandler`` loads and stores slot data.
* Provider context handlers perform verification, CSR generation, conversion,
  and public-key operations.
* Cross-context services may provide signing and public-key operations for
  non-exportable keys while preserving provider ownership of private keys.

Architecture constraints
------------------------

* Certificate slots reference one storage backend selected at startup.
* Trust stores reference certificate slots, never raw certificate paths.
* CRLs are slot-scoped and are not independently resolved.
* All trust-store mutation paths require trust-store write authorization.
* Shared deployment writes are atomic; a partially written descriptor must not
  replace the previous valid descriptor.

Key interfaces
--------------

``ICertSlotHandler`` is implemented by certificate storage backends such as
``FileBackedSlotHandler`` and ``Pkcs11CertSlotHandler``. The handler factory is
injected into ``TrustStoreManager`` so the core component does not depend on a
concrete provider backend.

``ITrustStoreHandler`` exposes anchor retrieval and chain-building lookups.
``TrustStoreHandler`` receives an anchor-loader callback from
``TrustStoreManager`` and loads its anchor content on demand.

``ICertParser`` is the narrow provider boundary for converting DER or PEM
bytes into a provider-neutral ``CertObject``. Verification, CSR generation,
format conversion, and public-key extraction are provider context operations,
not responsibilities of the core storage component.

Runtime flows
-------------

During startup, the configuration adapter registers certificate slots and
trust stores. A client resolves an application resource into a DataManager
node. Loading a certificate resolves its slot handler, reads the deployment
descriptor and payload, parses the bytes, and registers a shared
``CertEntry``. Repeated loads of the same slot share the registry entry.

Trust-store anchors are loaded lazily. ``TrustStoreManager`` resolves each
typed member slot and caches the resulting ``CertObject`` through a weak
reference. The trust-store handler holds strong references while active.

After a certificate update, ``CertManagementService`` finds every trust store
that references the slot and calls ``NotifySlotChanged``. The affected cache
entry is invalidated, and the next anchor request reloads and reparses the
certificate. Per-client references prevent one client's cleanup from evicting
another client's active cache.

Design decisions
----------------

The five structural decisions that shape the component's storage model are
documented with full context, alternatives considered, and consequences in
:ref:`crypto_cert_management_design_decisions`:

* :need:`dec_rec__crypto_cert_mgmt__ts_ref_slots` — trust-store members are
  named cert slot references, not raw paths.
* :need:`dec_rec__crypto_cert_mgmt__crl_co_location` — CRLs occupy an optional
  ``[crl]`` section of the cert slot descriptor; no independent CRL registry.
* :need:`dec_rec__crypto_cert_mgmt__deny_mutation` — all mutations are
  default-deny; write access requires an explicit UID in the resource access
  policy.
* :need:`dec_rec__crypto_cert_mgmt__atomic_writes` — file-backed cert and
  descriptor writes use the shared ``file_io::WriteFile`` temp-file + rename
  primitive.
* :need:`dec_rec__crypto_cert_mgmt__provider_boundary` — provider interaction is
  limited to ``ICertParser``; no private key or HSM handle crosses the cert
  management boundary.

Current limitations
--------------------

The current implementation does not provide CRL validation during
verification, OCSP, or hardware-key CSR signing. Hardware CSR signing
requires a cross-context service using ``Sign`` and ``GetPublicKeyDer``
without exporting private key material. Provider and daemon dispatch
integration is outside this component's storage and lifecycle boundary.
