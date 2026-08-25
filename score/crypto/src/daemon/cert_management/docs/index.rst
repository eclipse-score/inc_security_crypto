Certificate Management Component
================================

.. document:: Certificate Management Component
    :id: doc__crypto_cert_mgmt
    :version: 1
    :status: draft
    :safety: QM
    :security: YES
    :tags: cert_management, crypto_daemon, certificate, trust_store
    :realizes: wp__cmpt_request_dummy

.. toctree::
   :hidden:

   requirements/index
   architecture/index
   detailed_design/index

Abstract
--------

The ``cert_management`` daemon subcomponent provides lifecycle management
for X.509 certificates, CRLs, and trust stores inside the crypto daemon.
It sits parallel to ``key_management`` and implements the IPC back-end
for the certificate-management, certificate-verification, and CSR-generation
API contexts.

The component manages certificate slots (named, persistent locations for a
single certificate and its optional co-located CRL), trust stores (named
collections of trust anchors backed by typed slot references), and a
runtime certificate registry (live in-memory handles returned to clients).
Certificate bytes are treated as provider-neutral immutable values
(``CertObject``). All parsing, verification, CSR generation, and
hardware-bound operations are delegated to provider context handlers;
the core component owns only lifecycle, access control, and storage.

The default storage backend is file-system based (``FileBackedSlotHandler``).
The provider selected for the certificate-management capability supplies the
parser used by that backend. Other providers may supply their own
``ICertSlotHandler`` implementation for provider-owned storage.

Rationale
---------

Certificate material is public information — unlike private keys, raw
certificate bytes may be shared between clients and cached freely.
This drives several design decisions:

* **Software-first provider default** — unlike ``key_management`` (which
  prefers hardware), the cert management capability defaults to the
  file-backed handler so that all certificate operations are accessible
  without hardware.

* **CertObject as a value type** — parsed certificates are immutable
  ``shared_ptr``-managed values. The same ``CertObject`` instance is
  shared across trust stores and client handles via a weak-ptr cache in
  ``TrustStoreManager``, avoiding redundant parses and copies.

* **Trust store membership by typed slot reference** — anchors are
  certificate slots, not raw file paths. This allows the daemon to track
  content changes (``NotifySlotCertChanged``) and invalidate cached
  anchors atomically without polling.

* **CRL co-located with the CA cert slot** — an optional ``[crl]``
  section in the slot's KV deployment descriptor holds the CRL path and
  ``nextUpdate`` epoch. No separate CRL registry is needed.

* **Per-client anchor reference counting** — trust store anchor caches
  are reference counted per client, not globally. Releasing one
  application's verification context cannot evict another application's
  active anchor cache.

Backwards Compatibility Impact
-------------------------------

The component introduces no changes to existing certificate-management
callers. The certificate-management, certificate-verification, and
CSR-generation context interfaces are defined in ``score/crypto/src/api/``.

Security Impact
---------------

* Certificate bytes are public; no secret material is handled by this
  component. The deployment infrastructure (``daemon/common/storage/``)
  shared with key_management uses atomic rename-based writes to avoid
  partial updates.
* Write access to cert slots and trust stores is default-deny:
  ``AccessPolicyEnforcer::CheckWritePermission`` requires an explicit
  ``allowed_write_uids`` entry for mutation operations.
* Trust store mutations (``AddMember``, ``RemoveMember``,
  ``DisableMember``, ``EnableMember``) carry a separate write permission
  check on the trust store policy, independent of the member slot's
  write policy.

Safety Impact
-------------

No runtime safety-relevant behaviour beyond the general daemon isolation
contract. Certificate validation results (from the provider verification
handler) are returned to callers without modification; the component does
not cache or interpret verification outcomes.

Rejected Ideas
--------------

* **Separate ``HsmBackedSlotHandler`` stub** — rejected; hardware
  providers implement ``ICertSlotHandler`` directly (mirrors key_management
  pattern). A daemon-side stub would create an untested code path.
* **Static trust-store paths (``static_cert_paths``, ``static_cert_dir``)** —
  rejected; shared baseline anchors are represented by shared-static
  certificate slots, keeping the deployment model uniform across all
  anchor types.
* **``ICertFactory`` / ``ICertHandler``** — rejected; cert context
  operations (verify, CSR, convert, key-extract) live inside context
  handlers created by ``ICryptoHandlerFactory``. A separate factory
  interface would duplicate handler lifecycle management.
* **Separate ``CrlRegistry``** — rejected; CRL data is co-located with its
  CA cert slot in the KV descriptor. A standalone registry would require
  a separate resolution path and complicate the slot lifecycle.

Current Limitations
-------------------

* CSR generation with hardware-bound keys requires a cross-context signing
  service. Private key material is not exported by certificate management.
* CRL storage is supported, while CRL validation during certificate
  verification is outside the current component behavior.
* Certificate operations require provider and daemon dispatch integration.
