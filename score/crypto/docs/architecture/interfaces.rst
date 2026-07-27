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

.. _crypto_interfaces:

Interfaces
==========

The public API surface is organized into the following interface groups:

.. real_arc_int:: ICryptoStack
   :id: real_arc_int__crypto__i_crypto_stack
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Application-level entry point for cryptographic operations. The
   underlying daemon connection is managed internally and shared across
   all ``ICryptoStack`` instances in the same process. Objects created
   via this interface have independent lifetimes. Provides
   ``CreateCryptoContext()`` and ``GetMemoryAllocator()``.
   Created via ``CreateCryptoStack(CryptoStackConfig)`` where the
   config supports ``SetConnectionEndpoint()`` and
   ``SetDefaultOperationTimeout()`` for stack-wide per-IPC-call
   deadline enforcement.

.. real_arc_int:: CryptoResourceGuard
   :id: real_arc_int__crypto__crypto_resource_guard
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   RAII guard for transient ``CryptoResourceId`` handles. Returned
   by all resource-producing methods (``GenerateKey``, ``DeriveKey``,
   ``AgreeKey``, ``UnwrapKey``, ``ImportKey``, ``LoadKey``,
   ``LoadCertificatePublicKey``, ``ImportCrl``). Move-only to prevent
   double-release. Provides ``Id()`` accessor, implicit conversion
   to ``const CryptoResourceId&`` (so a guard can be passed directly to
   any API accepting ``const CryptoResourceId&``, including ``SetKey``),
   ``Release()`` for explicit synchronous release with ``Result<std::monostate>``
   feedback, and ``IsActive()`` query.

   ``Release()`` provides the explicit ``Result<std::monostate>`` path when
   error handling is needed before destruction. It sends the release
   IPC and auto-deactivates the guard on success.


   Destructor is explicitly ``noexcept`` (MISRA C++:2023 Rule 18.4.1).

.. real_arc_int:: ICryptoContext
   :id: real_arc_int__crypto__i_crypto_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Factory and resource resolution interface for a crypto daemon session.
   Resolves string resource identifiers to ``CryptoResourceId`` handles
   via ``ResolveResource()`` and creates all operation-specific contexts.
   Also provides typed object access.
   Uses **forward declarations** for
   all config, context, and object types — consumers include only
   the specific headers they need.  Provides
   ``ResolveResource()`` for string-to-handle
   resolution (with ACL), twelve ``Create[Op]Context()`` factory methods
   (including ``CreateCertificateVerificationContext`` and
   ``CreateCsrGenerationContext``), query methods
   (``QueryCapabilities``, ``QueryProviderCompatibility``,
   ``GetProviderInfo``), and typed object accessors
   (``GetKeyObject``, ``GetKeySlotObject``,
   ``GetCertificateObject``, ``GetCertSlotObject``,
   ``GetProviderObject``).

.. real_arc_int:: IMemoryAllocator
   :id: real_arc_int__crypto__i_memory_allocator
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Zero-copy shared-memory allocator. Allocates provider-compatible
   memory regions with optional type and provider hints. Provides
   ``Allocate()`` for default and provider-compatible shared memory,
   with per-application quota tracking via ``GetQuota()`` and
   ``GetCurrentUsage()``.

.. real_arc_int:: Streaming Context Hierarchy
   :id: real_arc_int__crypto__streaming_contexts
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   ``IContext`` → ``IStreamingContext`` → ``IStreamingOutputContext``
   base hierarchy.  All streaming methods (``Init()``, ``Update()``,
   ``Reset()``, ``Finalize()``, ``GetOutputSize()``) are **protected**
   in the base classes.  Derived context interfaces selectively expose
   them in their public sections via ``using``-declarations so that
   each context presents a self-contained, user-friendly API surface.

   ``IStreamingContext::Init()`` accepts an
   ``std::optional<span<const uint8_t>> iv`` parameter (default
   ``std::nullopt``) to support algorithms that require an IV
   (e.g. GMAC, AES-CBC).  Contexts that do not use an IV (hash,
   sign, verify) simply call ``Init()`` with the default.

   ``Reset()`` enables in-place context reuse after ``Finalize()``
   without a factory round-trip.  Key/algorithm binding is preserved;
   only streaming state is cleared.

   Concrete streaming contexts: ``IHashContext``, ``IMacContext``,
   ``ICipherContext``, ``IAeadContext``, ``ISignContext``,
   ``IVerifySignatureContext``, ``IRandomContext``.

.. real_arc_int:: IKeyManagementContext
   :id: real_arc_int__crypto__i_key_mgmnt_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Key lifecycle management with dual-overload design. Each
   key-producing method (``GenerateKey``, ``DeriveKey``, ``AgreeKey``,
   ``UnwrapKey``, ``ImportKey``) offers two overloads:

   - **Ephemeral overload** — takes a per-operation params struct,
     returns ``CryptoResourceGuard`` wrapping an ephemeral key.
   - **Direct-to-slot overload** — takes ``target_slot`` as the first
     parameter, an optional ``public_slot`` (for asymmetric key generation),
     followed by the params struct, returns ``Result<std::monostate>``.
     Key is generated/derived directly into the persistent slot(s).

   ``GenerateKey`` supports both symmetric (AES) and asymmetric (RSA, ECDH,
   ML-DSA, etc.) algorithms. For asymmetric generation, the optional
   ``public_slot`` parameter enables:

   - **Ephemeral public key** — omit ``public_slot``, derive public on-demand
     via ``IPrivateKeyObject::GetPublicKey()``
   - **Persistent public key** — provide ``public_slot``, public key generated
     directly into the slot

   Each operation's parameters are encapsulated in a dedicated
   fluent-builder struct (``GenerateKeyParams``, ``DeriveKeyParams``,
   ``AgreeKeyParams``, ``WrapKeyParams``, ``UnwrapKeyParams``,
   ``ImportKeyParams``). The ``target_slot``-first convention is
   consistent across all methods that accept a destination slot.

   ``DeriveKey`` and ``AgreeKey`` accept structured ``KdfParameters``
   for key derivation. Supported KDF algorithms: HKDF (RFC 5869),
   TLS 1.2 PRF (RFC 5246), TLS 1.3 HKDF (RFC 8446), PBKDF2 (RFC 8018),
   SP800-108.

   ``WrapKey`` and ``UnwrapKey`` accept wrapping metadata (IV, AAD,
   wrapping algorithm) via their param structs, enabling authenticated
   wrapping (e.g., AES-GCM key wrap).

   Also supports ``LoadKey`` (optional, advanced), ``ExportKey``
   (with format selection), ``ClearKey``, and ``GetKeySlotInfo``.

.. real_arc_int:: ICertificateManagementContext
   :id: real_arc_int__crypto__i_cert_mgmt_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Certificate lifecycle management — the certificate-domain mirror of
   ``IKeyManagementContext``. Handles: ``ParseCertificate`` /
   ``ParseCertificates`` (returns ``ICertificateObject::Uptr`` backed by
   a daemon-assigned ephemeral handle), ``SaveCertificate(id, slot)``
   (copy semantics — object remains valid after persist), export
   (``GetCertificateExportSize`` + ``ExportCertificate``), format
   conversion (``GetConvertedCertificateSize`` + ``ConvertCertificateFormat``),
   ``ClearCertificate``, ``GetCertificateSlotInfo``, CRL management
   (``ImportCrl``, ``DeleteCrl``, ``DeleteExpiredCrls``,
   ``DeleteExpiredCertificates``),
   public key extraction (``LoadCertificatePublicKey`` — returns a
   ``CryptoResourceGuard`` wrapping an ephemeral ``kKey`` resource,
   following the same guard model as key-producing methods), and OCSP
   request construction (``GetOcspRequestData``).

.. real_arc_int:: ICertificateVerificationContext
   :id: real_arc_int__crypto__i_cert_ver_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Builder-style certificate chain verification. Configures
   certificate, chain, verification trust store, and revocation check
   policy via fluent setters, then executes verification with ``Verify()``.

.. real_arc_int:: ICsrGenerationContext
   :id: real_arc_int__crypto__i_csr_gen_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Builder-style CSR generation. Configures subject key (as
   ``CryptoResourceId``), signature algorithm, subject DN, and
   SAN extensions via fluent setters, then generates with
   ``Generate()``.

.. real_arc_int:: Typed Object Hierarchy
   :id: real_arc_int__crypto__typed_objects
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   ``ICryptoObject`` base with ``GetId()`` and ``GetType()``
   (both ``const noexcept``).  All trivial accessors returning
   POD, enum, ``bool``, or ``string_view`` values are marked
   ``noexcept`` for exception-safety and optimiser hints.
   Concrete typed objects: ``IKeyObject`` (algorithm, persistence,
   exportability, key length, permitted operations),
   ``ISymmetricKeyObject``,
   ``IPublicKeyObject``, ``IPrivateKeyObject`` (with
   ``GetPublicKey()`` to derive ephemeral public key from private),
   ``IKeySlotObject`` (slot state, allowed algorithm, provider binding,
   permitted operations),
   ``ICertificateObject`` (subject, issuer, validity),
   ``ICertSlotObject``, ``IProviderObject`` (type, name,
   supported algorithms), ``ISecureObject``, ``IDataObject``.
   Obtained via ``ICryptoContext`` accessors.

.. real_arc_int:: CryptoResourceId
   :id: real_arc_int__crypto__crypto_resource_id
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Compact runtime handle for a daemon-managed crypto resource.
   Contains a daemon-assigned 64-bit identifier, resource type
   (key, certificate, data, etc.), persistence semantics (transient
   vs. persistent), and provider index. Obtained via
   ``ICryptoContext::ResolveResource()`` for persistent resources or
   from a ``CryptoResourceGuard`` for transient resources. Passed
   directly to ``SetKey(const CryptoResourceId&)`` for the slot-direct
   configuration path.

.. real_arc_int:: BaseContextConfig
   :id: real_arc_int__crypto__base_context_config
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Common fluent builder base for all operation context configuration
   structs. Provides algorithm, provider, and timeout fields shared
   across all contexts. Operation-specific subclasses:
   ``HashContextConfig`` and ``RandomContextConfig`` (algorithm and
   provider only); ``MacContextConfig`` (adds ``SetKey()``);
   ``CipherContextConfig`` and ``AeadContextConfig`` (add ``SetKey()``
   and ``SetDirection()`` for encrypt/decrypt); ``SignContextConfig``
   and ``VerifySignatureContextConfig`` (add ``SetKey()``);
   ``KeyManagementContextConfig`` (algorithm and provider for key
   operations); ``CertificateContextConfig``,
   ``CertificateVerificationContextConfig`` (adds
   ``SetRevocationPolicy()``), and ``CsrGenerationContextConfig``.
   Key-bearing configs accept a ``CryptoResourceId`` via ``SetKey()``; a
   ``CryptoResourceGuard`` passes directly via its implicit conversion.

.. real_arc_int:: KdfParameters
   :id: real_arc_int__crypto__kdf_parameters
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Structured parameters for key derivation functions.
   Contains typed fields: ``kdf_algorithm`` (``AlgorithmId``),
   ``salt`` (fixed-capacity 128-byte array), ``label``
   (``FixedCapacityString<128>``), ``seed`` (fixed-capacity
   256-byte array), ``output_key_length``, and ``iteration_count``
   (both ``optional<uint32_t>``). All fields have fluent setters.
   Supports HKDF (RFC 5869), TLS 1.2 PRF (RFC 5246), TLS 1.3
   HKDF-Expand-Label (RFC 8446), PBKDF2 (RFC 8018), and
   SP800-108 counter-mode KDF. Used by ``DeriveKeyParams`` and
   optionally by ``AgreeKeyParams`` for combined agree+derive.

.. real_arc_int:: Key Operation Parameter Structs
   :id: real_arc_int__crypto__key_operation_params
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Per-operation fluent-builder parameter structs for
   ``IKeyManagementContext`` methods. Each struct encapsulates the
   inputs for one key lifecycle operation:

   - ``GenerateKeyParams`` — algorithm, permissions.
   - ``DeriveKeyParams`` — source key, derived key algorithm,
     ``KdfParameters``, permissions.
   - ``AgreeKeyParams`` — private key, peer public key (span),
     agreement algorithm, optional public key format, optional
     derived key algorithm, optional ``KdfParameters``, permissions.
   - ``WrapKeyParams`` — key to wrap, wrapping key, optional
     wrapping algorithm, IV (span), AAD (span).
   - ``UnwrapKeyParams`` — wrapped data (span), wrapping key,
     inner key algorithm, optional wrapping algorithm, IV, AAD,
     permissions.
   - ``ImportKeyParams`` — key data (span), format, algorithm,
     permissions.

   The ``target_slot`` destination is **not** part of any params
   struct — it is expressed via the method overload signature
   (``target_slot`` as the first parameter).

.. real_arc_int:: IHashContext
   :id: real_arc_int__crypto__i_hash_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Cryptographic hashing. Extends ``IStreamingOutputContext``;
   exposes ``Init()``, ``Update()``, ``Reset()``, and ``Finalize()``
   from the base classes via ``using``-declarations plus ``SingleShot()``
   and ``GetDigestSize()``. ``GetOutputSize()`` is intentionally not
   exposed — use ``GetDigestSize()`` instead.

.. real_arc_int:: IMacContext
   :id: real_arc_int__crypto__i_mac_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Message authentication code generation (HMAC, CMAC, GMAC, etc.). Extends
   ``IStreamingOutputContext``; exposes ``Init()`` with the optional-IV
   base signature, ``Update()``, ``Reset()``, and ``Finalize()`` via
   ``using``-declarations; adds ``Verify()`` and ``GetMacSize()``.
   ``GetOutputSize()`` is intentionally not exposed — use ``GetMacSize()``
   instead.

.. real_arc_int:: ICipherContext
   :id: real_arc_int__crypto__i_cipher_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Symmetric encryption and decryption. Extends
   ``IStreamingOutputContext``; exposes ``Init()``, ``Reset()``,
   ``Finalize()``, and ``GetOutputSize()`` from the base, plus
   cipher-specific ``Update(input, output)`` and ``SingleShot()``.
   ``Init()`` uses the base optional-IV signature (``span`` implicitly
   converts to ``optional<span>``); for IV-based modes (AES-CBC,
   AES-CTR) an IV must be provided, for ECB ``std::nullopt`` is valid.
   Direction (encrypt/decrypt) selected via
   ``CipherContextConfig::SetDirection()``.

.. real_arc_int:: IAeadContext
   :id: real_arc_int__crypto__i_aead_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Authenticated encryption with associated data. Extends
   ``IStreamingContext``; exposes ``Init()`` and ``Reset()`` from the
   base. ``Init()`` uses the base optional-IV signature; a nonce/IV
   must be provided (``nullopt`` returns ``kUnsupportedOperation``).
   Adds ``UpdateAad()``, AEAD-specific ``Update(input, output)``,
   dual finalization paths (``Finalize(output, tag)`` for encrypt,
   ``VerifyAndFinalize(output, tag)`` for decrypt), and
   ``GetTagSize()``.

.. real_arc_int:: ISignContext
   :id: real_arc_int__crypto__i_sign_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Digital signature generation. Extends ``IStreamingOutputContext``;
   exposes ``Init()``, ``Update()``, and ``Reset()`` from the base.
   Adds ``SignFinalize()``, ``SingleShot()``, and
   ``GetSignatureSize()``.  Base ``Finalize()`` and
   ``GetOutputSize()`` are not exposed.

.. real_arc_int:: IVerifySignatureContext
   :id: real_arc_int__crypto__i_verify_sign_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Digital signature verification. Extends ``IStreamingContext``;
   exposes ``Init()``, ``Update()``, and ``Reset()`` from the base.
   Adds ``VerifyFinalize()`` and ``SingleShot()``.

.. real_arc_int:: IRandomContext
   :id: real_arc_int__crypto__i_random_context
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   Cryptographically secure random number generation. Provides
   ``Generate()`` for filling a caller-supplied buffer with entropy
   from the configured provider.
