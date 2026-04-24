..
    # =============================================================================
    #  C O P Y R I G H T
    # -----------------------------------------------------------------------------
    #  Copyright (c) 2026 by ETAS GmbH. All rights reserved.
    #
    #  The reproduction, distribution and utilization of this file as
    #  well as the communication of its contents to others without express
    #  authorization is prohibited. Offenders will be held liable for the
    #  payment of damages. All rights reserved in the event of the grant
    #  of a patent, utility model or design.
    # =============================================================================

.. _crypto_dynamic_architecture:

API Dynamic Architecture
========================

.. comp_arc_dyn:: Dynamic View
   :id: comp_arc_dyn__crypto__dynamic_view
   :security: YES
   :safety: QM
   :status: invalid
   :fulfils:

   Dynamic interactions for typical crypto operations.

Typical Usage Flow
------------------

The standard interaction sequence for performing a cryptographic operation:

.. uml:: typical_usage_sequence.puml
   :align: center
   :scale: 75

Pre-Deployed Key Flow (Slot-Direct Path)
-----------------------------------------

Using a pre-deployed persistent key for encryption — the simplest path.
No ``LoadKey`` or guard needed; the context internally loads from the slot:

..
   TODO: Removal all code blocks in this file.
   It must be part of the examples over time.

.. code-block:: cpp

   // 1. Create stack and context
   CryptoStackConfig stack_config;
   stack_config.SetConnectionEndpoint("unix:///var/run/crypto-daemon.sock");
   auto stack = CreateCryptoStack(stack_config).value();
   auto ctx = stack->CreateCryptoContext().value();

   // 2. Resolve the pre-deployed key slot (no LoadKey needed)
   auto slot = ctx->ResolveResource("PreDeployedSlot", ResourceType::kKeySlot).value();

   // 3. Create cipher context — pass slot directly to SetKey
   //    The context factory internally loads key material from the slot.
   CipherContextConfig enc_config;
   enc_config.SetAlgorithm("AES-256-CBC").SetKey(slot).SetDirection(CipherDirection::kEncrypt);
   auto enc = ctx->CreateCipherContext(enc_config).value();

   // 4. Encrypt data
   enc->Init(iv_span);
   enc->Update(plaintext_span, ciphertext_span);
   enc->Finalize(final_out_span);

   // 5. Context destruction releases the internally-loaded key material.

Pre-Deployed Key Flow (Guard Path — Multi-Context Reuse)
---------------------------------------------------------

When the same key must be used across multiple contexts simultaneously,
use ``LoadKey()`` to get a ``CryptoResourceGuard``:

.. code-block:: cpp

   // 1. Resolve slot and load key explicitly
   auto slot = ctx->ResolveResource("PreDeployedSlot", ResourceType::kKeySlot).value();
   auto key_mgmt = ctx->CreateKeyManagementContext(KeyManagementContextConfig{}).value();
   auto key_guard = key_mgmt->LoadKey(slot).value();
   // key_guard is a CryptoResourceGuard wrapping type == kKey

   // 2. Query key slot metadata
   auto info = key_mgmt->GetKeySlotInfo(slot).value();
   // info == {kOccupied, "AES-256", provider=2, compatible=[2,5]}

   // 3. Use the same loaded key in two contexts — implicit conversion
   CipherContextConfig enc_config;
   enc_config.SetAlgorithm("AES-256-CBC").SetKey(key_guard).SetDirection(CipherDirection::kEncrypt);
   auto enc = ctx->CreateCipherContext(enc_config).value();

   CipherContextConfig dec_config;
   dec_config.SetAlgorithm("AES-256-CBC").SetKey(key_guard).SetDirection(CipherDirection::kDecrypt);
   auto dec = ctx->CreateCipherContext(dec_config).value();

   // 4. Use both contexts...

   // 5. ~key_guard releases the loaded key material via ReleaseResource()

Ephemeral Key Generation and Use
---------------------------------

Generating an ephemeral key, using it, and optionally persisting:

.. code-block:: cpp

   // Generate ephemeral key (returns CryptoResourceGuard)
   auto key_mgmt = ctx->CreateKeyManagementContext(KeyManagementContextConfig{}).value();
   auto eph_key = key_mgmt->GenerateKey(GenerateKeyParams{}
       .SetAlgorithm("AES-256")
       .SetPermissions(KeyOperationPermission::kEncrypt | KeyOperationPermission::kDecrypt)).value();
   // eph_key is a CryptoResourceGuard wrapping:
   //   type == ResourceType::kKey
   //   persistence == ResourcePersistence::kEphemeral
   //   permitted operations == kEncrypt | kDecrypt

   // Use immediately in an operation — implicit conversion to const CryptoResourceId&
   CipherContextConfig config;
   config.SetAlgorithm("AES-256-GCM").SetKey(eph_key).SetDirection(CipherDirection::kEncrypt);
   auto enc = ctx->CreateCipherContext(config).value();
   // ... encrypt data ...

   // Optionally persist for future use
   auto target = ctx->ResolveResource("MyNewSlot", ResourceType::kKeySlot).value();
   key_mgmt->PersistKey(target, eph_key);  // copy semantics: eph_key guard stays active
   // Use target (kKeySlot handle) for all future durable operations

Hashing Example
---------------

.. code-block:: cpp

   HashContextConfig hash_config;
   hash_config.SetAlgorithm("SHA-256");
   auto hash = ctx->CreateHashContext(hash_config).value();

   // Streaming
   hash->Init();
   hash->Update(chunk1);
   hash->Update(chunk2);
   auto bytes_written = hash->Finalize(digest_out).value();

   // Or single-shot
   auto bytes = hash->SingleShot(input, digest_out).value();

Context Reuse via Reset()
-------------------------

.. code-block:: cpp

   // Create the context once — expensive (factory + IPC)
   HashContextConfig hash_config;
   hash_config.SetAlgorithm("SHA-256");
   auto hash = ctx->CreateHashContext(hash_config).value();

   // First message
   hash->Init();
   hash->Update(message1);
   auto n1 = hash->Finalize(digest1).value();

   // Reuse — cheap (single IPC call, no factory overhead)
   hash->Reset();

   // Second message with the same context
   hash->Init();
   hash->Update(message2);
   auto n2 = hash->Finalize(digest2).value();

   // Can also abort mid-stream and restart
   hash->Init();
   hash->Update(partial_data);
   hash->Reset();  // discard partial work
   hash->Init();
   hash->Update(correct_data);
   auto n3 = hash->Finalize(digest3).value();

Signing with PQC Algorithm
---------------------------

.. code-block:: cpp

   // Generate ML-DSA-65 key pair (returns CryptoResourceGuard)
   auto key_mgmt = ctx->CreateKeyManagementContext(KeyManagementContextConfig{}).value();
   auto signing_key = key_mgmt->GenerateKey(GenerateKeyParams{}.SetAlgorithm("ML-DSA-65")).value();

   // Sign data — implicit conversion passes guard to SetKey
   SignContextConfig sign_config;
   sign_config.SetAlgorithm("ML-DSA-65").SetKey(signing_key);
   auto signer = ctx->CreateSignContext(sign_config).value();
   auto sig_size = signer->GetSignatureSize(); // ~3293 bytes for ML-DSA-65
   signer->Init();
   signer->Update(message);
   auto sig_len = signer->SignFinalize(signature_buf).value();

   // ~signing_key releases the ephemeral key pair

Certificate Verification
-------------------------

.. code-block:: cpp

   // Resolve certificate and verification trust store
   auto cert = ctx->ResolveResource("DeviceCert", ResourceType::kCertSlot).value();
   auto anchor = ctx->ResolveResource("RootCA", ResourceType::kVerificationTrustStore).value();

   // Verify using builder-style context
   CertificateVerificationContextConfig verify_cfg;
   auto verifier = ctx->CreateCertificateVerificationContext(verify_cfg).value();
   verifier->SetCertificate(cert);
   verifier->SetVerificationTrustStore(anchor);
   verifier->SetRevocationCheckPolicy(RevocationCheckPolicy::kCrlOnly);
   auto result = verifier->Verify().value();

   if (result == CertVerifyResult::kValid) {
       // Extract public key for use — returns CryptoResourceGuard
       auto [pub_key, alg] = cert_mgmt->LoadCertificatePublicKey(cert).value();
       // pub_key is a CryptoResourceGuard; use via implicit conversion to const CryptoResourceId&
       // ~pub_key releases the ephemeral key when it goes out of scope
   }

Key Operation Permissions
--------------------------

Enforcing least-privilege on cryptographic keys:

.. code-block:: cpp

   // 1. Generate an encryption-only key (cannot be used for signing)
   auto key_mgmt = ctx->CreateKeyManagementContext(KeyManagementContextConfig{}).value();
   auto enc_key = key_mgmt->GenerateKey(GenerateKeyParams{}
       .SetAlgorithm("AES-256")
       .SetPermissions(KeyOperationPermission::kEncrypt | KeyOperationPermission::kDecrypt)).value();

   // 2. Encryption works — key has kEncrypt permission
   CipherContextConfig enc_config;
   enc_config.SetAlgorithm("AES-256-CBC").SetKey(enc_key).SetDirection(CipherDirection::kEncrypt);
   auto enc = ctx->CreateCipherContext(enc_config).value();  // OK

   // 3. Signing is rejected — key lacks kSign permission
   SignContextConfig sign_config;
   sign_config.SetAlgorithm("HMAC-SHA-256").SetKey(enc_key);
   auto sign_result = ctx->CreateSignContext(sign_config);
   // sign_result.error() == kKeyOperationNotPermitted

.. code-block:: cpp

   // 4. Query permissions from a key slot
   auto slot = ctx->ResolveResource("SigningKey", ResourceType::kKeySlot).value();
   auto slot_obj = ctx->GetKeySlotObject(slot).value();
   auto perms = slot_obj->GetPermittedOperations();

   if (HasPermission(perms, KeyOperationPermission::kSign)) {
       // Key slot allows signing
   }

   // 5. Use composite presets for common patterns
   auto auth_key = key_mgmt->GenerateKey(GenerateKeyParams{}
       .SetAlgorithm("ECDSA-P256")
       .SetPermissions(KeyOperationPermission::kAuthentication)).value();
   // auth_key can sign, verify, MAC, and agree — but cannot encrypt or wrap

Operation Timeout Configuration
--------------------------------

Bounding all IPC calls with a per-call deadline for safety analysis:

.. code-block:: cpp

   // 1. Stack-wide default: 500 ms per IPC call
   CryptoStackConfig stack_config;
   stack_config.SetConnectionEndpoint("unix:///var/run/crypto-daemon.sock")
               .SetDefaultOperationTimeout(std::chrono::milliseconds{500});
   auto stack = CreateCryptoStack(stack_config).value();
   auto ctx = stack->CreateCryptoContext().value();

   // 2. Per-context override: tighter 200 ms deadline for hashing
   HashContextConfig hash_cfg;
   hash_cfg.SetAlgorithm("SHA-256")
           .SetOperationTimeout(std::chrono::milliseconds{200});
   auto hash = ctx->CreateHashContext(hash_cfg).value();

   // Each Init(), Update(), Finalize() has its own 200 ms deadline.
   hash->Init();               // ≤ 200 ms or kOperationTimedOut
   hash->Update(chunk1);       // ≤ 200 ms or kOperationTimedOut
   auto result = hash->Finalize(digest_out);
   if (!result.has_value()) {
       // On timeout: context is in error state, must destroy and recreate.
       // result.error() == kOperationTimedOut
   }

   // 3. Disable timeout for slow PQC key generation on HSM
   KeyManagementContextConfig keygen_cfg;
   keygen_cfg.DisableTimeout();  // No deadline — HSM may take seconds
   auto key_mgmt = ctx->CreateKeyManagementContext(keygen_cfg).value();
   auto pqc_key = key_mgmt->GenerateKey(GenerateKeyParams{}.SetAlgorithm("ML-KEM-768")).value();
   // PQC key generation can take seconds on hardware — no timeout error
