/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_FACTORY_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <cstddef>
#include <functional>
#include <memory>
#include <string_view>

// Opaque OpenSSL context type; the implementation includes the OpenSSL headers.
struct evp_pkey_ctx_st;
using EVP_PKEY_CTX = evp_pkey_ctx_st;

namespace score::crypto::daemon::provider::openssl
{

/// OpenSSL implementation of IKeyFactory.
///
/// Key material model:
///   GenerateKey — RAND_bytes → heap buffer → OpenSslKeyHandler (owns unique_ptr<uint8_t[]>)
///   ImportKey   — memcpy → heap buffer → OpenSslKeyHandler
///
/// Each returned IKeyHandler (OpenSslKeyHandler) owns exclusive heap memory for
/// one key. Zeroization uses OPENSSL_cleanse, which is guaranteed not to be
/// optimized away by the compiler.
///
/// Thread safety: GenerateKey and ImportKey are safe to call concurrently
/// because each call allocates independent memory. The returned OpenSslKeyHandler
/// instances are not shared and require no additional locking.
class OpenSslKeyFactory final : public key_management::IKeyFactory
{
  public:
    OpenSslKeyFactory(common::ProviderId provider_id);
    ~OpenSslKeyFactory() override = default;

    OpenSslKeyFactory(const OpenSslKeyFactory&) = delete;
    OpenSslKeyFactory& operator=(const OpenSslKeyFactory&) = delete;
    OpenSslKeyFactory(OpenSslKeyFactory&&) = delete;
    OpenSslKeyFactory& operator=(OpenSslKeyFactory&&) = delete;

    /// Generate a symmetric key using OpenSSL RAND_bytes, or an asymmetric key pair.
    ///
    /// Symmetric key size is derived from request.algorithm:
    ///   HMAC-SHA256 → 32 B  |  HMAC-SHA384 → 48 B  |  HMAC-SHA512 → 64 B
    ///   AES-128-*   → 16 B  |  AES-192-*   → 24 B  |  AES-256-*   → 32 B
    ///
    /// ECDSA, RSA and Ed25519 key algorithms produce a single EVP_PKEY carrying
    /// both halves.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    GenerateKey(const key_management::KeyGenerationRequest& request) override;

    /// Import raw key material by copying into a new heap buffer, or parse a
    /// DER-encoded asymmetric key when request.algorithm names one.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    ImportKey(const key_management::KeyImportRequest& request) override;

  private:
    /// Result of parsing DER key material.
    struct ParsedDerKey
    {
        EvpPkeyPtr pkey{};             ///< Parsed key
        bool has_private_half{false};  ///< True for PKCS#8 private keys, false for SubjectPublicKeyInfo
    };

    common::ProviderId m_provider_id{common::kInvalidProviderId};

    /// Parse DER key material (PKCS#8 private key or SubjectPublicKeyInfo) of any
    /// supported asymmetric type into an EVP_PKEY.
    [[nodiscard]] ::score::crypto::Expected<ParsedDerKey, common::DaemonErrorCode> ParseDerKey(
        const key_management::KeyImportRequest& request);

    /// Wraps an already validated, parsed key in an OpenSslKeyHandler.
    ///
    /// Only handles behavior shared after the algorithm-specific key validation.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode>
    CreateImportedAsymmetricKey(const key_management::KeyImportRequest& request,
                                ParsedDerKey parsed,
                                std::size_t key_size);

    /// Generate an EC key pair on the curve named by request.algorithm.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    GenerateEcKey(const key_management::KeyGenerationRequest& request);

    /// Parse DER key material (PKCS#8 private key or SubjectPublicKeyInfo) into
    /// an EVP_PKEY.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    ImportEcKey(const key_management::KeyImportRequest& request);

    /// Generate an RSA key pair of the size named by request.algorithm (2048, 3072 or 4096 bits).
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    GenerateRsaKey(const key_management::KeyGenerationRequest& request);

    /// Generate an Ed25519 key pair.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    GenerateEd25519Key(const key_management::KeyGenerationRequest& request);

    /// Import a DER-encoded RSA key and validate that its size matches request.algorithm.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    ImportRsaKey(const key_management::KeyImportRequest& request);

    /// Import a DER-encoded Ed25519 key.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    ImportEd25519Key(const key_management::KeyImportRequest& request);

    /// Per-algorithm constants for GenerateAsymmetricKey.
    struct KeygenSpec
    {
        const char* key_type;
        std::size_t key_size;
        const char* operation;
    };

    /// Shared by GenerateEcKey, GenerateRsaKey and GenerateEd25519Key: creates the
    /// EVP_PKEY_CTX, applies configure_keygen, generates the key pair, and wraps
    /// it in an OpenSslKeyHandler.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    GenerateAsymmetricKey(
        const key_management::KeyGenerationRequest& request,
        const KeygenSpec& spec,
        const std::function<bool(EVP_PKEY_CTX*)>& configure_keygen = [](EVP_PKEY_CTX*) {
            return true;
        });

    /// Map well-known algorithm names to symmetric key sizes in bytes.
    /// Returns 0 for unknown algorithms.
    [[nodiscard]] static std::size_t DetermineKeySize(const common::AlgorithmId& algorithm) noexcept;
};

}  // namespace score::crypto::daemon::provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_FACTORY_HPP
