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

namespace score::crypto::daemon::provider::openssl
{

/// OpenSSL implementation of IKeyFactory.
///
/// Each key family claims the request.algorithm rows it serves: an ECC row on a
/// supported curve, ECDSA signature rows included, yields an EC key pair; an RSA
/// key row an RSA key pair; Ed25519 an Ed25519 key pair; and an AES or secret row
/// a symmetric key. A row no family claims, such as a hash row or an RSA-PSS
/// signature row, returns kUnsupportedAlgorithm.
///
/// Each returned IKeyHandler (OpenSslKeyHandler) exclusively owns the material
/// of one key: a heap buffer zeroized with OPENSSL_cleanse, or an EVP_PKEY.
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

    /// Generate a key of the family that claims the request.algorithm row.
    ///
    /// @param request Catalog row and permissions of the key to generate.
    /// @return The generated key, kUnsupportedAlgorithm when no family claims the row,
    ///         or the error of the family that claims it.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    GenerateKey(const key_management::KeyGenerationRequest& request) override;

    /// @brief Whether the factory accepts @p operation for @p algorithm, without performing it.
    ///
    /// Reports KEY_GENERATE only: EC keys on a curve OpenSSL names, RSA keys of a
    /// supported modulus size, Ed25519 keys, and symmetric keys of a known size.
    [[nodiscard]] bool IsOperationSupported(common::OperationAction operation,
                                            const AlgorithmDescriptor& algorithm) const override;

    /// Import raw symmetric key material, a DER-encoded key pair or public key, or a raw EC public point.
    ///
    /// @param request Key material, its format, catalog row and permissions.
    /// @return The imported key, kInvalidArgument when request.key_data is null or empty,
    ///         kUnsupportedAlgorithm when no family claims the row, or the error of the family that claims it.
    [[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    ImportKey(const key_management::KeyImportRequest& request) override;

    /// Export an EC public key as the raw uncompressed SEC1 point 0x04||X||Y.
    ///
    /// @param handle Handle of the key to export.
    /// @param format Requested export format; only kRaw is supported.
    /// @return The point, kUnsupportedOperation when the EC family does not claim the key's row,
    ///         or the errors of ExportEcPublicKey().
    [[nodiscard]] ::score::crypto::Expected<key_management::SecureKeyBytes,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    ExportKey(const key_management::ProviderKeyHandle& handle, score::crypto::FormatType format) override;

    /// Byte length of the raw export for @p handle, for the size-then-data two-call export.
    ///
    /// @param handle Handle of the key to export.
    /// @param format Requested export format; only kRaw is supported.
    /// @return The length, or the errors of ExportKey().
    [[nodiscard]] ::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
    GetExportKeySize(const key_management::ProviderKeyHandle& handle, score::crypto::FormatType format) override;

  private:
    common::ProviderId m_provider_id{common::kInvalidProviderId};
};

}  // namespace score::crypto::daemon::provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_FACTORY_HPP
