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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_EC_KEY_PAIR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_EC_KEY_PAIR_HPP

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

namespace score::crypto::daemon::provider::openssl
{

/// Whether the EC family serves @p algorithm: an ECC row on P-256, P-384 or P-521.
///
/// ECDSA signature rows are claimed as well, because such a row names the curve of its key.
[[nodiscard]] bool IsEcKeySupported(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept;

/// Generate an EC key pair on the curve of the request.algorithm row.
///
/// The returned handler owns a single EVP_PKEY carrying both halves.
/// Returns kUnsupportedAlgorithm when IsEcKeySupported() rejects the row.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
GenerateEcKeyPair(common::ProviderId provider_id, const key_management::KeyGenerationRequest& request);

/// Import a DER-encoded EC key (a private key, PKCS#8 or traditional, or a
/// SubjectPublicKeyInfo) into an OpenSslKeyHandler.
///
/// With request.format kRaw the bytes are instead the uncompressed SEC1 public
/// point 0x04||X||Y, which yields a public key without private-half permissions.
/// A raw point of the wrong length, another encoding, or off the curve returns kInvalidFormat.
///
/// Returns kUnsupportedAlgorithm when IsEcKeySupported() rejects the request.algorithm row,
/// kInvalidFormat when request.format is not kDer or the bytes are not one complete DER key,
/// kInvalidArgument when request.key_data_size does not fit a long, and kIncompatibleKeyType
/// when the key is not an EC key or lies on another curve.
/// @pre request.key_data is non-null and request.key_data_size is non-zero.
/// @note A SubjectPublicKeyInfo import carries no private-half permissions,
///       whatever request.permissions grants.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
ImportEcKey(common::ProviderId provider_id, const key_management::KeyImportRequest& request);

/// Export the public half of an EC key as the raw uncompressed SEC1 point 0x04||X||Y.
///
/// Returns kUnsupportedOperation when @p format is not kRaw, kIncompatibleKeyType when
/// @p handle is not a key pair or public key that IsEcKeySupported() claims, and
/// kKeyNotExportable when the public-half permissions lack kExport.
/// The point is uncompressed whatever encoding the key was imported from.
/// @pre @p handle was issued by this provider, so its opaque_id is the address of its EVP_PKEY.
[[nodiscard]] ::score::crypto::Expected<key_management::SecureKeyBytes,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
ExportEcPublicKey(const key_management::ProviderKeyHandle& handle, score::crypto::FormatType format);

/// Byte length ExportEcPublicKey() produces for @p handle, with the same checks and errors.
[[nodiscard]] ::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
GetEcPublicKeyExportSize(const key_management::ProviderKeyHandle& handle, score::crypto::FormatType format);

}  // namespace score::crypto::daemon::provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_EC_KEY_PAIR_HPP
