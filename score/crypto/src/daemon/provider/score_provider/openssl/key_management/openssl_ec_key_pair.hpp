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

/// Whether the EC family serves @p algorithm.
///
/// ECDSA signature rows are claimed as well, because such a row names the curve of its key.
/// @param algorithm Catalog row of a request or key handle.
/// @return true for an ECC row on P-256, P-384 or P-521.
[[nodiscard]] bool IsEcKeySupported(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept;

/// Generate an EC key pair on the curve of the request.algorithm row.
///
/// @param provider_id Provider that issues the key handle.
/// @param request Catalog row and permissions of the key to generate.
/// @return A handler owning one EVP_PKEY that carries both halves,
///         or kUnsupportedAlgorithm when IsEcKeySupported() rejects the row.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
GenerateEcKeyPair(common::ProviderId provider_id, const key_management::KeyGenerationRequest& request);

/// Import an EC key into an OpenSslKeyHandler.
///
/// The format is request.format, or detected when unset (see detail::ResolveAsymmetricFormat()).
/// As kDer or kPem the bytes are a private key (PKCS#8 or traditional) or a SubjectPublicKeyInfo.
/// As kRaw they are the uncompressed SEC1 public point 0x04||X||Y.
/// @param provider_id Provider that issues the key handle.
/// @param request Key material, its format, catalog row and permissions.
/// @return The imported key, or
///         - kUnsupportedAlgorithm when IsEcKeySupported() rejects the request.algorithm row;
///         - kInvalidFormat when the DER or PEM is not one complete key,
///           or the raw point has the wrong length, another encoding, or lies off the curve;
///         - kInvalidArgument when request.key_data_size does not fit a long;
///         - kIncompatibleKeyType when the parsed key is not an EC key or lies on another curve.
/// @pre request.key_data is non-null and request.key_data_size is non-zero.
/// @note A SubjectPublicKeyInfo or raw-point import carries no private-half permissions,
///       whatever request.permissions grants.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
ImportEcKey(common::ProviderId provider_id, const key_management::KeyImportRequest& request);

/// Export the public half of an EC key as the raw uncompressed SEC1 point 0x04||X||Y.
///
/// The point is uncompressed whatever encoding the key was imported from.
/// @param handle Handle of the key to export.
/// @param format Requested export format; only kRaw is supported.
/// @return The point, or
///         - kUnsupportedOperation when @p format is not kRaw;
///         - kIncompatibleKeyType when @p handle is not a key pair or public key that IsEcKeySupported() claims;
///         - kKeyNotExportable when the public-half permissions lack kExport.
/// @pre @p handle was issued by this provider, so its opaque_id is the address of its EVP_PKEY.
[[nodiscard]] ::score::crypto::Expected<key_management::SecureKeyBytes,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
ExportEcPublicKey(const key_management::ProviderKeyHandle& handle, score::crypto::FormatType format);

/// Byte length ExportEcPublicKey() produces for @p handle.
///
/// @param handle Handle of the key to export.
/// @param format Requested export format; only kRaw is supported.
/// @return The length of the uncompressed point, or the errors of ExportEcPublicKey().
/// @pre @p handle was issued by this provider, so its opaque_id is the address of its EVP_PKEY.
[[nodiscard]] ::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
GetEcPublicKeyExportSize(const key_management::ProviderKeyHandle& handle, score::crypto::FormatType format);

}  // namespace score::crypto::daemon::provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_EC_KEY_PAIR_HPP
