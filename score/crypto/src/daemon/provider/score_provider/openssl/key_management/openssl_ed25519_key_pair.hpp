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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_ED25519_KEY_PAIR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_ED25519_KEY_PAIR_HPP

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

namespace score::crypto::daemon::provider::openssl
{

/// Whether the Ed25519 family serves @p algorithm: the Ed25519 row.
[[nodiscard]] bool IsEd25519KeySupported(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept;

/// Generate an Ed25519 key pair.
///
/// The returned handler owns a single EVP_PKEY carrying both halves.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
GenerateEd25519KeyPair(common::ProviderId provider_id, const key_management::KeyGenerationRequest& request);

/// Import a DER-encoded Ed25519 key (a PKCS#8 private key or a
/// SubjectPublicKeyInfo) into an OpenSslKeyHandler.
///
/// Returns kInvalidFormat when request.format is not kDer or the bytes are not one complete DER key,
/// kInvalidArgument when request.key_data_size does not fit a long, and kIncompatibleKeyType when
/// the key is not an Ed25519 key.
/// @pre request.key_data is non-null and request.key_data_size is non-zero.
/// @note A SubjectPublicKeyInfo import carries no private-half permissions,
///       whatever request.permissions grants.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
ImportEd25519Key(common::ProviderId provider_id, const key_management::KeyImportRequest& request);

}  // namespace score::crypto::daemon::provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_ED25519_KEY_PAIR_HPP
