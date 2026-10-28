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

#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

namespace score::crypto::daemon::provider::openssl
{

/// Generate an EC key pair on the curve named by request.algorithm
/// ("ECDSA-P256", "ECDSA-P384", "ECDSA-P521").
///
/// The returned handler owns a single EVP_PKEY carrying both halves.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
GenerateEcKeyPair(common::ProviderId provider_id, const key_management::KeyGenerationRequest& request);

/// Parse DER key material (PKCS#8 private key or SubjectPublicKeyInfo) into an EVP_PKEY.
///
/// @pre request.key_data is non-null and request.key_data_size is non-zero.
/// @warning request.format must be kDer; any other format returns kInvalidFormat,
///          even when the bytes are valid DER.
/// @note A SubjectPublicKeyInfo import carries no private-half permissions,
///       whatever request.permissions grants.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
ImportEcKey(common::ProviderId provider_id, const key_management::KeyImportRequest& request);

}  // namespace score::crypto::daemon::provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_EC_KEY_PAIR_HPP
