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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_SYMMETRIC_KEY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_SYMMETRIC_KEY_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

#include <string_view>

namespace score::crypto::daemon::provider::openssl
{

/// True when @p algorithm names an AES or HMAC key ("AES-…", "HMAC-…").
///
/// @note This claims the family, not a key size: "AES-256" passes here and
///       still fails GenerateSymmetricKey(), which needs an exact table entry.
[[nodiscard]] bool IsSymmetricKeyAlgorithm(std::string_view algorithm) noexcept;

/// Generate a symmetric key using OpenSSL RAND_bytes.
///
/// The key size is common::LookupKeySize(request.algorithm).
/// Returns kInvalidArgument when the algorithm has no entry there, and
/// kOperationFailed when RAND_bytes fails.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
GenerateSymmetricKey(common::ProviderId provider_id, const key_management::KeyGenerationRequest& request);

/// Import raw symmetric key material by copying it into a new heap buffer.
///
/// @pre request.key_data is non-null and request.key_data_size is non-zero.
/// @note request.key_data_size is not checked against the key size of
///       request.algorithm; it becomes the handle's key_size as given.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
ImportSymmetricKey(common::ProviderId provider_id, const key_management::KeyImportRequest& request);

}  // namespace score::crypto::daemon::provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_SYMMETRIC_KEY_HPP
