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

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

namespace score::crypto::daemon::provider::openssl
{

/// Whether the symmetric family serves @p algorithm.
///
/// @param algorithm Catalog row of a request.
/// @return true for an AES or secret-key row.
[[nodiscard]] bool IsSymmetricKeySupported(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept;

/// Generate a symmetric key using OpenSSL RAND_bytes.
///
/// The key size is common::LookupKeySize() of the request.algorithm row.
/// @param provider_id Provider that issues the key handle.
/// @param request Catalog row and permissions of the key to generate.
/// @return A handler owning the key bytes, or
///         - kInvalidArgument when the row labels no key or a key of zero bytes;
///         - kOperationFailed when RAND_bytes fails.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
GenerateSymmetricKey(common::ProviderId provider_id, const key_management::KeyGenerationRequest& request);

/// Import raw symmetric key material by copying it into a new heap buffer.
///
/// @param provider_id Provider that issues the key handle.
/// @param request Key bytes, catalog row and permissions.
/// @return A handler owning the copied key bytes.
/// @pre request.key_data is non-null and request.key_data_size is non-zero.
/// @pre The request passed IKeyFactory::ValidateSymmetricImport(); OpenSslKeyFactory::ImportKey() checks it.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
ImportSymmetricKey(common::ProviderId provider_id, const key_management::KeyImportRequest& request);

}  // namespace score::crypto::daemon::provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_SYMMETRIC_KEY_HPP
