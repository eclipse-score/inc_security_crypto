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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_DETAIL_OPENSSL_VERIFY_RESULT_MAPPING_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_DETAIL_OPENSSL_VERIFY_RESULT_MAPPING_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <optional>

namespace score::crypto::daemon::provider::openssl::detail
{

/// @brief Maps an OpenSSL verification error to a CertVerifyResult.
///
/// @param x509_err X509_V_ERR_* code from X509_STORE_CTX_get_error().
/// @return The verdict, or nullopt if the error is not a completed verification outcome and should be reported
///         as an operation failure instead.
std::optional<::score::crypto::CertVerifyResult> MapX509Error(int x509_err);

/// @brief Maps an OpenSSL error that MapX509Error() does not treat as an outcome to the daemon error describing
///        why verification could not be completed.
///
/// @param x509_err X509_V_ERR_* code from X509_STORE_CTX_get_error().
/// @return A specific error for allocation, malformed-certificate and unsupported-feature codes,
///         otherwise kOperationFailed.
common::DaemonErrorCode MapX509OperationError(int x509_err);

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_DETAIL_OPENSSL_VERIFY_RESULT_MAPPING_HPP
