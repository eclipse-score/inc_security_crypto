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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_OPENSSL_CERT_PATH_VALIDATOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_OPENSSL_CERT_PATH_VALIDATOR_HPP

#include "score/crypto/src/daemon/provider/cert_management/i_cert_path_validator.hpp"

namespace score::crypto::daemon::provider::score_provider::openssl
{

/// OpenSSL implementation of ICertPathValidator.
///
/// Each call builds its own X509_STORE from the request's trust anchors and CRLs and runs X509_verify_cert() on the
/// leaf with the presented intermediates. The outcome is mapped to a CertVerifyResult, and the verified chain is
/// returned as the caller's certificate objects. The validator holds no per-call state, so one instance may serve
/// concurrent requests.
///
/// Only CRL-based revocation checking is supported. OCSP policies are rejected with kUnsupportedOperation.
class OpenSslCertPathValidator final : public provider::cert_management::ICertPathValidator
{
  public:
    OpenSslCertPathValidator() = default;
    ~OpenSslCertPathValidator() override = default;

    OpenSslCertPathValidator(const OpenSslCertPathValidator&) = delete;
    OpenSslCertPathValidator& operator=(const OpenSslCertPathValidator&) = delete;
    OpenSslCertPathValidator(OpenSslCertPathValidator&&) = delete;
    OpenSslCertPathValidator& operator=(OpenSslCertPathValidator&&) = delete;

    [[nodiscard]] score::crypto::Expected<provider::cert_management::PathValidationResult, common::DaemonErrorCode>
    Validate(const provider::cert_management::PathValidationRequest& request) override;
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_OPENSSL_CERT_PATH_VALIDATOR_HPP
