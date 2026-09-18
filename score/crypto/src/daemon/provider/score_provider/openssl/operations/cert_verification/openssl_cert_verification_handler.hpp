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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_OPENSSL_CERT_VERIFICATION_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_OPENSSL_CERT_VERIFICATION_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/operations/cert_verification/score_cert_verification_handler.hpp"

#include <memory>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// OpenSSL implementation of the certificate verification handler.
///
/// Overrides DoVerify() with OpenSSL X509_STORE_CTX-based chain verification.
/// Trust anchors are pre-resolved by the base class before DoVerify() is called.
/// Concrete verification steps:
///   - Trust anchors loaded into an X509_STORE
///   - X509_V_FLAG_PARTIAL_CHAIN applied for kTrustStoreTerminated policy
///   - Untrusted intermediates (chain + additional) supplied to X509_STORE_CTX
///   - Verified chain returned as CertObject::Sptr values (leaf first)
class OpenSslCertVerificationHandler final
    : public score_provider::operations::cert_verification::ScoreCertVerificationHandler
{
  public:
    OpenSslCertVerificationHandler(
        std::unique_ptr<score_provider::operations::cert_verification::CertVerificationExecutor> executor,
        std::shared_ptr<::score::crypto::daemon::cert_management::CertManagementService> service);

    ~OpenSslCertVerificationHandler() override = default;

    OpenSslCertVerificationHandler(const OpenSslCertVerificationHandler&) = delete;
    OpenSslCertVerificationHandler& operator=(const OpenSslCertVerificationHandler&) = delete;
    OpenSslCertVerificationHandler(OpenSslCertVerificationHandler&&) = delete;
    OpenSslCertVerificationHandler& operator=(OpenSslCertVerificationHandler&&) = delete;

  protected:
    [[nodiscard]] Expected<VerifyOutcome, common::DaemonErrorCode> DoVerify(const VerificationInput& input) override;

    [[nodiscard]] Expected<common::OwnedBuffer, common::DaemonErrorCode> EncodeCertificate(
        const CertSptr& cert,
        score::crypto::FormatType format) const override;
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CERT_VERIFICATION_OPENSSL_CERT_VERIFICATION_HANDLER_HPP
