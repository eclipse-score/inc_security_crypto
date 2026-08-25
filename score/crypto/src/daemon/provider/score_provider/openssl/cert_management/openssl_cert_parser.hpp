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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_OPENSSL_CERT_PARSER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_OPENSSL_CERT_PARSER_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"

namespace score::crypto::daemon::provider::score_provider::openssl
{

/// OpenSSL implementation of ICertParser.
///
/// Parses DER/PEM certificate bytes into provider-neutral CertObjects using
/// OpenSSL's X509 stack. Stateless beyond the provider ID; created on demand
/// by OpenSSL::GetCertParser() for injection into FileBackedSlotHandler.
///
/// Verification, CSR generation, public-key extraction, and format conversion
/// are certificate context-handler responsibilities, not parser concerns.
class OpenSslCertParser final : public cert_management::ICertParser
{
  public:
    explicit OpenSslCertParser(common::ProviderId provider_id) noexcept : m_provider_id{provider_id} {}
    ~OpenSslCertParser() override = default;

    OpenSslCertParser(const OpenSslCertParser&) = delete;
    OpenSslCertParser& operator=(const OpenSslCertParser&) = delete;
    OpenSslCertParser(OpenSslCertParser&&) = delete;
    OpenSslCertParser& operator=(OpenSslCertParser&&) = delete;

    [[nodiscard]] score::crypto::Expected<::score::crypto::daemon::cert_management::CertObject::Sptr,
                                          common::DaemonErrorCode>
    ParseCertificate(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format) override;

    [[nodiscard]] score::crypto::Expected<std::vector<::score::crypto::daemon::cert_management::CertObject::Sptr>,
                                          common::DaemonErrorCode>
    ParseCertificates(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format) override;

  private:
    common::ProviderId m_provider_id;
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_CERT_MANAGEMENT_OPENSSL_CERT_PARSER_HPP
