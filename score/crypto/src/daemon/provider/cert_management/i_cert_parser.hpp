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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_I_CERT_PARSER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_I_CERT_PARSER_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace score::crypto::daemon::cert_management
{
class CertObject;
struct CrlData;
}  // namespace score::crypto::daemon::cert_management

namespace score::crypto::daemon::provider::cert_management
{

/// Narrow provider capability for parsing certificate bytes into a
/// provider-neutral CertObject and encoding that object for certificate
/// management export. All other cert operations (verification, CSR generation,
/// and public-key extraction) are performed inside certificate context handlers
/// created by ICryptoHandlerFactory.
class ICertParser
{
  public:
    using Sptr = std::shared_ptr<ICertParser>;
    virtual ~ICertParser() = default;

    /// Parse a single DER/PEM certificate into a neutral CertObject.
    ///
    /// @param bytes Address of the encoded certificate data.
    /// @param size Number of bytes available at @p bytes.
    /// @param format Encoding format of the certificate data.
    /// @return An owning CertObject on success, or an error if the input cannot
    ///         be parsed as one certificate.
    [[nodiscard]] virtual score::crypto::Expected<std::shared_ptr<score::crypto::daemon::cert_management::CertObject>,
                                                  common::DaemonErrorCode>
    ParseCertificate(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format) = 0;

    /// Parse a sequence of X.509 certificates from PEM or DER data.
    ///
    /// PEM input is a sequence of certificate blocks. DER input is a sequence
    /// of complete DER-encoded X.509 objects. Protocol-specific framing and
    /// certificate-container formats are outside this parser contract. The
    /// operation decodes the objects but does not validate chain relationships
    /// or trust.
    ///
    /// @param bytes Address of the encoded certificate sequence.
    /// @param size Number of bytes available at @p bytes.
    /// @param format Encoding format of the sequence.
    /// @return The decoded certificates in input order, or an error if the input
    ///         is invalid or contains no certificates.
    [[nodiscard]] virtual score::crypto::Expected<
        std::vector<std::shared_ptr<score::crypto::daemon::cert_management::CertObject>>,
        common::DaemonErrorCode>
    ParseCertificates(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format) = 0;

    /// Encode a parsed certificate in the requested DER or PEM format.
    ///
    /// Each provider must define how parsed certificates are encoded.
    ///
    /// @param certificate Certificate to encode.
    /// @param format Requested output encoding.
    /// @return Encoded certificate bytes, or an error if encoding fails or the
    ///         format is unsupported.
    [[nodiscard]] virtual score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> EncodeCertificate(
        const score::crypto::daemon::cert_management::CertObject& certificate,
        score::crypto::FormatType format) = 0;

    /// Validate a CRL against the CA certificate that should have issued it.
    ///
    /// Checks (in order):
    /// 1. The CRL bytes are a parseable X.509 CRL in the encoding named by @p crl.
    /// 2. The CRL issuer DN equals the issuer cert's subject DN.
    /// 3. The CRL signature verifies against the issuer cert's public key.
    ///
    /// @param crl                 CRL bytes and encoding; empty bytes are rejected.
    /// @param issuer_cert_data    Encoded issuer certificate bytes.
    /// @param issuer_cert_size    Number of bytes available at @p issuer_cert_data.
    /// @param issuer_cert_format  Encoding format of the issuer certificate.
    /// @return Metadata from the validated CRL. Optional timestamps and
    ///         cRLNumber are zero when their fields are absent, or an error if
    ///         parsing, issuer matching, or signature verification fails.
    [[nodiscard]] virtual score::crypto::Expected<score::crypto::CrlMetadata, common::DaemonErrorCode> ValidateCrl(
        const score::crypto::daemon::cert_management::CrlData& crl,
        const std::uint8_t* issuer_cert_data,
        std::size_t issuer_cert_size,
        score::crypto::FormatType issuer_cert_format) = 0;
};

}  // namespace score::crypto::daemon::provider::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_I_CERT_PARSER_HPP
