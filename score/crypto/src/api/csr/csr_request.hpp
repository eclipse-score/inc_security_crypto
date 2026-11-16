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

#ifndef SCORE_CRYPTO_SRC_API_CSR_CSR_REQUEST_HPP
#define SCORE_CRYPTO_SRC_API_CSR_CSR_REQUEST_HPP

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace score::crypto
{
class ICsrProcessingService;
class NativeCsrProcessing;
namespace csr::wire
{
struct Access;
}
/// Attribute identifiers, independent of OpenSSL NIDs. Repeated attributes preserve order.
enum class CsrOid
{
    kCommonName,
    kSurname,
    kSerialNumber,
    kCountry,
    kLocality,
    kState,
    kStreet,
    kOrganization,
    kOrganizationalUnit,
    kTitle,
    kDescription,
    kPostalCode,
    kPostOfficeBox,
    kPhysicalDeliveryOfficeName,
    kTelephoneNumber,
    kName,
    kGivenName,
    kInitials,
    kGenerationQualifier,
    kDnQualifier,
    kPseudonym,
    kDomainComponent,
    kUserId,
    kEmailAddress,
    kOrganizationIdentifier
};
std::string_view GetCsrOid(CsrOid oid) noexcept;

struct CsrSubjectAttribute
{
    std::string oid;
    std::string value;
};

class CsrSubject
{
  public:
    score::Result<std::monostate> Add(ICsrProcessingService& processing, CsrOid oid, std::string_view value);
    /// Custom attribute identifiers must be canonical dotted OIDs (not aliases).
    score::Result<std::monostate> Add(ICsrProcessingService& processing, std::string_view oid, std::string_view value);
    const std::vector<CsrSubjectAttribute>& Attributes() const noexcept
    {
        return attributes_;
    }
    /// Compatibility syntax: comma-separated name=value, with backslash escaping
    /// for comma, equals and backslash. Multi-valued RDNs and hex escapes are rejected.
    static score::Result<CsrSubject> FromDn(ICsrProcessingService& processing, std::string_view dn);

  private:
    friend class NativeCsrProcessing;
    friend struct csr::wire::Access;
    std::vector<CsrSubjectAttribute> attributes_;
};

enum class CsrSanType
{
    kDns,
    kIp,
    kEmail,
    kUri
};
struct CsrSubjectAltName
{
    CsrSanType type;
    std::string value;
};
enum class CsrKeyUsage
{
    kDigitalSignature,
    kNonRepudiation,
    kKeyEncipherment,
    kDataEncipherment,
    kKeyAgreement,
    kKeyCertSign,
    kCrlSign,
    kEncipherOnly,
    kDecipherOnly
};

/// Extension value is OpenSSL X509V3 config syntax without external sections.
/// Configuration syntax is validated by the DER encoder; prefer typed helpers.
/// Raw extension-value octets remain opaque, as with the existing DER escape hatch.
/// Identifiers are canonical dotted OIDs, preventing alias-based duplicates.
struct CsrExtension
{
    std::string oid;
    bool critical{false};
    std::string value;

    static score::Result<CsrExtension> SubjectAltNames(ICsrProcessingService& processing,
                                                       const std::vector<CsrSubjectAltName>& names,
                                                       bool critical = false);
    static score::Result<CsrExtension> KeyUsage(ICsrProcessingService& processing,
                                                const std::vector<CsrKeyUsage>& usages,
                                                bool critical = true);
    static score::Result<CsrExtension> ExtendedKeyUsage(ICsrProcessingService& processing,
                                                        const std::vector<std::string>& oids,
                                                        bool critical = false);
    static score::Result<CsrExtension> BasicConstraints(ICsrProcessingService& processing,
                                                        bool ca,
                                                        int path_length = -1,
                                                        bool critical = true);
    /// DER is the complete ASN.1 extension value, not an X509_EXTENSION wrapper.
    static score::Result<CsrExtension> CustomDer(ICsrProcessingService& processing,
                                                 std::string_view oid,
                                                 score::cpp::span<const uint8_t> der,
                                                 bool critical = false);
};

struct CsrRequest
{
    CsrSubject subject;
    std::vector<CsrExtension> extensions;
    std::string challenge_password;

    /// Daemon-side structural validation: bounded UTF-8, canonical OIDs and duplicate
    /// extension checks. Does not parse configuration or require a public key;
    /// subject placeholders remain valid until generation.
    score::Result<std::monostate> Validate(ICsrProcessingService& processing) const;
    /// Ask the daemon to encode subject/attributes in the SCORE DER envelope.
    /// Optional public SPKI is helper-only encoding context. Generation never
    /// accepts it: the daemon uses its authorized bound key instead.
    score::Result<std::vector<std::uint8_t>> ToDer(ICsrProcessingService& processing,
                                                   score::cpp::span<const std::uint8_t> public_key_info = {}) const;
};
}  // namespace score::crypto

#endif  // SCORE_CRYPTO_SRC_API_CSR_CSR_REQUEST_HPP
