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

#ifndef SCORE_CRYPTO_SRC_COMMON_CSR_DER_HPP
#define SCORE_CRYPTO_SRC_COMMON_CSR_DER_HPP

#include "score/result/result.h"
#include "score/span.hpp"

#include <openssl/x509.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace score::crypto::csr::der
{
using Bytes = std::vector<std::uint8_t>;
struct SubjectAttribute
{
    std::string oid;
    std::string value;
};
struct ExtensionSpec
{
    std::string oid;
    bool critical{false};
    std::string value;  // Daemon-side X509V3 configuration; raw octets remain opaque.
};
struct TemplateRecord
{
    std::string id;
    std::string key_resource;
    std::string algorithm;
    std::vector<SubjectAttribute> subject;
    std::vector<SubjectAttribute> issuer;
    std::vector<ExtensionSpec> extensions;
    std::string submission_url;
};

/// Daemon codec / legacy envelope: SEQUENCE { subject Name, attributes SET OF Attribute }.
/// Contains standard X.509/PKCS#10 structures, but is not a complete CSR.
/// Not the production generation wire format. Public-key information is optional
/// codec context only and is not encoded in this envelope.
score::Result<Bytes> EncodeParameters(const std::vector<SubjectAttribute>& subject,
                                      const std::vector<ExtensionSpec>& extensions,
                                      std::string_view challenge_password,
                                      score::cpp::span<const std::uint8_t> public_key_info = {});
/// Decode, validate and populate only subject/attributes; never replace a bound key.
score::Result<std::monostate> PopulateRequest(X509_REQ* request, score::cpp::span<const std::uint8_t> encoded);
/// Versioned DER template schema retains placeholders and application metadata.
score::Result<Bytes> EncodeTemplate(const TemplateRecord& value);
score::Result<TemplateRecord> DecodeTemplate(score::cpp::span<const std::uint8_t> encoded);
/// Bounded, definite-length canonical DER validation before OpenSSL decoding.
bool IsCanonicalDer(score::cpp::span<const std::uint8_t> encoded) noexcept;
}  // namespace score::crypto::csr::der
#endif  // SCORE_CRYPTO_SRC_COMMON_CSR_DER_HPP
