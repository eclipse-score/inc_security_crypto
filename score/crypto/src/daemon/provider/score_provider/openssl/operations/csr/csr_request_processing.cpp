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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/csr/csr_processing.hpp"

#include "score/crypto/src/common/csr_der.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/csr_handler_operations.hpp"

#include <array>
#include <utility>

namespace score::crypto
{
namespace
{
namespace limits = daemon::provider::handler::csr_handler_operations;
auto Invalid()
{
    return MakeError(CryptoErrorCode::kInvalidArgument, "Invalid CSR parameters");
}

bool ValidText(std::string_view text, std::size_t limit, bool empty = false)
{
    if ((!empty && text.empty()) || text.size() > limit)
    {
        return false;
    }
    // Reject NUL, malformed/overlong UTF-8, surrogate code points and > U+10FFFF.
    for (std::size_t i = 0; i < text.size();)
    {
        const auto first = static_cast<unsigned char>(text[i++]);
        if (first == 0U)
        {
            return false;
        }
        if (first < 0x80U)
        {
            continue;
        }
        unsigned count = 0U;
        uint32_t cp = 0U;
        uint32_t minimum = 0U;
        if (first >= 0xC2U && first <= 0xDFU)
        {
            count = 1U;
            cp = first & 0x1FU;
            minimum = 0x80U;
        }
        else if (first >= 0xE0U && first <= 0xEFU)
        {
            count = 2U;
            cp = first & 0x0FU;
            minimum = 0x800U;
        }
        else if (first >= 0xF0U && first <= 0xF4U)
        {
            count = 3U;
            cp = first & 0x07U;
            minimum = 0x10000U;
        }
        else
        {
            return false;
        }
        if (text.size() - i < count)
        {
            return false;
        }
        for (unsigned j = 0; j < count; ++j)
        {
            const auto next = static_cast<unsigned char>(text[i++]);
            if ((next & 0xC0U) != 0x80U)
            {
                return false;
            }
            cp = (cp << 6U) | (next & 0x3FU);
        }
        if (cp < minimum || cp > 0x10FFFFU || (cp >= 0xD800U && cp <= 0xDFFFU))
        {
            return false;
        }
    }
    return true;
}

bool ValidOid(std::string_view oid)
{
    if (oid.size() < 3U || oid.size() > limits::kMaxOidBytes || oid[1] != '.' || oid[0] < '0' || oid[0] > '2')
    {
        return false;
    }
    std::size_t start = 2U;
    unsigned arc = 1U;
    while (start < oid.size())
    {
        auto end = oid.find('.', start);
        if (end == std::string_view::npos)
        {
            end = oid.size();
        }
        const auto part = oid.substr(start, end - start);
        if (part.empty() || (part.size() > 1U && part[0] == '0'))
        {
            return false;
        }
        for (char c : part)
        {
            if (c < '0' || c > '9')
            {
                return false;
            }
        }
        if (arc == 1U && oid[0] != '2' && (part.size() > 2U || (part.size() == 2U && part > "39")))
        {
            return false;
        }
        if (end == oid.size())
        {
            return true;
        }
        start = end + 1U;
        ++arc;
    }
    return false;
}

constexpr std::array<std::string_view, 25> kOids = {"2.5.4.3",
                                                    "2.5.4.4",
                                                    "2.5.4.5",
                                                    "2.5.4.6",
                                                    "2.5.4.7",
                                                    "2.5.4.8",
                                                    "2.5.4.9",
                                                    "2.5.4.10",
                                                    "2.5.4.11",
                                                    "2.5.4.12",
                                                    "2.5.4.13",
                                                    "2.5.4.17",
                                                    "2.5.4.18",
                                                    "2.5.4.19",
                                                    "2.5.4.20",
                                                    "2.5.4.41",
                                                    "2.5.4.42",
                                                    "2.5.4.43",
                                                    "2.5.4.44",
                                                    "2.5.4.46",
                                                    "2.5.4.65",
                                                    "0.9.2342.19200300.100.1.25",
                                                    "0.9.2342.19200300.100.1.1",
                                                    "1.2.840.113549.1.9.1",
                                                    "2.5.4.97"};
constexpr std::array<std::string_view, 25> kDnNames = {"CN",
                                                       "SN",
                                                       "serialNumber",
                                                       "C",
                                                       "L",
                                                       "ST",
                                                       "street",
                                                       "O",
                                                       "OU",
                                                       "title",
                                                       "description",
                                                       "postalCode",
                                                       "postOfficeBox",
                                                       "physicalDeliveryOfficeName",
                                                       "telephoneNumber",
                                                       "name",
                                                       "GN",
                                                       "initials",
                                                       "generationQualifier",
                                                       "dnQualifier",
                                                       "pseudonym",
                                                       "DC",
                                                       "UID",
                                                       "emailAddress",
                                                       "organizationIdentifier"};

std::string_view DnOid(std::string_view name)
{
    for (std::size_t i = 0; i < kDnNames.size(); ++i)
    {
        if (name == kDnNames[i])
        {
            return kOids[i];
        }
    }
    return name;
}
}  // namespace

score::Result<std::monostate> NativeCsrProcessing::Add(CsrSubject& subject, CsrOid oid, std::string_view value)
{
    return Add(subject, GetCsrOid(oid), value);
}

score::Result<std::monostate> NativeCsrProcessing::Add(CsrSubject& subject,
                                                       std::string_view oid,
                                                       std::string_view value)
{
    if (!ValidOid(oid) || !ValidText(value, limits::kMaxValueBytes) ||
        subject.attributes_.size() >= limits::kMaxSubjectEntries)
    {
        return score::Unexpected{Invalid()};
    }
    subject.attributes_.push_back({std::string{oid}, std::string{value}});
    return std::monostate{};
}

score::Result<CsrSubject> NativeCsrProcessing::FromDn(std::string_view dn)
{
    if (dn.empty() || dn.size() > limits::kMaxInputDerBytes)
    {
        return score::Unexpected{Invalid()};
    }
    CsrSubject subject;
    std::string name;
    std::string value;
    bool in_value = false;
    for (std::size_t i = 0; i <= dn.size(); ++i)
    {
        const char c = i == dn.size() ? ',' : dn[i];
        if (c == '\\')
        {
            if (!in_value || ++i >= dn.size() || (dn[i] != ',' && dn[i] != '=' && dn[i] != '\\'))
            {
                return score::Unexpected{Invalid()};
            }
            value += dn[i];
        }
        else if (c == ',')
        {
            if (!in_value)
            {
                return score::Unexpected{Invalid()};
            }
            auto added = Add(subject, DnOid(name), value);
            if (!added.has_value())
            {
                return score::Unexpected{added.error()};
            }
            name.clear();
            value.clear();
            in_value = false;
        }
        else if (c == '=' && !in_value)
        {
            in_value = true;
        }
        else if (c == '+' || c == '"' || c == ';' || (c == '=' && in_value))
        {
            return score::Unexpected{Invalid()};
        }
        else
        {
            (in_value ? value : name) += c;
        }
    }
    return subject;
}

score::Result<CsrExtension> NativeCsrProcessing::SubjectAltNames(const std::vector<CsrSubjectAltName>& names,
                                                                 bool critical)
{
    if (names.empty() || names.size() > limits::kMaxSubjectEntries)
    {
        return score::Unexpected{Invalid()};
    }
    CsrExtension extension{"2.5.29.17", critical, {}};
    constexpr std::array<std::string_view, 4> prefixes = {"DNS:", "IP:", "email:", "URI:"};
    for (const auto& name : names)
    {
        const auto index = static_cast<std::size_t>(name.type);
        if (index >= prefixes.size() || !ValidText(name.value, limits::kMaxValueBytes))
        {
            return score::Unexpected{Invalid()};
        }
        // Config separators/sections and whitespace cannot be injected through a typed value.
        for (unsigned char c : name.value)
        {
            if (c <= 0x20U || c >= 0x7FU || c == ',' || c == '\\' || c == '"' ||
                (c == '@' && name.type != CsrSanType::kEmail && name.type != CsrSanType::kUri))
            {
                return score::Unexpected{Invalid()};
            }
        }
        if (!extension.value.empty())
        {
            extension.value += ',';
        }
        extension.value += prefixes[index];
        extension.value += name.value;
        if (extension.value.size() > limits::kMaxValueBytes)
        {
            return score::Unexpected{Invalid()};
        }
    }
    return extension;
}

score::Result<CsrExtension> NativeCsrProcessing::KeyUsage(const std::vector<CsrKeyUsage>& usages, bool critical)
{
    constexpr std::array<std::string_view, 9> names = {"digitalSignature",
                                                       "nonRepudiation",
                                                       "keyEncipherment",
                                                       "dataEncipherment",
                                                       "keyAgreement",
                                                       "keyCertSign",
                                                       "cRLSign",
                                                       "encipherOnly",
                                                       "decipherOnly"};
    if (usages.empty() || usages.size() > names.size())
    {
        return score::Unexpected{Invalid()};
    }
    std::array<bool, 9> seen{};
    CsrExtension extension{"2.5.29.15", critical, {}};
    for (auto usage : usages)
    {
        const auto index = static_cast<std::size_t>(usage);
        if (index >= names.size() || seen[index])
        {
            return score::Unexpected{Invalid()};
        }
        seen[index] = true;
        if (!extension.value.empty())
        {
            extension.value += ',';
        }
        extension.value += names[index];
    }
    if ((seen[7] || seen[8]) && !seen[4])
    {
        return score::Unexpected{Invalid()};
    }
    return extension;
}

score::Result<CsrExtension> NativeCsrProcessing::ExtendedKeyUsage(const std::vector<std::string>& oids, bool critical)
{
    if (oids.empty() || oids.size() > limits::kMaxSubjectEntries)
    {
        return score::Unexpected{Invalid()};
    }
    CsrExtension extension{"2.5.29.37", critical, {}};
    for (const auto& oid : oids)
    {
        if (!ValidOid(oid))
        {
            return score::Unexpected{Invalid()};
        }
        if (!extension.value.empty())
        {
            extension.value += ',';
        }
        extension.value += oid;
    }
    if (extension.value.size() > limits::kMaxValueBytes)
    {
        return score::Unexpected{Invalid()};
    }
    return extension;
}

score::Result<CsrExtension> NativeCsrProcessing::BasicConstraints(bool ca, int path_length, bool critical)
{
    if (path_length < -1 || (!ca && path_length != -1))
    {
        return score::Unexpected{Invalid()};
    }
    CsrExtension extension{"2.5.29.19", critical, ca ? "CA:TRUE" : "CA:FALSE"};
    if (path_length >= 0)
    {
        extension.value += ",pathlen:" + std::to_string(path_length);
    }
    return extension;
}

score::Result<CsrExtension> NativeCsrProcessing::CustomDer(std::string_view oid,
                                                           score::cpp::span<const uint8_t> der,
                                                           bool critical)
{
    if (!ValidOid(oid) || der.empty() || der.size() > (limits::kMaxValueBytes - 4U) / 3U)
    {
        return score::Unexpected{Invalid()};
    }
    constexpr char hex[] = "0123456789ABCDEF";
    CsrExtension extension{std::string{oid}, critical, "DER:"};
    for (const auto byte : der)
    {
        if (extension.value.size() > 4U)
        {
            extension.value += ':';
        }
        extension.value += hex[byte >> 4U];
        extension.value += hex[byte & 0xFU];
    }
    return extension;
}

score::Result<std::monostate> NativeCsrProcessing::Validate(const CsrRequest& request)
{
    const auto& subject = request.subject;
    const auto& extensions = request.extensions;
    const auto& challenge_password = request.challenge_password;
    if (subject.Attributes().empty() || subject.Attributes().size() > limits::kMaxSubjectEntries ||
        extensions.size() > limits::kMaxExtensions ||
        !ValidText(challenge_password, limits::kMaxChallengePasswordBytes, true))
    {
        return score::Unexpected{Invalid()};
    }
    // Bound aggregate application input without parsing extension configuration.
    // The codec separately checks the final DER size, including ASN.1 overhead.
    std::size_t total = challenge_password.size();
    const auto account = [&total](std::size_t size) {
        if (size > limits::kMaxInputDerBytes - total)
        {
            return false;
        }
        total += size;
        return true;
    };
    for (const auto& attribute : subject.Attributes())
    {
        if (!ValidOid(attribute.oid) || !ValidText(attribute.value, limits::kMaxValueBytes) ||
            !account(attribute.oid.size()) || !account(attribute.value.size()))
        {
            return score::Unexpected{Invalid()};
        }
    }
    for (std::size_t i = 0; i < extensions.size(); ++i)
    {
        const auto& extension = extensions[i];
        if (!ValidOid(extension.oid) || !ValidText(extension.value, limits::kMaxValueBytes) ||
            !account(extension.oid.size()) || !account(extension.value.size()) || !account(1U))
        {
            return score::Unexpected{Invalid()};
        }
        for (std::size_t j = 0; j < i; ++j)
        {
            if (extensions[j].oid == extension.oid)
            {
                return score::Unexpected{Invalid()};
            }
        }
    }
    return std::monostate{};
}

score::Result<std::vector<std::uint8_t>> NativeCsrProcessing::ToDer(
    const CsrRequest& request,
    score::cpp::span<const std::uint8_t> public_key_info)
{
    const auto& subject = request.subject;
    const auto& extensions = request.extensions;
    const auto& challenge_password = request.challenge_password;
    const auto valid = Validate(request);
    if (!valid.has_value())
    {
        return score::Unexpected{valid.error()};
    }
    std::vector<csr::der::SubjectAttribute> attributes;
    attributes.reserve(subject.Attributes().size());
    for (const auto& attribute : subject.Attributes())
    {
        attributes.push_back({attribute.oid, attribute.value});
    }
    std::vector<csr::der::ExtensionSpec> requested_extensions;
    requested_extensions.reserve(extensions.size());
    for (const auto& extension : extensions)
    {
        requested_extensions.push_back({extension.oid, extension.critical, extension.value});
    }
    return csr::der::EncodeParameters(attributes, requested_extensions, challenge_password, public_key_info);
}
}  // namespace score::crypto
