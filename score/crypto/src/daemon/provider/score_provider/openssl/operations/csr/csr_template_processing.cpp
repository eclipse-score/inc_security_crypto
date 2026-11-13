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

#include <utility>

namespace score::crypto
{
namespace
{
constexpr std::size_t kMaxDocumentBytes = 65536U;
constexpr std::size_t kMaxTemplateIdBytes = 128U;
constexpr std::size_t kMaxSubmissionUrlBytes = 2048U;
constexpr std::size_t kMaxAttributeValueBytes = 2048U;
constexpr std::size_t kMaxAttributeEntries = 64U;
constexpr std::size_t kMaxRuntimeEntries = 64U;
constexpr std::size_t kMaxExtensions = 32U;
auto Invalid()
{
    return score::Unexpected{MakeError(CryptoErrorCode::kInvalidArgument, "Invalid CSR template")};
}

template <typename Template>
bool BoundedCommonMetadata(const Template& value)
{
    const std::string_view key = value.key_resource;
    const std::string_view algorithm = value.algorithm;
    return !value.id.empty() && value.id.size() <= kMaxTemplateIdBytes && value.id.find('\0') == std::string::npos &&
           !key.empty() && !value.key_resource.truncated() && key.find('\0') == std::string_view::npos &&
           !algorithm.empty() && !value.algorithm.truncated() && algorithm.find('\0') == std::string_view::npos &&
           value.submission_url.size() <= kMaxSubmissionUrlBytes &&
           value.submission_url.find('\0') == std::string::npos;
}

bool ContainsExtensionPlaceholder(const std::vector<CsrExtension>& extensions)
{
    for (const auto& extension : extensions)
    {
        if (extension.value.find("${") != std::string::npos)
        {
            return true;
        }
    }
    return false;
}

bool BoundedSubject(const CsrSubject& subject, bool allow_empty)
{
    const auto& entries = subject.Attributes();
    if (entries.size() > kMaxAttributeEntries || (!allow_empty && entries.empty()))
    {
        return false;
    }
    // CsrSubject::Add already validates canonical OIDs and UTF-8. Do not
    // substitute placeholders or apply X.509 Name encoding to stored values.
    for (const auto& entry : entries)
    {
        if (entry.value.empty() || entry.value.size() > kMaxAttributeValueBytes ||
            entry.value.find('\0') != std::string::npos)
        {
            return false;
        }
        CsrSubject checked;
        if (!NativeCsrProcessing::Add(checked, entry.oid, entry.value).has_value())
        {
            return false;
        }
    }
    return true;
}

score::Result<CsrSubject> ReadSubject(const std::vector<csr::der::SubjectAttribute>& entries, bool allow_empty)
{
    if (entries.size() > kMaxAttributeEntries || (!allow_empty && entries.empty()))
    {
        return Invalid();
    }
    CsrSubject subject;
    for (const auto& entry : entries)
    {
        if (entry.value.size() > kMaxAttributeValueBytes)
        {
            return Invalid();
        }
        auto added = NativeCsrProcessing::Add(subject, entry.oid, entry.value);
        if (!added.has_value())
        {
            return score::Unexpected{added.error()};
        }
    }
    return subject;
}

std::vector<csr::der::SubjectAttribute> WriteSubject(const CsrSubject& subject)
{
    std::vector<csr::der::SubjectAttribute> entries;
    entries.reserve(subject.Attributes().size());
    for (const auto& attribute : subject.Attributes())
    {
        entries.push_back({attribute.oid, attribute.value});
    }
    return entries;
}

score::Result<CsrSubject> Substitute(const CsrSubject& source, const CsrRuntimeValues& runtime)
{
    CsrSubject output;
    for (const auto& attribute : source.Attributes())
    {
        std::string text;
        std::size_t cursor = 0;
        while (cursor < attribute.value.size())
        {
            const auto open = attribute.value.find("${", cursor);
            if (open == std::string::npos)
            {
                text.append(attribute.value, cursor, std::string::npos);
                break;
            }
            text.append(attribute.value, cursor, open - cursor);
            const auto close = attribute.value.find('}', open + 2U);
            if (close == std::string::npos)
            {
                return Invalid();
            }
            const auto found = runtime.find(attribute.value.substr(open + 2U, close - open - 2U));
            if (found == runtime.end() || found->second.empty() || found->second.size() > kMaxAttributeValueBytes ||
                found->second.find("${") != std::string::npos)
            {
                return Invalid();
            }
            text += found->second;
            if (text.size() > kMaxAttributeValueBytes)
            {
                return Invalid();
            }
            cursor = close + 1U;
        }
        auto added = NativeCsrProcessing::Add(output, attribute.oid, text);
        if (!added.has_value())
        {
            return score::Unexpected{added.error()};
        }
    }
    return output;
}

bool ContainsRequired(const CsrSubject& subject, const std::vector<std::string>& required)
{
    if (required.size() > kMaxAttributeEntries)
    {
        return false;
    }
    for (const auto& oid : required)
    {
        bool found = false;
        for (const auto& attribute : subject.Attributes())
        {
            if (attribute.oid == oid && !attribute.value.empty())
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            return false;
        }
    }
    return true;
}
}  // namespace

score::Result<CsrTemplate> NativeCsrProcessing::Load(score::cpp::span<const uint8_t> document_, std::string_view id)
{
    if (document_.empty() || document_.size() > kMaxDocumentBytes)
    {
        return Invalid();
    }
    auto decoded = csr::der::DecodeTemplate(document_);
    if (!decoded.has_value())
    {
        return score::Unexpected{decoded.error()};
    }
    const auto& record = decoded.value();
    if (record.id != id || record.extensions.size() > kMaxExtensions)
    {
        return Invalid();
    }
    auto subject = ReadSubject(record.subject, false);
    auto issuer = ReadSubject(record.issuer, true);
    if (!subject.has_value() || !issuer.has_value())
    {
        return Invalid();
    }
    CsrTemplate output;
    output.id = record.id;
    output.key_resource = record.key_resource;
    output.algorithm = record.algorithm;
    output.submission_url = record.submission_url;
    output.subject = std::move(subject.value());
    output.issuer = std::move(issuer.value());
    output.extensions.reserve(record.extensions.size());
    for (const auto& extension : record.extensions)
    {
        output.extensions.push_back({extension.oid, extension.critical, extension.value});
    }
    if (!BoundedCommonMetadata(output))
    {
        return Invalid();
    }
    CsrRequest request{output.subject, output.extensions, {}};
    if (!Validate(request).has_value())
    {
        return Invalid();
    }
    return output;
}

score::Result<std::vector<std::uint8_t>> NativeCsrProcessing::Save(const CsrTemplate& value)
{
    if (!BoundedCommonMetadata(value) || !BoundedSubject(value.subject, false) || !BoundedSubject(value.issuer, true))
    {
        return Invalid();
    }
    CsrRequest request{value.subject, value.extensions, {}};
    if (!Validate(request).has_value())
    {
        return Invalid();
    }
    csr::der::TemplateRecord record;
    record.id = value.id;
    record.key_resource = std::string{std::string_view{value.key_resource}};
    record.algorithm = std::string{std::string_view{value.algorithm}};
    record.subject = WriteSubject(value.subject);
    record.issuer = WriteSubject(value.issuer);
    record.submission_url = value.submission_url;
    record.extensions.reserve(value.extensions.size());
    for (const auto& extension : value.extensions)
    {
        record.extensions.push_back({extension.oid, extension.critical, extension.value});
    }
    auto encoded = csr::der::EncodeTemplate(record);
    if (!encoded.has_value())
    {
        return score::Unexpected{encoded.error()};
    }
    if (encoded->empty() || encoded->size() > kMaxDocumentBytes)
    {
        return Invalid();
    }
    return std::move(encoded.value());
}

score::Result<PreparedCsrTemplate> NativeCsrProcessing::Prepare(const CsrTemplate& value,
                                                                const CsrRuntimeValues& runtime,
                                                                const CsrAttributeRequirements& requirements)
{
    if (!BoundedCommonMetadata(value) || runtime.size() > kMaxRuntimeEntries)
    {
        return Invalid();
    }
    auto subject = Substitute(value.subject, runtime);
    auto issuer = Substitute(value.issuer, runtime);
    if (!subject.has_value() || !issuer.has_value())
    {
        return Invalid();
    }
    if (!ContainsRequired(subject.value(), requirements.subject_oids) ||
        !ContainsRequired(issuer.value(), requirements.issuer_oids))
    {
        return Invalid();
    }
    PreparedCsrTemplate output{value.id,
                               value.key_resource,
                               value.algorithm,
                               {std::move(subject.value()), value.extensions, {}},
                               std::move(issuer.value()),
                               value.submission_url};
    if (!Validate(output.request).has_value())
    {
        return Invalid();
    }
    if (ContainsExtensionPlaceholder(output.request.extensions))
    {
        return Invalid();
    }
    return output;
}

score::Result<std::monostate> NativeCsrProcessing::ValidatePrepared(const PreparedCsrTemplate& value)
{
    // Daemon validation precedes the client's signing-key resolution, including
    // caller-built prepared values.
    if (!BoundedCommonMetadata(value) || !Validate(value.request).has_value() ||
        ContainsExtensionPlaceholder(value.request.extensions))
    {
        return Invalid();
    }
    return std::monostate{};
}
}  // namespace score::crypto
