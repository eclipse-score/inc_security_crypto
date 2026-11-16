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

#include "score/crypto/src/common/csr_wire.hpp"

#include <flatbuffers/flatbuffers.h>
#include <flatbuffers/verifier.h>

#include <algorithm>

namespace score::crypto::csr::wire
{
namespace
{
auto Invalid()
{
    return score::Unexpected{MakeError(CryptoErrorCode::kInvalidArgument, "Invalid CSR wire document")};
}
template <typename Entries>
bool EntriesBounded(const Entries& entries)
{
    if (entries.size() > 64U)
    {
        return false;
    }
    for (const auto& entry : entries)
    {
        if (!entry || entry->oid.size() > 128U || entry->value.size() > 2048U)
        {
            return false;
        }
    }
    return true;
}
bool StringsBounded(const std::vector<std::string>& values)
{
    if (values.size() > 64U)
    {
        return false;
    }
    for (const auto& value : values)
    {
        if (value.size() > 128U)
        {
            return false;
        }
    }
    return true;
}
bool Bounded(const Document& value)
{
    return value.version == 1U && value.action >= Action::Add && value.action <= Action::SanText &&
           EntriesBounded(value.subject) && EntriesBounded(value.issuer) && EntriesBounded(value.names) &&
           EntriesBounded(value.runtime) && value.extensions.size() <= 32U && EntriesBounded(value.extensions) &&
           StringsBounded(value.oids) && StringsBounded(value.required_subject) &&
           StringsBounded(value.required_issuer) && value.text.size() <= 16384U && value.bytes.size() <= 65536U &&
           value.id.size() <= 128U && value.resource.size() <= 64U && value.algorithm.size() <= 64U &&
           value.url.size() <= 2048U;
}
std::vector<std::unique_ptr<fb::EntryT>> Entries(const CsrSubject& subject)
{
    std::vector<std::unique_ptr<fb::EntryT>> result;
    for (const auto& attribute : subject.Attributes())
    {
        auto entry = std::make_unique<fb::EntryT>();
        entry->oid = attribute.oid;
        entry->value = attribute.value;
        result.push_back(std::move(entry));
    }
    return result;
}
// Bound vectors and strings BEFORE object-API allocation. The verifier checks
// offsets, nested tables, alignment, vector arithmetic and the file identifier.
bool WireBounded(const fb::Document& root)
{
    const auto string_ok = [](const flatbuffers::String* s, std::size_t n) {
        return !s || s->size() <= n;
    };
    const auto entries_ok = [&string_ok](const auto* entries, std::size_t n) {
        if (!entries)
        {
            return true;
        }
        if (entries->size() > n)
        {
            return false;
        }
        for (const auto* entry : *entries)
        {
            if (!entry || !string_ok(entry->oid(), 128U) || !string_ok(entry->value(), 2048U))
            {
                return false;
            }
        }
        return true;
    };
    const auto strings_ok = [&string_ok](const auto* entries) {
        if (!entries)
        {
            return true;
        }
        if (entries->size() > 64U)
        {
            return false;
        }
        for (const auto* entry : *entries)
        {
            if (!entry || !string_ok(entry, 128U))
            {
                return false;
            }
        }
        return true;
    };
    return root.version() == 1U && root.action() >= Action::Add && root.action() <= Action::SanText &&
           entries_ok(root.subject(), 64U) && entries_ok(root.issuer(), 64U) && entries_ok(root.names(), 64U) &&
           entries_ok(root.runtime(), 64U) && entries_ok(root.extensions(), 32U) && strings_ok(root.oids()) &&
           strings_ok(root.required_subject()) && strings_ok(root.required_issuer()) &&
           string_ok(root.text(), 16384U) && (!root.bytes() || root.bytes()->size() <= 65536U) &&
           string_ok(root.id(), 128U) && string_ok(root.resource(), 64U) && string_ok(root.algorithm(), 64U) &&
           string_ok(root.url(), 2048U);
}
}  // namespace
score::Result<Bytes> Encode(const Document& value)
{
    if (!Bounded(value))
    {
        return Invalid();
    }
    flatbuffers::FlatBufferBuilder builder;
    const auto root = fb::Document::Pack(builder, &value);
    fb::FinishDocumentBuffer(builder, root);
    if (builder.GetSize() > kMaxWireBytes)
    {
        return Invalid();
    }
    return Bytes{builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
}
score::Result<Document> Decode(score::cpp::span<const std::uint8_t> bytes)
{
    if (bytes.empty() || bytes.data() == nullptr || bytes.size() > kMaxWireBytes)
    {
        return Invalid();
    }
    // Input may refer to writable client SHM. Verify and unpack one owned
    // snapshot, never offsets that a peer can change after verification.
    const Bytes snapshot{bytes.begin(), bytes.end()};
    bytes = {snapshot.data(), snapshot.size()};
    flatbuffers::Verifier verifier(bytes.data(), bytes.size(), 16U, 1024U);
    if (!fb::VerifyDocumentBuffer(verifier))
    {
        return Invalid();
    }
    const auto* root = fb::GetDocument(bytes.data());
    if (!WireBounded(*root))
    {
        return Invalid();
    }
    std::unique_ptr<Document> value{root->UnPack()};
    if (!value || !Bounded(*value))
    {
        return Invalid();
    }
    // Require the single canonical schema encoding: rejects appended data,
    // hidden unused objects and alternate/ambiguous wire representations.
    auto encoded = Encode(*value);
    if (!encoded.has_value() || encoded->size() != bytes.size() ||
        !std::equal(encoded->begin(), encoded->end(), bytes.begin()))
    {
        return Invalid();
    }
    return std::move(*value);
}
bool ResponseShape(const Document& value) noexcept
{
    if (!value.names.empty() || !value.oids.empty() || !value.runtime.empty() || !value.required_subject.empty() ||
        !value.required_issuer.empty() || value.critical || value.ca || value.path != -1)
    {
        return false;
    }
    for (const auto& entry : value.subject)
    {
        if (!entry || entry->type != 0U)
        {
            return false;
        }
    }
    for (const auto& entry : value.issuer)
    {
        if (!entry || entry->type != 0U)
        {
            return false;
        }
    }
    const bool metadata =
        !value.id.empty() || !value.resource.empty() || !value.algorithm.empty() || !value.url.empty();
    switch (value.action)
    {
        case Action::Add:
        case Action::FromDn:
            return !value.subject.empty() && value.issuer.empty() && value.extensions.empty() && value.text.empty() &&
                   value.bytes.empty() && !metadata;
        case Action::San:
        case Action::SanText:
        case Action::Usage:
        case Action::Eku:
        case Action::Basic:
        case Action::Custom:
            return value.extensions.size() == 1U && value.subject.empty() && value.issuer.empty() &&
                   value.text.empty() && value.bytes.empty() && !metadata;
        case Action::Validate:
        case Action::ValidatePrepared:
            return value.subject.empty() && value.issuer.empty() && value.extensions.empty() && value.text.empty() &&
                   value.bytes.empty() && !metadata;
        case Action::Encode:
        case Action::Save:
            return !value.bytes.empty() && value.subject.empty() && value.issuer.empty() && value.extensions.empty() &&
                   value.text.empty() && !metadata;
        case Action::Load:
        case Action::Prepare:
            return !value.subject.empty() && !value.id.empty() && !value.resource.empty() && !value.algorithm.empty() &&
                   value.text.empty() && value.bytes.empty();
        default:
            return false;
    }
}

CsrSubject Access::Subject(const std::vector<std::unique_ptr<fb::EntryT>>& entries)
{
    CsrSubject subject;
    for (const auto& entry : entries)
    {
        subject.attributes_.push_back({entry->oid, entry->value});
    }
    return subject;
}
Document Request(Action action, const CsrRequest& request)
{
    Document value;
    value.action = action;
    value.subject = Entries(request.subject);
    value.text = request.challenge_password;
    for (const auto& extension : request.extensions)
    {
        auto entry = std::make_unique<fb::ExtensionT>();
        entry->oid = extension.oid;
        entry->value = extension.value;
        entry->critical = extension.critical;
        value.extensions.push_back(std::move(entry));
    }
    return value;
}
CsrRequest ReadRequest(const Document& value)
{
    CsrRequest result;
    result.subject = Access::Subject(value.subject);
    result.challenge_password = value.text;
    for (const auto& entry : value.extensions)
    {
        result.extensions.push_back({entry->oid, entry->critical, entry->value});
    }
    return result;
}
Document Template(Action action, const CsrTemplate& source)
{
    auto value = Request(action, {source.subject, source.extensions, {}});
    value.issuer = Entries(source.issuer);
    value.id = source.id;
    value.resource = std::string{std::string_view{source.key_resource}};
    value.algorithm = std::string{std::string_view{source.algorithm}};
    // Never silently accept truncated bounded API identifiers.
    if (source.key_resource.truncated())
    {
        value.resource.append(65U, 'x');
    }
    if (source.algorithm.truncated())
    {
        value.algorithm.append(65U, 'x');
    }
    value.url = source.submission_url;
    return value;
}
CsrTemplate ReadTemplate(const Document& value)
{
    const auto request = ReadRequest(value);
    return {value.id,
            ResourceId{value.resource},
            AlgorithmId{value.algorithm},
            request.subject,
            Access::Subject(value.issuer),
            request.extensions,
            value.url};
}
Document Prepared(Action action, const PreparedCsrTemplate& source)
{
    auto value = Template(action,
                          {source.id,
                           source.key_resource,
                           source.algorithm,
                           source.request.subject,
                           source.issuer,
                           source.request.extensions,
                           source.submission_url});
    value.text = source.request.challenge_password;
    return value;
}
PreparedCsrTemplate ReadPrepared(const Document& value)
{
    return {value.id,
            ResourceId{value.resource},
            AlgorithmId{value.algorithm},
            ReadRequest(value),
            Access::Subject(value.issuer),
            value.url};
}
}  // namespace score::crypto::csr::wire
