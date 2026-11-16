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

namespace score::crypto
{
namespace
{
namespace wire = csr::wire;
using Action = wire::Action;
auto Invalid()
{
    return score::Unexpected{MakeError(CryptoErrorCode::kInvalidArgument, "Invalid CSR processing request")};
}
enum Field : uint32_t
{
    Subject = 1U,
    Issuer = 2U,
    Extensions = 4U,
    Names = 8U,
    Oids = 16U,
    Runtime = 32U,
    Requirements = 64U,
    Text = 128U,
    Bytes = 256U,
    Metadata = 512U,
    Critical = 1024U,
    Constraints = 2048U
};
constexpr uint32_t kRequest = Subject | Extensions | Text;
constexpr uint32_t kTemplate = Subject | Issuer | Extensions | Metadata;
uint32_t Fields(const wire::Document& value)
{
    uint32_t fields = 0U;
    if (!value.subject.empty())
    {
        fields |= Subject;
    }
    if (!value.issuer.empty())
    {
        fields |= Issuer;
    }
    if (!value.extensions.empty())
    {
        fields |= Extensions;
    }
    if (!value.names.empty())
    {
        fields |= Names;
    }
    if (!value.oids.empty())
    {
        fields |= Oids;
    }
    if (!value.runtime.empty())
    {
        fields |= Runtime;
    }
    if (!value.required_subject.empty() || !value.required_issuer.empty())
    {
        fields |= Requirements;
    }
    if (!value.text.empty())
    {
        fields |= Text;
    }
    if (!value.bytes.empty())
    {
        fields |= Bytes;
    }
    if (!value.id.empty() || !value.resource.empty() || !value.algorithm.empty() || !value.url.empty())
    {
        fields |= Metadata;
    }
    if (value.critical)
    {
        fields |= Critical;
    }
    if (value.ca || value.path != -1)
    {
        fields |= Constraints;
    }
    return fields;
}
bool Shape(const wire::Document& value)
{
    uint32_t allowed = 0U;
    switch (value.action)
    {
        case Action::Add:
            allowed = Subject | Names;
            break;
        case Action::FromDn:
            allowed = Text;
            break;
        case Action::San:
        case Action::SanText:
        case Action::Usage:
            allowed = Names | Critical;
            break;
        case Action::Eku:
            allowed = Oids | Critical;
            break;
        case Action::Basic:
            allowed = Constraints | Critical;
            break;
        case Action::Custom:
            allowed = Oids | Bytes | Critical;
            break;
        case Action::Validate:
        case Action::Generate:
            allowed = kRequest;
            break;
        case Action::Encode:
            allowed = kRequest | Bytes;
            break;
        case Action::Save:
            allowed = kTemplate;
            break;
        case Action::Load:
            allowed = Metadata | Bytes;
            break;
        case Action::Prepare:
            allowed = kTemplate | Runtime | Requirements;
            break;
        case Action::ValidatePrepared:
            allowed = kTemplate | Text;
            break;
        default:
            return false;
    }
    if ((Fields(value) & ~allowed) != 0U)
    {
        return false;
    }
    for (const auto& entry : value.subject)
    {
        if (entry->type != 0U)
        {
            return false;
        }
    }
    for (const auto& entry : value.issuer)
    {
        if (entry->type != 0U)
        {
            return false;
        }
    }
    for (const auto& entry : value.runtime)
    {
        if (entry->type != 0U)
        {
            return false;
        }
    }
    if (value.action == Action::Load && (!value.resource.empty() || !value.algorithm.empty() || !value.url.empty()))
    {
        return false;
    }
    return true;
}
score::Result<wire::Document> ExtensionResult(Action action, score::Result<CsrExtension> extension)
{
    if (!extension.has_value())
    {
        return score::Unexpected{extension.error()};
    }
    return wire::Request(action, {{}, {extension.value()}, {}});
}
}  // namespace
score::Result<wire::Document> NativeCsrProcessing::Process(const wire::Document& untrusted)
{
    // The test adapter uses the same bounded serializer/decoder as production.
    // Never recurse through public helper APIs, including for template subjects.
    auto encoded = wire::Encode(untrusted);
    if (!encoded.has_value())
    {
        return score::Unexpected{encoded.error()};
    }
    auto decoded = wire::Decode(encoded.value());
    if (!decoded.has_value())
    {
        return score::Unexpected{decoded.error()};
    }
    const auto& input = decoded.value();
    if (!Shape(input) || input.action == Action::Generate)
    {
        return Invalid();
    }
    wire::Document output;
    output.action = input.action;
    switch (input.action)
    {
        case Action::Add:
        {
            if (input.names.size() != 1U || input.names[0]->type != 0U)
            {
                return Invalid();
            }
            CsrSubject subject;
            for (const auto& entry : input.subject)
            {
                auto added = Add(subject, entry->oid, entry->value);
                if (!added.has_value())
                {
                    return score::Unexpected{added.error()};
                }
            }
            const auto& entry = *input.names[0];
            auto added = Add(subject, entry.oid, entry.value);
            if (!added.has_value())
            {
                return score::Unexpected{added.error()};
            }
            return wire::Request(input.action, {subject, {}, {}});
        }
        case Action::FromDn:
        {
            auto subject = FromDn(input.text);
            if (!subject.has_value())
            {
                return score::Unexpected{subject.error()};
            }
            return wire::Request(input.action, {subject.value(), {}, {}});
        }
        case Action::San:
        {
            std::vector<CsrSubjectAltName> names;
            for (const auto& entry : input.names)
            {
                if (!entry->oid.empty() || entry->type > static_cast<uint32_t>(CsrSanType::kUri))
                {
                    return Invalid();
                }
                names.push_back({static_cast<CsrSanType>(entry->type), entry->value});
            }
            return ExtensionResult(input.action, SubjectAltNames(names, input.critical));
        }
        case Action::SanText:
        {
            std::vector<CsrSubjectAltName> names;
            for (const auto& entry : input.names)
            {
                if (!entry->oid.empty() || entry->type != 0U)
                {
                    return Invalid();
                }
                const auto separator = entry->value.find(':');
                if (separator == std::string::npos)
                {
                    return Invalid();
                }
                const auto type = entry->value.substr(0U, separator);
                CsrSanType san_type{};
                if (type == "DNS")
                {
                    san_type = CsrSanType::kDns;
                }
                else if (type == "IP")
                {
                    san_type = CsrSanType::kIp;
                }
                else if (type == "email")
                {
                    san_type = CsrSanType::kEmail;
                }
                else if (type == "URI")
                {
                    san_type = CsrSanType::kUri;
                }
                else
                {
                    return Invalid();
                }
                names.push_back({san_type, entry->value.substr(separator + 1U)});
            }
            return ExtensionResult(input.action, SubjectAltNames(names, input.critical));
        }
        case Action::Usage:
        {
            std::vector<CsrKeyUsage> usages;
            for (const auto& entry : input.names)
            {
                if (!entry->oid.empty() || !entry->value.empty() ||
                    entry->type > static_cast<uint32_t>(CsrKeyUsage::kDecipherOnly))
                {
                    return Invalid();
                }
                usages.push_back(static_cast<CsrKeyUsage>(entry->type));
            }
            return ExtensionResult(input.action, KeyUsage(usages, input.critical));
        }
        case Action::Eku:
            return ExtensionResult(input.action, ExtendedKeyUsage(input.oids, input.critical));
        case Action::Basic:
            return ExtensionResult(input.action, BasicConstraints(input.ca, input.path, input.critical));
        case Action::Custom:
            if (input.oids.size() != 1U)
            {
                return Invalid();
            }
            return ExtensionResult(input.action, CustomDer(input.oids[0], input.bytes, input.critical));
        case Action::Validate:
        {
            auto valid = Validate(wire::ReadRequest(input));
            if (!valid.has_value())
            {
                return score::Unexpected{valid.error()};
            }
            return output;
        }
        case Action::Encode:
        {
            auto der = ToDer(wire::ReadRequest(input), input.bytes);
            if (!der.has_value())
            {
                return score::Unexpected{der.error()};
            }
            output.bytes = std::move(der.value());
            return output;
        }
        case Action::Save:
        {
            auto der = Save(wire::ReadTemplate(input));
            if (!der.has_value())
            {
                return score::Unexpected{der.error()};
            }
            output.bytes = std::move(der.value());
            return output;
        }
        case Action::Load:
        {
            auto value = Load(input.bytes, input.id);
            if (!value.has_value())
            {
                return score::Unexpected{value.error()};
            }
            return wire::Template(input.action, value.value());
        }
        case Action::Prepare:
        {
            CsrRuntimeValues runtime;
            for (const auto& entry : input.runtime)
            {
                if (!runtime.emplace(entry->oid, entry->value).second)
                {
                    return Invalid();
                }
            }
            auto value = Prepare(wire::ReadTemplate(input), runtime, {input.required_subject, input.required_issuer});
            if (!value.has_value())
            {
                return score::Unexpected{value.error()};
            }
            return wire::Prepared(input.action, value.value());
        }
        case Action::ValidatePrepared:
        {
            auto valid = ValidatePrepared(wire::ReadPrepared(input));
            if (!valid.has_value())
            {
                return score::Unexpected{valid.error()};
            }
            return output;
        }
        default:
            return Invalid();
    }
}
score::Result<CsrRequest> NativeCsrProcessing::GenerationRequest(const wire::Document& input)
{
    if (input.action != Action::Generate || !Shape(input))
    {
        return Invalid();
    }
    auto request = wire::ReadRequest(input);
    auto valid = Validate(request);
    if (!valid.has_value())
    {
        return score::Unexpected{valid.error()};
    }
    return request;
}
}  // namespace score::crypto
