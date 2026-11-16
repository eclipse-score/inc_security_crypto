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

#include "score/crypto/src/api/csr/csr_processing_client.hpp"

#include <array>

namespace score::crypto
{
namespace
{
namespace wire = csr::wire;
score::Result<CsrExtension> Extension(ICsrProcessingService& service, const wire::Document& input)
{
    auto result = service.Process(input);
    if (!result.has_value())
    {
        return score::Unexpected{result.error()};
    }
    if (result->extensions.size() != 1U)
    {
        return score::Unexpected{MakeError(CryptoErrorCode::kOperationFailed, "Invalid CSR extension response")};
    }
    const auto& value = *result->extensions[0];
    return CsrExtension{value.oid, value.critical, value.value};
}
}  // namespace
std::string_view GetCsrOid(CsrOid oid) noexcept
{
    constexpr std::array<std::string_view, 25> oids = {"2.5.4.3",
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
    const auto index = static_cast<std::size_t>(oid);
    return index < oids.size() ? oids[index] : std::string_view{};
}
score::Result<std::monostate> CsrSubject::Add(ICsrProcessingService& service, CsrOid oid, std::string_view value)
{
    return Add(service, GetCsrOid(oid), value);
}
score::Result<std::monostate> CsrSubject::Add(ICsrProcessingService& service,
                                              std::string_view oid,
                                              std::string_view value)
{
    auto input = wire::Request(wire::Action::Add, {*this, {}, {}});
    auto entry = std::make_unique<wire::fb::EntryT>();
    entry->oid = oid;
    entry->value = value;
    input.names.push_back(std::move(entry));
    auto result = service.Process(input);
    if (!result.has_value())
    {
        return score::Unexpected{result.error()};
    }
    *this = wire::Access::Subject(result->subject);
    return std::monostate{};
}
score::Result<CsrSubject> CsrSubject::FromDn(ICsrProcessingService& service, std::string_view dn)
{
    wire::Document input;
    input.action = wire::Action::FromDn;
    input.text = dn;
    auto result = service.Process(input);
    if (!result.has_value())
    {
        return score::Unexpected{result.error()};
    }
    return wire::Access::Subject(result->subject);
}
score::Result<CsrExtension> CsrExtension::SubjectAltNames(ICsrProcessingService& service,
                                                          const std::vector<CsrSubjectAltName>& names,
                                                          bool critical)
{
    wire::Document input;
    input.action = wire::Action::San;
    input.critical = critical;
    for (const auto& name : names)
    {
        auto entry = std::make_unique<wire::fb::EntryT>();
        entry->type = static_cast<uint32_t>(name.type);
        entry->value = name.value;
        input.names.push_back(std::move(entry));
    }
    return Extension(service, input);
}
score::Result<CsrExtension> CsrExtension::KeyUsage(ICsrProcessingService& service,
                                                   const std::vector<CsrKeyUsage>& usages,
                                                   bool critical)
{
    wire::Document input;
    input.action = wire::Action::Usage;
    input.critical = critical;
    for (const auto usage : usages)
    {
        auto entry = std::make_unique<wire::fb::EntryT>();
        entry->type = static_cast<uint32_t>(usage);
        input.names.push_back(std::move(entry));
    }
    return Extension(service, input);
}
score::Result<CsrExtension> CsrExtension::ExtendedKeyUsage(ICsrProcessingService& service,
                                                           const std::vector<std::string>& oids,
                                                           bool critical)
{
    wire::Document input;
    input.action = wire::Action::Eku;
    input.oids = oids;
    input.critical = critical;
    return Extension(service, input);
}
score::Result<CsrExtension> CsrExtension::BasicConstraints(ICsrProcessingService& service,
                                                           bool ca,
                                                           int path_length,
                                                           bool critical)
{
    wire::Document input;
    input.action = wire::Action::Basic;
    input.ca = ca;
    input.path = path_length;
    input.critical = critical;
    return Extension(service, input);
}
score::Result<CsrExtension> CsrExtension::CustomDer(ICsrProcessingService& service,
                                                    std::string_view oid,
                                                    score::cpp::span<const uint8_t> der,
                                                    bool critical)
{
    wire::Document input;
    input.action = wire::Action::Custom;
    input.oids.emplace_back(oid);
    input.bytes.assign(der.begin(), der.end());
    input.critical = critical;
    return Extension(service, input);
}
score::Result<std::monostate> CsrRequest::Validate(ICsrProcessingService& service) const
{
    auto result = service.Process(wire::Request(wire::Action::Validate, *this));
    if (!result.has_value())
    {
        return score::Unexpected{result.error()};
    }
    return std::monostate{};
}
score::Result<std::vector<uint8_t>> CsrRequest::ToDer(ICsrProcessingService& service,
                                                      score::cpp::span<const uint8_t> public_key_info) const
{
    auto input = wire::Request(wire::Action::Encode, *this);
    input.bytes.assign(public_key_info.begin(), public_key_info.end());
    auto result = service.Process(input);
    if (!result.has_value())
    {
        return score::Unexpected{result.error()};
    }
    return std::move(result->bytes);
}
}  // namespace score::crypto
