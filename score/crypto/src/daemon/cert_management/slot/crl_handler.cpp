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

#include "score/crypto/src/daemon/cert_management/slot/crl_handler.hpp"

#include "score/crypto/src/daemon/cert_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_writer.hpp"
#include "score/crypto/src/daemon/common/hex.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/filesystem/path.h"

#include <charconv>
#include <algorithm>
#include <array>
#include <utility>

namespace score::crypto::daemon::cert_management
{
namespace
{
using Error = common::DaemonErrorCode;
namespace file_io = common::storage;
using Descriptor = common::storage::DeploymentDescriptor;

score::crypto::Expected<Descriptor, Error> LoadDescriptor(const CertSlotConfig& slot)
{
    return DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
}

score::crypto::Expected<std::monostate, Error> SaveDescriptor(const CertSlotConfig& slot,
                                                              const Descriptor& d,
                                                              const file_io::FileWriter& writer)
{
    return DeploymentWriter::Write(slot.deployment_path, slot.deployment_format, d, writer);
}

score::crypto::FormatType ParseFormat(const std::string& name)
{
    return name == "pem" ? score::crypto::FormatType::kPem : score::crypto::FormatType::kDer;
}

/// Metadata cached in the [crl] section; empty when any field is absent or malformed.
std::optional<score::crypto::CrlMetadata> ParseMetadata(const Descriptor& descriptor)
{
    const auto fingerprint = common::DecodeHex(descriptor.Get("crl", "crl_fingerprint"));
    const auto issuer_fingerprint = common::DecodeHex(descriptor.Get("crl", "crl_issuer_fingerprint"));
    if (!fingerprint.has_value() || fingerprint->size() != score::crypto::kSha256FingerprintSize ||
        !issuer_fingerprint.has_value() || issuer_fingerprint->size() != score::crypto::kSha256FingerprintSize)
        return std::nullopt;

    score::crypto::CrlMetadata metadata;
    std::copy(fingerprint->begin(), fingerprint->end(), metadata.fingerprint.begin());
    std::copy(issuer_fingerprint->begin(), issuer_fingerprint->end(), metadata.issuer_fingerprint.begin());

    const auto parse_integer = [&descriptor](std::string_view key, auto& result) {
        const auto value = descriptor.Get("crl", std::string{key});
        if (value.empty())
            return false;
        const auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), result);
        return ec == std::errc{} && end == value.data() + value.size();
    };
    if (!parse_integer("crl_this_update", metadata.this_update) ||
        !parse_integer("crl_next_update", metadata.next_update) || !parse_integer("crl_number", metadata.crl_number))
        return std::nullopt;
    return metadata;
}

/// True when the descriptor names a CRL file that exists.
score::crypto::Expected<bool, Error> CrlFilePresent(const Descriptor& descriptor)
{
    const auto path = descriptor.Get("crl", "crl_path");
    if (path.empty() || descriptor.Get("crl", "crl_format").empty())
        return false;
    return file_io::FileExists(path);
}
}  // namespace

CrlHandler::CrlHandler(file_io::FileWriter writer) : m_write_file{std::move(writer)} {}

std::string CrlHandler::FormatName(score::crypto::FormatType format)
{
    return format == score::crypto::FormatType::kDer ? "der" : "pem";
}

score::crypto::Expected<bool, Error> CrlHandler::HasCrl(const CertSlotConfig& slot) const
{
    const auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    return CrlFilePresent(*descriptor);
}

score::crypto::Expected<std::monostate, Error> CrlHandler::StoreCrl(const CertSlotConfig& slot, const CrlData& crl)
{
    if (crl.bytes.empty() || crl.bytes.size() > kMaxCrlSize)
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    const score::crypto::span<const std::uint8_t> data{crl.bytes.data(), crl.bytes.size()};
    const auto format = crl.format;
    const auto& metadata = crl.metadata;
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    auto path = descriptor->Get("crl", "crl_path");
    if (path.empty())
    {
        // Prefer a sibling of the cert file; fall back to alongside the descriptor.
        const auto cert_path = descriptor->Get("certificate", "cert_path");
        if (!cert_path.empty())
        {
            score::filesystem::Path crl_path{cert_path};
            crl_path.ReplaceExtension(score::filesystem::Path{".crl"});
            path = crl_path.Native();
        }
        else
        {
            path = slot.deployment_path + ".crl";
        }
    }
    auto result = m_write_file(path, data);
    if (!result)
        return result;
    descriptor->RemoveSection("crl");
    descriptor->Set("crl", "crl_path", path);
    descriptor->Set("crl", "crl_format", FormatName(format));
    if (metadata.has_value())
    {
        descriptor->Set(
            "crl", "crl_fingerprint", common::EncodeHex({metadata->fingerprint.data(), metadata->fingerprint.size()}));
        descriptor->Set("crl",
                        "crl_issuer_fingerprint",
                        common::EncodeHex({metadata->issuer_fingerprint.data(), metadata->issuer_fingerprint.size()}));
        descriptor->Set("crl", "crl_this_update", std::to_string(metadata->this_update));
        descriptor->Set("crl", "crl_next_update", std::to_string(metadata->next_update));
        descriptor->Set("crl", "crl_number", std::to_string(metadata->crl_number));
    }
    return SaveDescriptor(slot, *descriptor, m_write_file);
}

score::crypto::Expected<std::monostate, Error> CrlHandler::ClearCrl(const CertSlotConfig& slot)
{
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    const auto path = descriptor->Get("crl", "crl_path");
    if (!path.empty())
    {
        auto remove_result = file_io::RemoveFile(path);
        if (!remove_result)
            return score::crypto::make_unexpected(remove_result.error());
    }
    descriptor->RemoveSection("crl");
    if (!path.empty())
        descriptor->Set("crl", "crl_path", path);
    return SaveDescriptor(slot, *descriptor, m_write_file);
}

score::crypto::Expected<std::optional<score::crypto::CrlMetadata>, Error> CrlHandler::GetCrlMetadata(
    const CertSlotConfig& slot) const
{
    const auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    const auto present = CrlFilePresent(*descriptor);
    if (!present.has_value())
        return score::crypto::make_unexpected(present.error());
    if (!present.value())
        return std::optional<score::crypto::CrlMetadata>{};
    return ParseMetadata(*descriptor);
}

score::crypto::Expected<std::optional<CrlData>, Error> CrlHandler::LoadCrlData(const CertSlotConfig& slot) const
{
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());

    const auto present = CrlFilePresent(*descriptor);
    if (!present.has_value())
        return score::crypto::make_unexpected(present.error());
    if (!present.value())
        return std::optional<CrlData>{};

    auto bytes = file_io::ReadFile(descriptor->Get("crl", "crl_path"), kMaxCrlSize);
    if (!bytes.has_value())
        return score::crypto::make_unexpected(bytes.error());
    return std::optional<CrlData>{CrlData{
        std::move(bytes.value()), ParseFormat(descriptor->Get("crl", "crl_format")), ParseMetadata(*descriptor)}};
}

}  // namespace score::crypto::daemon::cert_management
