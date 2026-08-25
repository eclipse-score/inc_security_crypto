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
#include "score/crypto/src/daemon/common/storage/file_io.hpp"

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

score::crypto::Expected<std::monostate, Error> SaveDescriptor(const CertSlotConfig& slot, const Descriptor& d)
{
    return DeploymentWriter::Write(slot.deployment_path, slot.deployment_format, d);
}
}  // namespace

std::string CrlHandler::FormatName(score::crypto::FormatType format)
{
    return format == score::crypto::FormatType::kDer ? "der" : "pem";
}

bool CrlHandler::HasCrl(const CertSlotConfig& slot) const
{
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return false;
    const auto path = descriptor->Get("crl", "crl_path");
    return !path.empty() && file_io::FileExists(path);
}

score::crypto::Expected<std::vector<std::uint8_t>, Error> CrlHandler::LoadCrl(const CertSlotConfig& slot) const
{
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    const auto path = descriptor->Get("crl", "crl_path");
    if (path.empty())
        return score::crypto::make_unexpected(Error::kResourceNotAllocated);
    return file_io::ReadFile(path, kMaxCrlSize);
}

score::crypto::Expected<std::monostate, Error> CrlHandler::StoreCrl(const CertSlotConfig& slot,
                                                                    score::crypto::span<const std::uint8_t> data,
                                                                    score::crypto::FormatType format)
{
    if (data.empty())
        return score::crypto::make_unexpected(Error::kInvalidArgument);
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
            const auto dot = cert_path.rfind('.');
            path = (dot != std::string::npos ? cert_path.substr(0U, dot) : cert_path) + ".crl";
        }
        else
        {
            path = slot.deployment_path + ".crl";
        }
    }
    auto result = file_io::WriteFile(path, data);
    if (!result)
        return result;
    descriptor->Set("crl", "crl_path", path);
    descriptor->Set("crl", "crl_format", FormatName(format));
    return SaveDescriptor(slot, *descriptor);
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
    return SaveDescriptor(slot, *descriptor);
}

score::crypto::Expected<std::int64_t, Error> CrlHandler::GetCrlNextUpdate(const CertSlotConfig& slot) const
{
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    const auto value = descriptor->Get("crl", "crl_next_update");
    if (value.empty())
        return score::crypto::make_unexpected(Error::kResourceNotAllocated);
    try
    {
        return std::stoll(value);
    }
    catch (...)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
}

}  // namespace score::crypto::daemon::cert_management
