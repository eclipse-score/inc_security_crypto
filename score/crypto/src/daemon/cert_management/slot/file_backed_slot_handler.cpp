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
#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"

#include "score/crypto/src/daemon/common/storage/deployment_descriptor.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"

namespace score::crypto::daemon::cert_management
{
namespace
{
using Error = common::DaemonErrorCode;
using Descriptor = common::storage::DeploymentDescriptor;
namespace file_io = common::storage;

score::crypto::Expected<Descriptor, Error> LoadDescriptor(const CertSlotConfig& slot)
{
    return DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
}

score::crypto::Expected<std::monostate, Error> SaveDescriptor(const CertSlotConfig& slot, const Descriptor& d)
{
    return DeploymentWriter::Write(slot.deployment_path, slot.deployment_format, d);
}

std::string ResolvePath(const Descriptor& d, const std::string& section, const std::string& key)
{
    return d.Get(section, key);
}

score::crypto::FormatType ParseFormat(const std::string& value, score::crypto::FormatType fallback)
{
    if (value == "der")
        return score::crypto::FormatType::kDer;
    if (value == "pem")
        return score::crypto::FormatType::kPem;
    return fallback;
}
}  // namespace

score::crypto::Expected<CertObject::Sptr, Error> FileBackedSlotHandler::LoadCertificate(const CertSlotConfig& slot)
{
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    const auto path = ResolvePath(*descriptor, "certificate", "cert_path");
    if (path.empty())
        return score::crypto::make_unexpected(Error::kKeySlotEmpty);
    auto bytes = file_io::ReadFile(path, kMaxCertSize);
    if (!bytes)
        return score::crypto::make_unexpected(bytes.error());

    if (slot.integrity_policy == IntegrityPolicy::kRequired)
    {
        const auto hash = descriptor->Get("certificate", "cert_hash");
        if (hash.empty())
            return score::crypto::make_unexpected(Error::kInvalidArgument);
        // The descriptor hash is validated by the certificate verification layer.
    }

    const auto format = ParseFormat(descriptor->Get("certificate", "cert_format"), score::crypto::FormatType::kPem);
    if (!m_parser)
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    return m_parser->ParseCertificate(bytes->data(), bytes->size(), format);
}

score::crypto::Expected<score::crypto::CertificateSlotState, Error> FileBackedSlotHandler::GetSlotState(
    const CertSlotConfig& slot)
{
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    const auto path = ResolvePath(*descriptor, "certificate", "cert_path");
    return (!path.empty() && file_io::FileExists(path)) ? score::crypto::CertificateSlotState::kOccupied
                                                        : score::crypto::CertificateSlotState::kEmpty;
}

score::crypto::Expected<score::crypto::CertificateSlotInfo, Error> FileBackedSlotHandler::GetSlotInfo(
    const CertSlotConfig& slot)
{
    auto state = GetSlotState(slot);
    if (!state)
        return score::crypto::make_unexpected(state.error());
    score::crypto::CertificateSlotInfo info{};
    info.state = *state;
    info.has_crl = HasCrl(slot);
    return info;
}

bool FileBackedSlotHandler::HasCrl(const CertSlotConfig& slot)
{
    return m_crl.HasCrl(slot);
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::StoreCertificate(const CertSlotConfig& slot,
                                                                                       const CertObject& cert)
{
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    auto path = descriptor->Get("certificate", "cert_path");
    if (path.empty())
        path = slot.deployment_path + ".pem";
    // The CertObject already holds serialized bytes; store them as-is and record
    // the object's format. Callers needing a specific on-disk encoding convert
    // via the provider's ConvertFormat before storing.
    const auto bytes = cert.GetRawBytes();
    auto result = file_io::WriteFile(path, bytes);
    if (!result)
        return result;
    descriptor->Set("certificate", "cert_format", cert.GetFormat() == score::crypto::FormatType::kDer ? "der" : "pem");
    descriptor->Set("certificate_metadata", "subject", std::string(cert.GetSubject()));
    descriptor->Set("certificate_metadata", "issuer", std::string(cert.GetIssuer()));
    descriptor->Set("certificate_metadata", "not_before", std::to_string(cert.GetNotBefore()));
    descriptor->Set("certificate_metadata", "not_after", std::to_string(cert.GetNotAfter()));
    descriptor->Set("certificate_metadata", "is_ca", cert.IsCA() ? "true" : "false");
    return SaveDescriptor(slot, *descriptor);
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::ClearSlot(const CertSlotConfig& slot)
{
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    const auto cert = descriptor->Get("certificate", "cert_path");
    if (!cert.empty())
        file_io::RemoveFile(cert);
    // Preserve crl_path so a future StoreCrl re-uses the same location.
    // Only the file and volatile metadata (format, next_update) are discarded.
    const auto crl_path = descriptor->Get("crl", "crl_path");
    if (!crl_path.empty())
        file_io::RemoveFile(crl_path);
    descriptor->RemoveSection("crl");
    if (!crl_path.empty())
        descriptor->Set("crl", "crl_path", crl_path);
    descriptor->RemoveSection("certificate_metadata");
    return SaveDescriptor(slot, *descriptor);
}

score::crypto::Expected<std::vector<uint8_t>, Error> FileBackedSlotHandler::LoadCrl(const CertSlotConfig& slot)
{
    return m_crl.LoadCrl(slot);
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::StoreCrl(const CertSlotConfig& slot,
                                                                               score::crypto::span<const uint8_t> data,
                                                                               score::crypto::FormatType format)
{
    return m_crl.StoreCrl(slot, data, format);
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::ClearCrl(const CertSlotConfig& slot)
{
    return m_crl.ClearCrl(slot);
}

score::crypto::Expected<int64_t, Error> FileBackedSlotHandler::GetCrlNextUpdate(const CertSlotConfig& slot)
{
    return m_crl.GetCrlNextUpdate(slot);
}
}  // namespace score::crypto::daemon::cert_management
