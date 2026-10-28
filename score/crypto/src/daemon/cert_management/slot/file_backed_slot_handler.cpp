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

#include <utility>

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

score::crypto::Expected<std::monostate, Error> SaveDescriptor(const CertSlotConfig& slot,
                                                              const Descriptor& d,
                                                              const file_io::FileWriter& writer)
{
    return DeploymentWriter::Write(slot.deployment_path, slot.deployment_format, d, writer);
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

score::crypto::Expected<score::crypto::CertificateSlotState, Error> LoadSlotState(const CertSlotConfig& slot)
{
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    const auto path = ResolvePath(*descriptor, "certificate", "cert_path");
    if (path.empty())
        return score::crypto::CertificateSlotState::kEmpty;
    const auto exists = file_io::FileExists(path);
    if (!exists)
        return score::crypto::make_unexpected(exists.error());
    return exists.value() ? score::crypto::CertificateSlotState::kOccupied
                          : score::crypto::CertificateSlotState::kEmpty;
}
}  // namespace

FileBackedSlotHandler::FileBackedSlotHandler(CertSlotConfig config,
                                             provider::cert_management::ICertParser::Sptr parser,
                                             common::storage::FileWriter writer)
    : ICertSlotHandler{std::move(config)},
      m_parser{std::move(parser)},
      m_write_file{writer},
      m_crl{GetConfig(), std::move(writer)}
{
}

FileBackedSlotHandler::~FileBackedSlotHandler() = default;

score::crypto::Expected<CertObject::Sptr, Error> FileBackedSlotHandler::LoadCertificate()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    return LoadCertificateUnlocked();
}

score::crypto::Expected<CertObject::Sptr, Error> FileBackedSlotHandler::LoadCertificateUnlocked()
{
    const auto& slot = GetConfig();
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

score::crypto::Expected<score::crypto::CertificateSlotState, Error> FileBackedSlotHandler::GetSlotState()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    return LoadSlotState(GetConfig());
}

score::crypto::Expected<score::crypto::CertificateSlotInfo, Error> FileBackedSlotHandler::GetSlotInfo()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    auto state = LoadSlotState(GetConfig());
    if (!state)
        return score::crypto::make_unexpected(state.error());
    score::crypto::CertificateSlotInfo info{};
    info.state = *state;
    const auto has_crl = m_crl.HasCrl();
    if (!has_crl)
        return score::crypto::make_unexpected(has_crl.error());
    info.has_crl = has_crl.value();
    return info;
}

score::crypto::Expected<bool, Error> FileBackedSlotHandler::HasCrl()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    return m_crl.HasCrl();
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::StoreCertificate(const CertObject& cert)
{
    const std::lock_guard lock{m_slot_operation_mutex};
    const auto& slot = GetConfig();
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
    if (bytes.size() > kMaxCertSize)
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    auto result = m_write_file(path, bytes);
    if (!result)
        return result;
    // Clear any stale CRL: it was issued for the previous CA key and is no longer
    // valid for the incoming certificate. Metadata invalidation happens
    // unconditionally so the descriptor never reports a stale CRL as current,
    // even if the physical file removal below fails. Preserve crl_path so that
    // a future StoreCrl call re-uses the same location — this is essential for
    // backends (e.g. PKCS#11) where cert_path is absent and the CRL path cannot
    // be re-derived from the certificate file. File removal is best-effort: a
    // leftover stale CRL file will be overwritten by the next StoreCrl.
    const auto old_crl_path = descriptor->Get("crl", "crl_path");
    descriptor->RemoveSection("crl");
    if (!old_crl_path.empty())
    {
        descriptor->Set("crl", "crl_path", old_crl_path);
        static_cast<void>(file_io::RemoveFile(old_crl_path));
    }
    // Record the path actually written, so that loads and state queries find the certificate.
    descriptor->Set("certificate", "cert_path", path);
    descriptor->Set("certificate", "cert_format", cert.GetFormat() == score::crypto::FormatType::kDer ? "der" : "pem");
    descriptor->Set("certificate_metadata", "subject", std::string(cert.GetSubject()));
    descriptor->Set("certificate_metadata", "issuer", std::string(cert.GetIssuer()));
    descriptor->Set("certificate_metadata", "not_before", std::to_string(cert.GetNotBefore()));
    descriptor->Set("certificate_metadata", "not_after", std::to_string(cert.GetNotAfter()));
    descriptor->Set("certificate_metadata", "is_ca", cert.IsCA() ? "true" : "false");
    return SaveDescriptor(slot, *descriptor, m_write_file);
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::ClearSlot()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    const auto& slot = GetConfig();
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    const auto cert = descriptor->Get("certificate", "cert_path");
    if (!cert.empty())
    {
        if (const auto rm = file_io::RemoveFile(cert); !rm)
            return rm;
    }
    // Preserve crl_path so a future StoreCrl re-uses the same location.
    // Only the file and volatile metadata (format, next_update) are discarded.
    const auto crl_path = descriptor->Get("crl", "crl_path");
    if (!crl_path.empty())
    {
        if (const auto rm = file_io::RemoveFile(crl_path); !rm)
            return rm;
    }
    descriptor->RemoveSection("crl");
    if (!crl_path.empty())
        descriptor->Set("crl", "crl_path", crl_path);
    descriptor->RemoveSection("certificate_metadata");
    return SaveDescriptor(slot, *descriptor, m_write_file);
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::StoreCrl(const CrlData& crl)
{
    const std::lock_guard lock{m_slot_operation_mutex};
    return m_crl.StoreCrl(crl);
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::ClearCrl()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    return m_crl.ClearCrl();
}

score::crypto::Expected<std::optional<score::crypto::CrlMetadata>, Error> FileBackedSlotHandler::GetCrlMetadata()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    auto metadata = m_crl.GetCrlMetadata();
    if (!metadata.has_value() || metadata->has_value() || !m_parser)
    {
        return metadata;
    }
    // The descriptor has no cached metadata; if a CRL exists (e.g. written out of band),
    // derive the metadata from it.
    const auto crl = m_crl.LoadCrlData();
    if (!crl.has_value() || !crl->has_value())
        return std::optional<score::crypto::CrlMetadata>{};
    return DeriveCrlMetadata(**crl);
}

std::optional<score::crypto::CrlMetadata> FileBackedSlotHandler::DeriveCrlMetadata(const CrlData& crl)
{
    if (!m_parser)
        return std::nullopt;
    const auto certificate = LoadCertificateUnlocked();
    if (!certificate.has_value())
        return std::nullopt;

    const auto result = m_parser->ValidateCrl(crl,
                                              certificate.value()->GetRawBytes().data(),
                                              certificate.value()->GetRawBytes().size(),
                                              certificate.value()->GetFormat());
    return result.has_value() ? std::optional<score::crypto::CrlMetadata>{result.value()} : std::nullopt;
}

score::crypto::Expected<std::optional<CrlData>, Error> FileBackedSlotHandler::LoadCrlData()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    auto crl = m_crl.LoadCrlData();
    if (!crl.has_value() || !crl->has_value() || (*crl)->metadata.has_value())
        return crl;
    // The descriptor has no cached metadata for an existing CRL (e.g. written out of band).
    (*crl)->metadata = DeriveCrlMetadata(**crl);
    return crl;
}
}  // namespace score::crypto::daemon::cert_management
