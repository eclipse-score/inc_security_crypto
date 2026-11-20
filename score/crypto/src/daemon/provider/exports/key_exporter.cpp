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

#include "score/crypto/src/daemon/provider/exports/key_exporter.hpp"

#include <utility>

namespace score::crypto::daemon::provider
{
namespace
{
bool CanUseFormattedExport(common::DaemonErrorCode error) noexcept
{
    return error == common::DaemonErrorCode::kKeyNotExportable ||
           error == common::DaemonErrorCode::kKeyOperationNotPermitted ||
           error == common::DaemonErrorCode::kUnsupportedOperation;
}
}  // namespace

KeyExporter::KeyExporter(std::shared_ptr<key_management::IKeyFactory> factory) : m_factory{std::move(factory)} {}

Expected<key_management::SecureKeyBytes, common::DaemonErrorCode> KeyExporter::ExportKey(
    const key_management::IKeyHandler& key,
    score::crypto::FormatType format) const
{
    if (format != score::crypto::FormatType::kRaw)
    {
        return m_factory->ExportKey(key.GetHandle(), format);
    }

    auto raw = key.Export();
    if (raw.has_value() || !CanUseFormattedExport(raw.error()))
    {
        return raw;
    }

    auto formatted = m_factory->ExportKey(key.GetHandle(), format);
    if (!formatted.has_value() && formatted.error() == common::DaemonErrorCode::kUnsupportedOperation)
    {
        return raw;
    }
    return formatted;
}

Expected<std::size_t, common::DaemonErrorCode> KeyExporter::GetExportKeySize(const key_management::IKeyHandler& key,
                                                                             score::crypto::FormatType format) const
{
    if (format != score::crypto::FormatType::kRaw)
    {
        return m_factory->GetExportKeySize(key.GetHandle(), format);
    }

    auto raw = key.Export();
    if (raw.has_value())
    {
        return raw.value().bytes.size();
    }
    if (!CanUseFormattedExport(raw.error()))
    {
        return make_unexpected(raw.error());
    }

    auto size = m_factory->GetExportKeySize(key.GetHandle(), format);
    if (!size.has_value() && size.error() == common::DaemonErrorCode::kUnsupportedOperation)
    {
        return make_unexpected(raw.error());
    }
    return size;
}

}  // namespace score::crypto::daemon::provider
