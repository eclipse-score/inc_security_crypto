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

#include "score/crypto/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include "score/mw/log/logging.h"
#include <openssl/crypto.h>  // OPENSSL_cleanse
#include <algorithm>

namespace score::crypto::daemon::provider::openssl
{

OpenSslKeyHandler::OpenSslKeyHandler(std::vector<std::uint8_t> key_bytes,
                                     const key_management::ProviderKeyHandle& handle) noexcept
    : m_key_bytes{std::move(key_bytes)}, m_handle{handle}, m_released{false}
{
}

OpenSslKeyHandler::~OpenSslKeyHandler()
{
    score::mw::log::LogDebug() << "[OPENSSL_KEY_HANDLER] Release Key";
    static_cast<void>(Release());
}

const key_management::ProviderKeyHandle& OpenSslKeyHandler::GetHandle() const noexcept
{
    return m_handle;
}

common::ProviderId OpenSslKeyHandler::GetProviderId() const noexcept
{
    return m_handle.provider_id;
}

::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> OpenSslKeyHandler::Release()
{
    if (!m_released && !m_key_bytes.empty())
    {
        OPENSSL_cleanse(m_key_bytes.data(), m_key_bytes.size());
        m_key_bytes.clear();
        m_released = true;
    }
    return std::monostate{};
}

const std::uint8_t* OpenSslKeyHandler::GetRawKeyBytes(std::size_t& out_size) const noexcept
{
    if (m_released || m_key_bytes.empty())
    {
        out_size = 0U;
        return nullptr;
    }
    out_size = m_key_bytes.size();
    return m_key_bytes.data();
}

::score::crypto::Expected<key_management::SecureKeyBytes, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyHandler::Export() const
{
    if (!score::mw::crypto::HasPermission(m_handle.permissions, score::mw::crypto::KeyOperationPermission::kExport))
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kKeyOperationNotPermitted);
    }
    if (m_released || m_key_bytes.empty())
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    key_management::SecureKeyBytes out(m_key_bytes.size());
    std::copy(m_key_bytes.begin(), m_key_bytes.end(), out.bytes.begin());
    return out;
}

}  // namespace score::crypto::daemon::provider::openssl
