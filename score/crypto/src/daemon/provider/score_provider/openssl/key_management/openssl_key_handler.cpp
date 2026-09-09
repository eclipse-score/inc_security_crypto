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

#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <openssl/crypto.h>  // OPENSSL_cleanse
#include <openssl/evp.h>     // EVP_PKEY_free
#include <algorithm>
#include <utility>

namespace score::crypto::daemon::provider::openssl
{

void EvpPkeyDeleter::operator()(evp_pkey_st* pkey) const noexcept
{
    // EVP_PKEY is a typedef for evp_pkey_st, so the forward-declared pointer is
    // already the right type. EVP_PKEY_free scrubs the private component
    // internally and tolerates nullptr.
    EVP_PKEY_free(pkey);
}

OpenSslKeyHandler::OpenSslKeyHandler(std::vector<std::uint8_t> key_bytes,
                                     const key_management::ProviderKeyHandle& handle) noexcept
    : m_key_bytes{std::move(key_bytes)}, m_pkey{nullptr}, m_handle{handle}, m_released{false}
{
}

OpenSslKeyHandler::OpenSslKeyHandler(EvpPkeyPtr pkey, const key_management::ProviderKeyHandle& handle) noexcept
    : m_key_bytes{}, m_pkey{std::move(pkey)}, m_handle{handle}, m_released{false}
{
}

OpenSslKeyHandler::~OpenSslKeyHandler()
{
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
    if (m_released)
    {
        return std::monostate{};
    }

    if (!m_key_bytes.empty())
    {
        OPENSSL_cleanse(m_key_bytes.data(), m_key_bytes.size());
        m_key_bytes.clear();
    }

    // Releasing early is an optimisation, not a requirement: if this is never
    // called, ~OpenSslKeyHandler destroys m_pkey and EvpPkeyDeleter runs anyway.
    m_pkey.reset();

    m_released = true;
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

evp_pkey_st* OpenSslKeyHandler::GetPkey() const noexcept
{
    // Release() resets the pointer, so the released case needs no separate check.
    return m_pkey.get();
}

::score::crypto::Expected<key_management::SecureKeyBytes, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyHandler::Export() const
{
    if (!score::crypto::HasPermission(m_handle.permissions, score::crypto::KeyOperationPermission::kExport))
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kKeyOperationNotPermitted);
    }
    if (m_released)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    // Asymmetric keys have no raw-byte representation. Exporting them requires a
    // choice of encoding (PKCS#8 / SubjectPublicKeyInfo, DER or PEM) that this
    // interface cannot express, so it is handled by the key-export operation
    // rather than here.
    if (m_pkey)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kKeyNotExportable);
    }

    if (m_key_bytes.empty())
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    key_management::SecureKeyBytes out;
    out.bytes.assign(m_key_bytes.begin(), m_key_bytes.end());
    return out;
}

}  // namespace score::crypto::daemon::provider::openssl
