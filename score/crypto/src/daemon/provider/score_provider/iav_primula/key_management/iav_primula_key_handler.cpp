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
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/api/common/types.hpp"
#include <algorithm>

namespace score::crypto::daemon::provider::score_provider::iav_primula
{
IavPrimulaKeyHandler::IavPrimulaKeyHandler(iav_primula_key_handle* key,
                                           std::vector<std::uint8_t> pub,
                                           const key_management::ProviderKeyHandle& handle) noexcept
    : m_native_key{key}, m_public_key{std::move(pub)}, m_handle{handle}
{
}

IavPrimulaKeyHandler::~IavPrimulaKeyHandler()
{
    static_cast<void>(Release());
}

const key_management::ProviderKeyHandle& IavPrimulaKeyHandler::GetHandle() const noexcept
{
    return m_handle;
}

common::ProviderId IavPrimulaKeyHandler::GetProviderId() const noexcept
{
    return m_handle.provider_id;
}

Expected<std::monostate, common::DaemonErrorCode> IavPrimulaKeyHandler::Release()
{
    if (!m_released)
    {
        // Release the native key handle and wipe cached key material exactly once.
        if (m_native_key != nullptr)
        {
            iav_key_destroy(m_native_key);
        }
        m_native_key = nullptr;
        std::fill(m_public_key.begin(), m_public_key.end(), 0U);
        m_public_key.clear();
        m_released = true;
    }
    return std::monostate{};
}

Expected<key_management::SecureKeyBytes, common::DaemonErrorCode> IavPrimulaKeyHandler::Export() const
{
    // Export only the cached public key after checking permissions and release state.
    if (!score::crypto::HasPermission(m_handle.permissions, score::crypto::KeyOperationPermission::kExport) ||
        m_released)
    {
        return make_unexpected(common::DaemonErrorCode::kKeyOperationNotPermitted);
    }

    key_management::SecureKeyBytes out(m_public_key.size());
    std::copy(m_public_key.begin(), m_public_key.end(), out.bytes.begin());
    return out;
}

const std::uint8_t* IavPrimulaKeyHandler::GetPublicKey(std::size_t& size) const noexcept
{
    size = m_released ? 0U : m_public_key.size();
    return size == 0U ? nullptr : m_public_key.data();
}
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula
