/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 * See the NOTICE file(s) distributed with this work for additional information.
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0:
 * https://www.apache.org/licenses/LICENSE-2.0
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_shared_secret_handler.hpp"

#include <utility>

namespace score::crypto::daemon::provider::score_provider::pqc_provider
{

// Take ownership of the ephemeral KEM output and describe its derive-only use.
PqcProviderSharedSecretHandler::PqcProviderSharedSecretHandler(key_management::SecureKeyBytes secret,
                                                             common::ProviderId provider_id)
    : m_secret{std::move(secret)}
{
    m_handle.provider_id = provider_id;
    m_handle.algorithm.name = "KEM-SHARED-SECRET";
    m_handle.algorithm.category = AlgorithmCategory::kKey;
    m_handle.algorithm.key_type = KeyType::kSecret;
    m_handle.algorithm.key_bits = static_cast<std::uint16_t>(m_secret.bytes.size() * 8U);
    m_handle.key_size = m_secret.bytes.size();
    m_handle.material_kind = key_management::KeyMaterialKind::kSharedSecret;
    m_handle.permissions = score::crypto::KeyOperationPermission::kDerive;
    // Internal provider reference only. The client receives a distinct DataNodeId.
    m_handle.opaque_id = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(m_secret.bytes.data()));
}

// Release the secret on destruction.
PqcProviderSharedSecretHandler::~PqcProviderSharedSecretHandler()
{
    static_cast<void>(Release());
}

// Return the provider metadata associated with this shared secret.
const key_management::ProviderKeyHandle& PqcProviderSharedSecretHandler::GetHandle() const noexcept
{
    return m_handle;
}

// Return the provider that owns this shared secret.
common::ProviderId PqcProviderSharedSecretHandler::GetProviderId() const noexcept
{
    return m_handle.provider_id;
}

// Wipe the in-memory secret and invalidate the metadata used to refer to it.
Expected<std::monostate, common::DaemonErrorCode> PqcProviderSharedSecretHandler::Release()
{
    common::SecureZeroizeAndClear(m_secret.bytes);
    m_handle.opaque_id = 0U;
    m_handle.key_size = 0U;
    m_handle.permissions = score::crypto::KeyOperationPermission::kNone;
    return std::monostate{};
}

// KEM shared secrets are never exportable.
Expected<key_management::SecureKeyBytes, common::DaemonErrorCode> PqcProviderSharedSecretHandler::Export() const
{
    return make_unexpected(common::DaemonErrorCode::kKeyOperationNotPermitted);
}

}  // namespace score::crypto::daemon::provider::score_provider::pqc_provider
