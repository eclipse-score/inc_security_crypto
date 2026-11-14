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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_DETAIL_OPENSSL_KEY_HANDLE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_DETAIL_OPENSSL_KEY_HANDLE_HPP

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace score::crypto::daemon::provider::openssl::detail
{

/// Builds the handle of a symmetric key whose material is @p key_bytes.
///
/// key_size is key_bytes.size(), and opaque_id the address of the buffer that
/// the OpenSslKeyHandler built from this handle takes over.
[[nodiscard]] inline key_management::ProviderKeyHandle MakeKeyHandle(
    common::ProviderId provider_id,
    const ::score::crypto::AlgorithmDescriptor& algorithm,
    score::crypto::KeyOperationPermission permissions,
    const std::vector<std::uint8_t>& key_bytes) noexcept
{
    key_management::ProviderKeyHandle handle{};
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(key_bytes.data()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    handle.provider_id = provider_id;
    handle.permissions = permissions;
    handle.is_asymmetric = false;
    handle.algorithm = algorithm;
    handle.key_size = key_bytes.size();
    return handle;
}

/// Builds the handle of a key pair or public key whose material is @p pkey.
///
/// opaque_id is the address of @p pkey. The caller still sets public_key_permissions.
[[nodiscard]] inline key_management::ProviderKeyHandle MakeKeyHandle(
    common::ProviderId provider_id,
    const ::score::crypto::AlgorithmDescriptor& algorithm,
    score::crypto::KeyOperationPermission permissions,
    std::size_t key_size,
    const evp_pkey_st* pkey) noexcept
{
    key_management::ProviderKeyHandle handle{};
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(pkey));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    handle.provider_id = provider_id;
    handle.permissions = permissions;
    handle.is_asymmetric = true;
    handle.algorithm = algorithm;
    handle.key_size = key_size;
    return handle;
}

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_DETAIL_OPENSSL_KEY_HANDLE_HPP
