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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_HANDLE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_HANDLE_HPP

#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

#include <cstddef>
#include <cstdint>

namespace score::crypto::daemon::provider::openssl::detail
{

/// Builds the key handle metadata shared by every key the OpenSSL key factory produces.
///
/// opaque_id is the address of @p material, the buffer or EVP_PKEY the returned
/// handler will own. The caller still sets public_key_permissions for a key pair.
[[nodiscard]] inline key_management::ProviderKeyHandle MakeKeyHandle(common::ProviderId provider_id,
                                                                     const common::AlgorithmId& algorithm,
                                                                     score::crypto::KeyOperationPermission permissions,
                                                                     std::size_t key_size,
                                                                     bool is_asymmetric,
                                                                     const void* material) noexcept
{
    key_management::ProviderKeyHandle handle{};
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(material));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    handle.provider_id = provider_id;
    handle.permissions = permissions;
    handle.is_asymmetric = is_asymmetric;
    handle.algorithm = algorithm;
    handle.key_size = key_size;
    return handle;
}

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_OPENSSL_KEY_HANDLE_HPP
