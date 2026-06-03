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

#include "score/crypto/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"

#include "score/crypto/daemon/common/algorithm_info.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <openssl/crypto.h>  // OPENSSL_cleanse
#include <openssl/rand.h>    // RAND_bytes

#include <algorithm>
#include <cstdint>
#include <vector>

namespace score::crypto::daemon::provider::openssl
{

OpenSslKeyFactory::OpenSslKeyFactory(common::ProviderId provider_id) : m_provider_id(provider_id) {};

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GenerateKey(const key_management::KeyGenerationRequest& request)
{
    const std::size_t key_size = DetermineKeySize(request.algorithm);
    if (key_size == 0U)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    std::vector<std::uint8_t> key_bytes(key_size);

    if (RAND_bytes(key_bytes.data(), static_cast<int>(key_size)) != 1)
    {
        OPENSSL_cleanse(key_bytes.data(), key_size);
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }

    key_management::ProviderKeyHandle handle{};
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(key_bytes.data()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    handle.provider_id = m_provider_id;
    handle.permissions = request.permissions;
    handle.is_asymmetric = false;
    handle.algorithm = request.algorithm;
    handle.key_size = key_size;

    return std::make_shared<OpenSslKeyHandler>(std::move(key_bytes), handle);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ImportKey(const key_management::KeyImportRequest& request)
{
    if ((request.key_data == nullptr) || (request.key_data_size == 0U))
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    std::vector<std::uint8_t> key_bytes(request.key_data, request.key_data + request.key_data_size);

    key_management::ProviderKeyHandle handle{};
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(key_bytes.data()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    handle.provider_id = m_provider_id;
    handle.permissions = request.permissions;
    handle.is_asymmetric = false;
    handle.algorithm = request.algorithm;
    handle.key_size = request.key_data_size;

    return std::make_shared<OpenSslKeyHandler>(std::move(key_bytes), handle);
}

// static
std::size_t OpenSslKeyFactory::DetermineKeySize(const common::AlgorithmId& algorithm) noexcept
{
    return ::score::crypto::daemon::common::LookupKeySize(std::string_view{algorithm.data(), algorithm.size()})
        .value_or(0U);
}

}  // namespace score::crypto::daemon::provider::openssl
