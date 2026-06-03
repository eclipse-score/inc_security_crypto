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

#ifndef CRYPTO_DAEMON_COMMON_ALGORITHM_INFO_HPP
#define CRYPTO_DAEMON_COMMON_ALGORITHM_INFO_HPP

#include <cstddef>
#include <optional>
#include <string_view>

namespace score::crypto::daemon::common
{

// ---------------------------------------------------------------------------
// Hash algorithm properties (provider-independent)
// ---------------------------------------------------------------------------

struct HashAlgorithmInfo
{
    std::string_view name;
    std::size_t digest_size;  ///< Output size in bytes
};

inline constexpr HashAlgorithmInfo kHashAlgorithms[] = {
    {"SHA256", 32U},
    {"SHA384", 48U},
    {"SHA512", 64U},
    {"SHA224", 28U},
    {"SHA1", 20U},
    {"MD5", 16U},
};

/// @brief Look up digest size by algorithm name.
/// @return digest size in bytes, or std::nullopt if unknown.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupDigestSize(std::string_view algorithm) noexcept
{
    for (const auto& entry : kHashAlgorithms)
    {
        if (entry.name == algorithm)
        {
            return entry.digest_size;
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// MAC algorithm properties (provider-independent)
// ---------------------------------------------------------------------------

struct MacAlgorithmInfo
{
    std::string_view name;
    std::size_t mac_size;  ///< Output tag size in bytes
};

inline constexpr MacAlgorithmInfo kMacAlgorithms[] = {
    {"HMAC-SHA256", 32U},
    {"HMAC-SHA384", 48U},
    {"HMAC-SHA512", 64U},
};

/// @brief Look up MAC output size by algorithm name.
/// @return MAC size in bytes, or std::nullopt if unknown.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupMacSize(std::string_view algorithm) noexcept
{
    for (const auto& entry : kMacAlgorithms)
    {
        if (entry.name == algorithm)
        {
            return entry.mac_size;
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Key algorithm properties (provider-independent)
// ---------------------------------------------------------------------------

struct KeyAlgorithmInfo
{
    std::string_view name;
    std::size_t key_size;  ///< Default key size in bytes
};

inline constexpr KeyAlgorithmInfo kKeyAlgorithms[] = {
    {"HMAC-SHA256", 32U},
    {"HMAC-SHA384", 48U},
    {"HMAC-SHA512", 64U},
    {"AES-128-CBC", 16U},
    {"AES-192-CBC", 24U},
    {"AES-256-CBC", 32U},
    {"AES-128-GCM", 16U},
    {"AES-192-GCM", 24U},
    {"AES-256-GCM", 32U},
    {"AES-128-CMAC", 16U},
    {"AES-256-CMAC", 32U},
};

/// @brief Look up default key size by algorithm name.
/// @return key size in bytes, or std::nullopt if unknown.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupKeySize(std::string_view algorithm) noexcept
{
    for (const auto& entry : kKeyAlgorithms)
    {
        if (entry.name == algorithm)
        {
            return entry.key_size;
        }
    }
    return std::nullopt;
}

}  // namespace score::crypto::daemon::common

#endif  // CRYPTO_DAEMON_COMMON_ALGORITHM_INFO_HPP
