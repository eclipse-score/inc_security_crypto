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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_ALGORITHM_INFO_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_ALGORITHM_INFO_HPP

#include <cstddef>
#include <optional>
#include <string_view>

namespace score::crypto::daemon::common
{

// ---------------------------------------------------------------------------
// Hash algorithm properties (provider-independent)
// ---------------------------------------------------------------------------

enum class HashAlgorithmStatus
{
    kRecommended,
    kLegacy,
};

enum class HashAlgorithm
{
    kSha256,
    kSha384,
    kSha512,
    kSha224,
    kSha1,
    kMd5,
};

struct HashAlgorithmInfo
{
    HashAlgorithm algorithm;
    std::string_view name;
    std::size_t digest_size;     ///< Output size in bytes
    HashAlgorithmStatus status;  ///< Recommendation for new integrations
};

inline constexpr HashAlgorithmInfo kHashAlgorithms[] = {
    {HashAlgorithm::kSha256, "SHA256", 32U, HashAlgorithmStatus::kRecommended},
    {HashAlgorithm::kSha384, "SHA384", 48U, HashAlgorithmStatus::kRecommended},
    {HashAlgorithm::kSha512, "SHA512", 64U, HashAlgorithmStatus::kRecommended},
    {HashAlgorithm::kSha224, "SHA224", 28U, HashAlgorithmStatus::kLegacy},
    {HashAlgorithm::kSha1, "SHA1", 20U, HashAlgorithmStatus::kLegacy},
    {HashAlgorithm::kMd5, "MD5", 16U, HashAlgorithmStatus::kLegacy},
};

/// @brief Look up provider-independent hash algorithm metadata.
/// @return algorithm metadata, or std::nullopt if unknown.
[[nodiscard]] inline constexpr std::optional<HashAlgorithmInfo> LookupHashAlgorithmInfo(
    std::string_view algorithm) noexcept
{
    for (const auto& entry : kHashAlgorithms)
    {
        if (entry.name == algorithm)
        {
            return entry;
        }
    }
    return std::nullopt;
}

/// @brief Look up digest size by algorithm name.
/// @return digest size in bytes, or std::nullopt if unknown.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupDigestSize(std::string_view algorithm) noexcept
{
    const auto info = LookupHashAlgorithmInfo(algorithm);
    return info.has_value() ? std::optional<std::size_t>{info->digest_size} : std::nullopt;
}

/// @brief Return whether an algorithm is recommended for new integrations.
///
/// Legacy algorithms remain available for compatibility.
[[nodiscard]] inline constexpr bool IsRecommendedHashAlgorithm(std::string_view algorithm) noexcept
{
    const auto info = LookupHashAlgorithmInfo(algorithm);
    return info.has_value() && (info->status == HashAlgorithmStatus::kRecommended);
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

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_ALGORITHM_INFO_HPP
