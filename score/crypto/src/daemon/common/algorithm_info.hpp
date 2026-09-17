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

#include <array>
#include <cstddef>
#include <cstdint>
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

inline constexpr std::array<HashAlgorithmInfo, 6UL> kHashAlgorithms{{
    {"SHA256", 32U},
    {"SHA384", 48U},
    {"SHA512", 64U},
    {"SHA224", 28U},
    {"SHA1", 20U},
    {"MD5", 16U},
}};

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

inline constexpr std::array<MacAlgorithmInfo, 3UL> kMacAlgorithms = {{
    {"HMAC-SHA256", 32U},
    {"HMAC-SHA384", 48U},
    {"HMAC-SHA512", 64U},
}};

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

// ---------------------------------------------------------------------------
// Post-quantum algorithm properties
// ---------------------------------------------------------------------------

/// @brief Identifies the operation family implemented by a PQC algorithm.
enum class PqcAlgorithmKind : std::uint8_t
{
    kSignature,
    kKem,
};

/// @brief Fixed-size properties for standardized PQC parameter sets.
///
/// The sizes describe the byte representation used at the provider boundary.
/// The provider remains responsible for validating the actual encoding.
struct PqcAlgorithmInfo
{
    std::string_view name;                     ///< Standardized algorithm identifier.
    PqcAlgorithmKind kind;                     ///< Signature or KEM algorithm.
    std::size_t public_key_size;               ///< Public key size in bytes.
    std::size_t private_key_size;              ///< Private key size in bytes.
    std::size_t signature_or_ciphertext_size;  ///< Signature or ciphertext size in bytes; zero when not applicable.
    std::size_t shared_secret_size;            ///< Shared-secret size in bytes; zero for signature algorithms.
};

inline constexpr std::array<PqcAlgorithmInfo, 6UL> kPqcAlgorithms = {{
    // ML-DSA: public key, private key, and signature sizes from FIPS 204.
    {"ML-DSA-44", PqcAlgorithmKind::kSignature, 1312U, 2560U, 2420U, 0U},
    {"ML-DSA-65", PqcAlgorithmKind::kSignature, 1952U, 4032U, 3309U, 0U},
    {"ML-DSA-87", PqcAlgorithmKind::kSignature, 2592U, 4896U, 4627U, 0U},

    // ML-KEM: public key, private key, ciphertext, and shared-secret sizes
    // from FIPS 203.
    {"ML-KEM-512", PqcAlgorithmKind::kKem, 800U, 1632U, 768U, 32U},
    {"ML-KEM-768", PqcAlgorithmKind::kKem, 1184U, 2400U, 1088U, 32U},
    {"ML-KEM-1024", PqcAlgorithmKind::kKem, 1568U, 3168U, 1568U, 32U},
}};

/// @brief Look up a standardized PQC algorithm by its textual identifier.
[[nodiscard]] inline constexpr std::optional<PqcAlgorithmInfo> LookupPqcAlgorithm(std::string_view algorithm) noexcept
{
    for (const auto& entry : kPqcAlgorithms)
    {
        if (entry.name == algorithm)
        {
            return entry;
        }
    }
    return std::nullopt;
}

/// @brief Return whether the identifier names a PQC signature algorithm.
[[nodiscard]] inline constexpr bool IsPqcSignatureAlgorithm(std::string_view algorithm) noexcept
{
    const auto info = LookupPqcAlgorithm(algorithm);
    return info.has_value() && info->kind == PqcAlgorithmKind::kSignature;
}

/// @brief Return whether the identifier names a PQC KEM algorithm.
[[nodiscard]] inline constexpr bool IsPqcKemAlgorithm(std::string_view algorithm) noexcept
{
    const auto info = LookupPqcAlgorithm(algorithm);
    return info.has_value() && info->kind == PqcAlgorithmKind::kKem;
}

inline constexpr std::array<KeyAlgorithmInfo, 11UL> kKeyAlgorithms = {{
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
}};

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
