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

inline constexpr std::array<KeyAlgorithmInfo, 14UL> kKeyAlgorithms = {{
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
    {"ECDSA-P256", 32U},
    {"ECDSA-P384", 48U},
    {"ECDSA-P521", 66U},
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

// ---------------------------------------------------------------------------
// Symmetric cipher properties (provider-independent)
// ---------------------------------------------------------------------------

struct CipherAlgorithmInfo
{
    std::string_view name;
    std::size_t key_size;    ///< Key length in bytes
    std::size_t block_size;  ///< Cipher block size in bytes; 1 for stream modes
    std::size_t iv_size;     ///< Required IV / nonce length in bytes; 0 when none
};

// Currently only AES-CBC is supported by the daemon, but this table can be
// extended to include other symmetric ciphers (AES-CTR, AES-ECB, etc.)
inline constexpr CipherAlgorithmInfo kCipherAlgorithms[] = {
    {"AES-128-CBC", 16U, 16U, 16U},
    {"AES-192-CBC", 24U, 16U, 16U},
    {"AES-256-CBC", 32U, 16U, 16U},
};

/// @brief Look up symmetric cipher properties by algorithm name.
/// @return the entry, or std::nullopt if the algorithm is unknown.
[[nodiscard]] inline constexpr std::optional<CipherAlgorithmInfo> LookupCipher(std::string_view algorithm) noexcept
{
    for (const auto& entry : kCipherAlgorithms)
    {
        if (entry.name == algorithm)
        {
            return entry;
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Elliptic-curve / ECDSA properties (provider-independent)
// ---------------------------------------------------------------------------

/// @brief Properties of a NIST prime curve and the ECDSA variant built on it.
///
/// @note @c signature_size is the IEEE P1363 fixed-length encoding r?s, which
///       is the on-the-wire signature format of this stack.  It is twice the
///       byte length of the field order, so P-521 yields 2 * 66 = 132 bytes.
struct EcCurveInfo
{
    std::string_view name;        ///< Curve identifier as used in AlgorithmId, e.g. "P256"
    std::string_view group_name;  ///< Standard NIST designation of the curve, e.g. "P-256"
    std::size_t field_size;       ///< Byte length of one coordinate / of r and s
    std::size_t signature_size;   ///< P1363 signature length = 2 * field_size
    std::size_t key_bits;         ///< Nominal key strength in bits
};

/// @note Curve names are spelled without an inner hyphen ("P256", not "P-256")
///       so that the hyphen is unambiguously the separator in composite
///       identifiers such as "ECDSA-P256-SHA256". This matches the AlgorithmId
///       examples documented in score/crypto/src/api/common/types.hpp.
/// @note @c group_name carries the hyphen that @c name omits, and the two are not
///       interchangeable where a provider selects a curve by name. The spelling
///       of @c group_name does not follow from @c name in general, so each curve
///       carries both.
inline constexpr EcCurveInfo kEcCurves[] = {
    {"P256", "P-256", 32U, 64U, 256U},
    {"P384", "P-384", 48U, 96U, 384U},
    // NIST's largest prime curve is P-521 (not P-512); 521 bits is 66 bytes.
    {"P521", "P-521", 66U, 132U, 521U},
};

/// @brief Extract the curve of an ECDSA signature algorithm identifier.
///
/// Accepts signature algorithms like ECDSA-P256-SHA256 i.e.ECDSA-<NIST curve>-<Hash algo>.
[[nodiscard]] inline constexpr std::optional<EcCurveInfo> LookupEcCurveOfAlgorithm(std::string_view algorithm) noexcept
{
    for (const auto& entry : kEcCurves)
    {
        if (algorithm.find(entry.name) != std::string_view::npos)
        {
            return entry;
        }
    }
    return std::nullopt;
}

/// @brief Extract the message-digest name of a signature algorithm identifier.
///
/// "ECDSA-P256-SHA256" -> "SHA256".
[[nodiscard]] inline constexpr std::optional<std::string_view> LookupSignatureDigest(
    std::string_view algorithm) noexcept
{
    for (const auto& entry : kHashAlgorithms)
    {
        if (algorithm.find(entry.name) != std::string_view::npos)
        {
            return entry.name;
        }
    }
    return std::nullopt;
}

/// @brief True when the identifier names an ECDSA key or signature algorithm.
[[nodiscard]] inline constexpr bool IsEcdsaAlgorithm(std::string_view algorithm) noexcept
{
    return (algorithm.find("ECDSA") != std::string_view::npos) && LookupEcCurveOfAlgorithm(algorithm).has_value();
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_ALGORITHM_INFO_HPP
