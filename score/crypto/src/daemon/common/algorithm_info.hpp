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
    {"ECDSA-P256", 32U},
    {"ECDSA-P384", 48U},
    {"ECDSA-P521", 66U},
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
    std::string_view name;          ///< Curve identifier as used in AlgorithmId, e.g. "P256"
    std::string_view openssl_name;  ///< OpenSSL group name, e.g. "prime256v1" / "secp384r1"
    std::size_t field_size;         ///< Byte length of one coordinate / of r and s
    std::size_t signature_size;     ///< P1363 signature length = 2 * field_size
    std::size_t key_bits;           ///< Nominal key strength in bits
};

/// @note Curve names are spelled without an inner hyphen ("P256", not "P-256")
///       so that the hyphen is unambiguously the separator in composite
///       identifiers such as "ECDSA-P256-SHA256". This matches the AlgorithmId
///       examples documented in score/crypto/src/api/common/types.hpp.
inline constexpr EcCurveInfo kEcCurves[] = {
    {"P256", "prime256v1", 32U, 64U, 256U},
    {"P384", "secp384r1", 48U, 96U, 384U},
    // NIST's largest prime curve is P-521 (not P-512); 521 bits is 66 bytes.
    {"P521", "secp521r1", 66U, 132U, 521U},
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
