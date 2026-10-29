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

#include "score/crypto/src/api/types/algorithm.hpp"

#include <cstddef>
#include <optional>
#include <string_view>

// Provider-independent algorithm properties for the daemon. The hash and MAC
// tables list what the daemon supports; the key, cipher and curve lookups
// resolve an identifier through score::crypto::kAlgorithmCatalog. Every lookup
// matches exactly; nothing searches an identifier for a fragment of another.

namespace score::crypto::daemon::common
{

// ---------------------------------------------------------------------------
// Hash algorithm properties (provider-independent)
// ---------------------------------------------------------------------------

/// @brief Provider-neutral identifiers for supported hash algorithms.
enum class HashAlgorithm
{
    kSha256,  ///< SHA-256.
    kSha384,  ///< SHA-384.
    kSha512,  ///< SHA-512.
    kSha224,  ///< SHA-224.
};

/// @brief Provider-neutral metadata for a hash algorithm.
struct HashAlgorithmInfo
{
    HashAlgorithm algorithm;  ///< Internal algorithm identifier.
    std::string_view name;    ///< API algorithm identifier.
    std::size_t digest_size;  ///< Output size in bytes.
};

inline constexpr HashAlgorithmInfo kHashAlgorithms[] = {
    {HashAlgorithm::kSha256, "SHA256", 32U},
    {HashAlgorithm::kSha384, "SHA384", 48U},
    {HashAlgorithm::kSha512, "SHA512", 64U},
    {HashAlgorithm::kSha224, "SHA224", 28U},
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

// ---------------------------------------------------------------------------
// MAC algorithm properties (provider-independent)
// ---------------------------------------------------------------------------

/// @brief Provider-neutral identifiers for supported MAC algorithms.
enum class MacAlgorithm
{
    kHmacSha256,  ///< HMAC with SHA-256.
    kHmacSha384,  ///< HMAC with SHA-384.
    kHmacSha512,  ///< HMAC with SHA-512.
};

/// @brief Provider-neutral metadata for a MAC algorithm.
struct MacAlgorithmInfo
{
    MacAlgorithm algorithm;  ///< Internal algorithm identifier.
    std::string_view name;   ///< API algorithm identifier.
    std::size_t mac_size;    ///< Output tag size in bytes.
};

inline constexpr MacAlgorithmInfo kMacAlgorithms[] = {
    {MacAlgorithm::kHmacSha256, "HMAC-SHA256", 32U},
    {MacAlgorithm::kHmacSha384, "HMAC-SHA384", 48U},
    {MacAlgorithm::kHmacSha512, "HMAC-SHA512", 64U},
};

/// @brief Look up provider-independent MAC algorithm metadata.
/// @return algorithm metadata, or std::nullopt if unknown.
[[nodiscard]] inline constexpr std::optional<MacAlgorithmInfo> LookupMacAlgorithmInfo(
    std::string_view algorithm) noexcept
{
    for (const auto& entry : kMacAlgorithms)
    {
        if (entry.name == algorithm)
        {
            return entry;
        }
    }
    return std::nullopt;
}

/// @brief Look up MAC output size by algorithm name.
/// @return MAC size in bytes, or std::nullopt if unknown.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupMacSize(std::string_view algorithm) noexcept
{
    const auto info = LookupMacAlgorithmInfo(algorithm);
    return info.has_value() ? std::optional<std::size_t>{info->mac_size} : std::nullopt;
}

// ---------------------------------------------------------------------------
// Key algorithm properties
// ---------------------------------------------------------------------------

/// @brief Look up default key size by algorithm name.
///
/// For elliptic curves this is the byte length of one coordinate.
/// @return key size in bytes, or std::nullopt if the algorithm takes no key or is unknown.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupKeySize(std::string_view algorithm) noexcept
{
    const auto id = ::score::crypto::FromAlgorithmName(algorithm);
    return id.has_value() ? ::score::crypto::GetKeySizeBytes(*id) : std::nullopt;
}

// ---------------------------------------------------------------------------
// Symmetric cipher properties
// ---------------------------------------------------------------------------

struct CipherAlgorithmInfo
{
    std::string_view name;
    std::size_t key_size;    ///< Key length in bytes
    std::size_t block_size;  ///< Cipher block size in bytes; 1 for stream modes
    std::size_t iv_size;     ///< Required IV / nonce length in bytes; 0 when none
};

/// @brief Look up unauthenticated symmetric cipher properties by algorithm name.
/// @return the properties, or std::nullopt if the name is not a cipher algorithm.
[[nodiscard]] inline constexpr std::optional<CipherAlgorithmInfo> LookupCipher(std::string_view algorithm) noexcept
{
    const auto row = ::score::crypto::GetAlgorithmDescriptor(algorithm);
    if (!row.has_value() || (row->category != ::score::crypto::AlgorithmCategory::kCipher))
    {
        return std::nullopt;
    }
    return CipherAlgorithmInfo{
        row->name, (static_cast<std::size_t>(row->key_bits) + 7U) / 8U, row->block_size, row->iv_size};
}

// ---------------------------------------------------------------------------
// Elliptic-curve / ECDSA properties
// ---------------------------------------------------------------------------

/// @brief Properties of a NIST prime curve and the ECDSA variant built on it.
///
/// @note @c signature_size is the IEEE P1363 fixed-length encoding r||s, which
///       is the on-the-wire signature format of this stack.  It is twice the
///       byte length of the field order, so P-521 yields 2 * 66 = 132 bytes.
struct EcCurveInfo
{
    ::score::crypto::EccCurve curve;  ///< Structured curve identifier
    std::string_view name;            ///< Curve token as used in AlgorithmId, e.g. "P256"
    std::string_view group_name;      ///< Standard NIST designation of the curve, e.g. "P-256"
    std::size_t field_size;           ///< Byte length of one coordinate / of r and s
    std::size_t signature_size;       ///< P1363 signature length = 2 * field_size
    std::size_t key_bits;             ///< Nominal key strength in bits
};

/// @note Curve tokens are spelled without an inner hyphen ("P256", not "P-256")
///       so that the hyphen is unambiguously the separator in composite
///       identifiers such as "ECDSA-P256-SHA256".
/// @note @c group_name carries the hyphen that @c name omits, and the two are not
///       interchangeable where a provider selects a curve by name.
inline constexpr EcCurveInfo kEcCurves[] = {
    {::score::crypto::EccCurve::kP256, "P256", "P-256", 32U, 64U, 256U},
    {::score::crypto::EccCurve::kP384, "P384", "P-384", 48U, 96U, 384U},
    {::score::crypto::EccCurve::kP521, "P521", "P-521", 66U, 132U, 521U},
};

/// @brief Look up a curve by its structured identifier.
[[nodiscard]] inline constexpr std::optional<EcCurveInfo> LookupEcCurve(::score::crypto::EccCurve curve) noexcept
{
    for (const auto& entry : kEcCurves)
    {
        if (entry.curve == curve)
        {
            return entry;
        }
    }
    return std::nullopt;
}

/// @brief Components of an ECDSA identifier.
struct EcdsaName
{
    EcCurveInfo curve;
    std::optional<std::string_view> digest;  ///< Hash token; absent for the bare key form "ECDSA-<curve>"
};

/// @brief Split an ECDSA identifier into its curve and digest tokens.
///
/// Accepts exactly "ECDSA-<curve>" (a key algorithm) and "ECDSA-<curve>-<hash>"
/// (a signature scheme), where each token must equal a known curve or hash name.
/// The pairing of curve and hash is not checked here; whether a provider
/// serves it is the provider's decision.
[[nodiscard]] inline constexpr std::optional<EcdsaName> ParseEcdsaName(std::string_view algorithm) noexcept
{
    constexpr std::string_view kPrefix{"ECDSA-"};
    if (algorithm.substr(0U, kPrefix.size()) != kPrefix)
    {
        return std::nullopt;
    }
    const std::string_view rest = algorithm.substr(kPrefix.size());
    const std::size_t dash = rest.find('-');
    const std::string_view curve_token = rest.substr(0U, dash);

    for (const auto& entry : kEcCurves)
    {
        if (entry.name != curve_token)
        {
            continue;
        }
        if (dash == std::string_view::npos)
        {
            return EcdsaName{entry, std::nullopt};
        }
        const std::string_view digest_token = rest.substr(dash + 1U);
        if (!LookupDigestSize(digest_token).has_value())
        {
            return std::nullopt;
        }
        return EcdsaName{entry, digest_token};
    }
    return std::nullopt;
}

/// @brief Extract the curve of an ECDSA key or signature algorithm identifier.
[[nodiscard]] inline constexpr std::optional<EcCurveInfo> LookupEcCurveOfAlgorithm(std::string_view algorithm) noexcept
{
    const auto parsed = ParseEcdsaName(algorithm);
    return parsed.has_value() ? std::optional<EcCurveInfo>{parsed->curve} : std::nullopt;
}

/// @brief Extract the message-digest name of an ECDSA signature algorithm identifier.
///
/// "ECDSA-P256-SHA256" -> "SHA256".
[[nodiscard]] inline constexpr std::optional<std::string_view> LookupSignatureDigest(
    std::string_view algorithm) noexcept
{
    const auto parsed = ParseEcdsaName(algorithm);
    return parsed.has_value() ? parsed->digest : std::nullopt;
}

/// @brief True when the identifier names an ECDSA key or signature algorithm.
[[nodiscard]] inline constexpr bool IsEcdsaAlgorithm(std::string_view algorithm) noexcept
{
    return ParseEcdsaName(algorithm).has_value();
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_ALGORITHM_INFO_HPP
