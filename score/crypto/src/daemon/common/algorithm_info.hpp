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
// tables list what the daemon supports and take their names and sizes from
// score::crypto::kAlgorithmCatalog; the key, cipher and curve lookups resolve
// an identifier through the catalog directly. Every lookup matches exactly;
// nothing searches an identifier for a fragment of another.

namespace score::crypto::daemon::common
{

// ---------------------------------------------------------------------------
// Catalog membership of provider support lists
// ---------------------------------------------------------------------------

/// @brief Whether every name in @p names is a catalog identifier.
///
/// Providers keep their own list of the identifiers they serve. Checking such a
/// list with static_assert turns a misspelt or uncatalogued entry into a build
/// error instead of an algorithm that is silently never served.
template <typename Names>
[[nodiscard]] constexpr bool AllInCatalog(const Names& names) noexcept
{
    for (const auto& name : names)
    {
        if (!::score::crypto::FromAlgorithmName(std::string_view{name}).has_value())
        {
            return false;
        }
    }
    return true;
}

/// @brief Whether every name in @p names is a catalog identifier of @p category.
template <typename Names>
[[nodiscard]] constexpr bool AllInCatalog(const Names& names, ::score::crypto::AlgorithmCategory category) noexcept
{
    for (const auto& name : names)
    {
        if (::score::crypto::GetAlgorithmCategory(std::string_view{name}) != category)
        {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Hash and MAC properties (provider-independent)
// ---------------------------------------------------------------------------
//
// The catalog holds the properties; whether an algorithm is served is decided
// per provider. A provider maps the catalog's HashFunction to its own type in
// an exhaustive switch without a default case, so a hash added to the catalog
// needs an explicit decision in every provider.

/// @brief Look up digest size by hash algorithm name.
/// @return digest size in bytes, or std::nullopt if @p algorithm is not a hash in the catalog.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupDigestSize(std::string_view algorithm) noexcept
{
    const auto row = ::score::crypto::GetAlgorithmDescriptor(algorithm);
    if (!row.has_value() || (row->category != ::score::crypto::AlgorithmCategory::kHash))
    {
        return std::nullopt;
    }
    return row->output_size;
}

/// @brief Look up MAC output size by algorithm name.
/// @return tag size in bytes, or std::nullopt if @p algorithm is not a MAC in the catalog.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupMacSize(std::string_view algorithm) noexcept
{
    const auto row = ::score::crypto::GetAlgorithmDescriptor(algorithm);
    if (!row.has_value() || (row->category != ::score::crypto::AlgorithmCategory::kMac))
    {
        return std::nullopt;
    }
    return row->output_size;
}

/// @brief Hash function of a hash algorithm name, e.g. HashFunction::kSha256 for "SHA256".
/// @return the hash function, or std::nullopt if @p algorithm is not a hash in the catalog.
[[nodiscard]] inline constexpr std::optional<::score::crypto::HashFunction> LookupHashFunction(
    std::string_view algorithm) noexcept
{
    const auto row = ::score::crypto::GetAlgorithmDescriptor(algorithm);
    if (!row.has_value() || (row->category != ::score::crypto::AlgorithmCategory::kHash))
    {
        return std::nullopt;
    }
    return row->hash;
}

/// @brief Underlying hash function of an HMAC name, e.g. HashFunction::kSha256 for "HMAC-SHA256".
/// @return the hash function, or std::nullopt if @p algorithm is not an HMAC in the catalog.
[[nodiscard]] inline constexpr std::optional<::score::crypto::HashFunction> LookupHmacHashFunction(
    std::string_view algorithm) noexcept
{
    const auto row = ::score::crypto::GetAlgorithmDescriptor(algorithm);
    if (!row.has_value() || (row->category != ::score::crypto::AlgorithmCategory::kMac) ||
        (row->hash == ::score::crypto::HashFunction::kNone))
    {
        return std::nullopt;
    }
    return row->hash;
}

// ---------------------------------------------------------------------------
// Key algorithm properties
// ---------------------------------------------------------------------------

/// @brief Look up default key size by algorithm name.
///
/// Answers for names that can label a key: key rows, symmetric cipher, AEAD
/// and MAC rows, and Ed25519. A signature scheme such as
/// "RSA-PSS-2048-SHA256" names no key and yields std::nullopt, so it cannot be
/// mistaken for a request for that many random bytes.
/// For elliptic curves this is the byte length of one coordinate.
/// @return key size in bytes, or std::nullopt if the name labels no key or is unknown.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupKeySize(std::string_view algorithm) noexcept
{
    const auto row = ::score::crypto::GetAlgorithmDescriptor(algorithm);
    if (!row.has_value() || ((row->category == ::score::crypto::AlgorithmCategory::kSignature) &&
                             (row->key_type != ::score::crypto::KeyType::kEd25519)))
    {
        return std::nullopt;
    }
    return ::score::crypto::GetKeySizeBytes(row->id);
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
/// (a signature scheme), where the curve token must equal a curve of kEcCurves
/// and the hash token the name of a hash row of the catalog. Any such pairing is
/// an ECDSA name, e.g. "ECDSA-P256-SHA384", without a catalog row of its own;
/// whether a provider serves the pairing, and with which hashes, is the
/// provider's decision.
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
        if (!LookupHashFunction(digest_token).has_value())
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

/// @brief Name of the hash row for a digest, e.g. "SHA256" for HashFunction::kSha256.
[[nodiscard]] inline constexpr std::optional<std::string_view> LookupHashName(
    ::score::crypto::HashFunction hash) noexcept
{
    if (hash == ::score::crypto::HashFunction::kNone)
    {
        return std::nullopt;
    }
    for (const auto& row : ::score::crypto::kAlgorithmCatalog)
    {
        if ((row.category == ::score::crypto::AlgorithmCategory::kHash) && (row.hash == hash))
        {
            return row.name;
        }
    }
    return std::nullopt;
}

/// @brief Extract the message-digest name of a signature algorithm identifier.
///
/// "ECDSA-P256-SHA256" -> "SHA256", "RSA-PSS-2048-SHA384" -> "SHA384".
/// ECDSA names are split into tokens, so any curve/hash pairing resolves;
/// other schemes resolve through their catalog row. Ed25519 has no separate
/// digest and yields std::nullopt.
[[nodiscard]] inline constexpr std::optional<std::string_view> LookupSignatureDigest(
    std::string_view algorithm) noexcept
{
    const auto parsed = ParseEcdsaName(algorithm);
    if (parsed.has_value())
    {
        return parsed->digest;
    }
    const auto row = ::score::crypto::GetAlgorithmDescriptor(algorithm);
    if (!row.has_value() || (row->category != ::score::crypto::AlgorithmCategory::kSignature))
    {
        return std::nullopt;
    }
    return LookupHashName(row->hash);
}

/// @brief Look up the digest size for a signature algorithm identifier.
/// @return digest size in bytes, or std::nullopt if the scheme has no separate digest.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupSignatureDigestSize(std::string_view algorithm) noexcept
{
    const auto digest = LookupSignatureDigest(algorithm);
    return digest.has_value() ? LookupDigestSize(*digest) : std::nullopt;
}

// ---------------------------------------------------------------------------
// RSA properties
// ---------------------------------------------------------------------------

/// @brief Properties of a supported RSA key size.
struct RsaKeyInfo
{
    std::string_view name;     ///< Key algorithm identifier, e.g. "RSA-2048"
    std::size_t modulus_size;  ///< Modulus length in bytes
    std::size_t key_bits;      ///< Modulus length in bits
};

/// @brief Look up RSA key properties from an RSA key algorithm identifier ("RSA-2048").
/// @return the properties, or std::nullopt if the name is not an RSA key row of the catalog.
[[nodiscard]] inline constexpr std::optional<RsaKeyInfo> LookupRsaKeyInfo(std::string_view algorithm) noexcept
{
    const auto row = ::score::crypto::GetAlgorithmDescriptor(algorithm);
    if (!row.has_value() || (row->category != ::score::crypto::AlgorithmCategory::kKey) ||
        (row->key_type != ::score::crypto::KeyType::kRsa))
    {
        return std::nullopt;
    }
    return RsaKeyInfo{row->name, (static_cast<std::size_t>(row->key_bits) + 7U) / 8U, row->key_bits};
}

/// @brief True when the identifier names a complete RSA-PSS signature scheme, e.g. "RSA-PSS-2048-SHA256".
[[nodiscard]] inline constexpr bool IsRsaPssAlgorithm(std::string_view algorithm) noexcept
{
    const auto row = ::score::crypto::GetAlgorithmDescriptor(algorithm);
    return row.has_value() && (row->category == ::score::crypto::AlgorithmCategory::kSignature) &&
           (row->key_type == ::score::crypto::KeyType::kRsa);
}

/// @brief Look up the RSA key properties an RSA-PSS signature scheme needs.
/// @return the key row with the scheme's modulus length, or std::nullopt.
[[nodiscard]] inline constexpr std::optional<RsaKeyInfo> LookupRsaKeyInfoForSignatureAlgorithm(
    std::string_view algorithm) noexcept
{
    const auto scheme = ::score::crypto::GetAlgorithmDescriptor(algorithm);
    if (!IsRsaPssAlgorithm(algorithm) || !scheme.has_value())
    {
        return std::nullopt;
    }
    for (const auto& row : ::score::crypto::kAlgorithmCatalog)
    {
        if ((row.category == ::score::crypto::AlgorithmCategory::kKey) &&
            (row.key_type == ::score::crypto::KeyType::kRsa) && (row.key_bits == scheme->key_bits))
        {
            return LookupRsaKeyInfo(row.name);
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Ed25519 properties
// ---------------------------------------------------------------------------

/// Ed25519 key size in bytes (RFC 8032).
inline constexpr std::size_t kEd25519KeySize{
    ::score::crypto::GetKeySizeBytes(::score::crypto::Algorithm::kEd25519).value_or(0U)};

/// Ed25519 signature size in bytes (RFC 8032).
inline constexpr std::size_t kEd25519SignatureSize{
    ::score::crypto::GetAlgorithmDescriptor(::score::crypto::Algorithm::kEd25519).has_value()
        ? ::score::crypto::GetAlgorithmDescriptor(::score::crypto::Algorithm::kEd25519)->output_size
        : 0U};

static_assert((kEd25519KeySize == 32U) && (kEd25519SignatureSize == 64U), "Ed25519 sizes are fixed by RFC 8032");

/// @brief True when the identifier names the Ed25519 key or signature algorithm.
[[nodiscard]] inline constexpr bool IsEd25519Algorithm(std::string_view algorithm) noexcept
{
    const auto row = ::score::crypto::GetAlgorithmDescriptor(algorithm);
    return row.has_value() && (row->key_type == ::score::crypto::KeyType::kEd25519);
}

/// @brief True when the identifier names an ECDSA key or signature algorithm.
[[nodiscard]] inline constexpr bool IsEcdsaAlgorithm(std::string_view algorithm) noexcept
{
    return ParseEcdsaName(algorithm).has_value();
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_ALGORITHM_INFO_HPP
