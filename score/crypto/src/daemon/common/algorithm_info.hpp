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

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

// Daemon helpers over score::crypto::kAlgorithmCatalog. The daemon resolves an
// algorithm name to its catalog row once, where a request or a slot enters it
// (CTX_CREATE in the mediator, the key management request parser, slot load);
// providers and handlers receive that AlgorithmDescriptor and read its fields.
// The helpers here answer the questions a row does not answer by itself.

namespace score::crypto::daemon::common
{

/// Standardized PQC identifiers from the algorithm catalog.
inline constexpr std::string_view kMlDsa44Name{::score::crypto::ToAlgorithmName(::score::crypto::Algorithm::kMlDsa44)};
inline constexpr std::string_view kMlDsa65Name{::score::crypto::ToAlgorithmName(::score::crypto::Algorithm::kMlDsa65)};
inline constexpr std::string_view kMlDsa87Name{::score::crypto::ToAlgorithmName(::score::crypto::Algorithm::kMlDsa87)};
inline constexpr std::string_view kMlKem512Name{::score::crypto::ToAlgorithmName(::score::crypto::Algorithm::kMlKem512)};
inline constexpr std::string_view kMlKem768Name{::score::crypto::ToAlgorithmName(::score::crypto::Algorithm::kMlKem768)};
inline constexpr std::string_view kMlKem1024Name{::score::crypto::ToAlgorithmName(::score::crypto::Algorithm::kMlKem1024)};

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

/// @brief Read standardized PQC sizes from an already resolved catalog descriptor.
[[nodiscard]] inline constexpr std::optional<PqcAlgorithmInfo> LookupPqcAlgorithm(
    const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    if ((algorithm.key_type != ::score::crypto::KeyType::kMlDsa) &&
        (algorithm.key_type != ::score::crypto::KeyType::kMlKem))
    {
        return std::nullopt;
    }
    return PqcAlgorithmInfo{
        algorithm.name,
        algorithm.key_type == ::score::crypto::KeyType::kMlDsa ? PqcAlgorithmKind::kSignature : PqcAlgorithmKind::kKem,
        algorithm.public_key_size,
        algorithm.private_key_size,
        algorithm.output_size,
        algorithm.shared_secret_size};
}

/// @brief Look up a standardized PQC algorithm by its exact textual identifier.
[[nodiscard]] inline constexpr std::optional<PqcAlgorithmInfo> LookupPqcAlgorithm(std::string_view name) noexcept
{
    const auto algorithm = ::score::crypto::GetAlgorithmDescriptor(name);
    return algorithm.has_value() ? LookupPqcAlgorithm(*algorithm) : std::nullopt;
}

/// @brief Return whether the resolved row describes a PQC signature algorithm.
[[nodiscard]] inline constexpr bool IsPqcSignatureAlgorithm(
    const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    return algorithm.key_type == ::score::crypto::KeyType::kMlDsa;
}

/// @brief Return whether the identifier names a PQC signature algorithm.
[[nodiscard]] inline constexpr bool IsPqcSignatureAlgorithm(std::string_view name) noexcept
{
    const auto algorithm = ::score::crypto::GetAlgorithmDescriptor(name);
    return algorithm.has_value() && IsPqcSignatureAlgorithm(*algorithm);
}

/// @brief Return whether the resolved row describes a PQC KEM algorithm.
[[nodiscard]] inline constexpr bool IsPqcKemAlgorithm(
    const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    return algorithm.key_type == ::score::crypto::KeyType::kMlKem;
}

/// @brief Return whether the identifier names a PQC KEM algorithm.
[[nodiscard]] inline constexpr bool IsPqcKemAlgorithm(std::string_view name) noexcept
{
    const auto algorithm = ::score::crypto::GetAlgorithmDescriptor(name);
    return algorithm.has_value() && IsPqcKemAlgorithm(*algorithm);
}

/// @brief Digest length in bytes of a hash function, from its hash row in the catalog.
/// @return the length, or std::nullopt for HashFunction::kNone.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupDigestSize(::score::crypto::HashFunction hash) noexcept
{
    if (hash == ::score::crypto::HashFunction::kNone)
    {
        return std::nullopt;
    }
    for (const auto& row : ::score::crypto::kAlgorithmCatalog)
    {
        if ((row.category == ::score::crypto::AlgorithmCategory::kHash) && (row.hash == hash))
        {
            return row.output_size;
        }
    }
    return std::nullopt;
}

/// @brief Default key size of the key an algorithm labels.
///
/// Answers for rows that can label a key: key rows, symmetric cipher, AEAD
/// and MAC rows, and Ed25519. A signature scheme such as
/// "RSA-PSS-2048-SHA256" or "ECDSA-P256-SHA256" names no key and yields
/// std::nullopt, so it cannot be mistaken for a request for that many random
/// bytes. For elliptic curves this is the byte length of one coordinate.
/// For ML-DSA and ML-KEM it is the encoded private-key length.
/// @return key size in bytes, or std::nullopt if the row labels no key.
[[nodiscard]] inline constexpr std::optional<std::size_t> LookupKeySize(
    const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    if ((algorithm.key_type == ::score::crypto::KeyType::kMlDsa) ||
        (algorithm.key_type == ::score::crypto::KeyType::kMlKem))
    {
        return algorithm.private_key_size;
    }
    if ((algorithm.key_type == ::score::crypto::KeyType::kNone) ||
        ((algorithm.category == ::score::crypto::AlgorithmCategory::kSignature) &&
         (algorithm.key_type != ::score::crypto::KeyType::kEd25519)))
    {
        return std::nullopt;
    }
    return (static_cast<std::size_t>(algorithm.key_bits) + 7U) / 8U;
}

/// @brief Byte length of one coordinate of the curve of an ECC row, which is
///        also the length of r and s in an ECDSA signature.
/// @return the length, or 0 for rows without a curve.
[[nodiscard]] inline constexpr std::size_t EcFieldSize(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    return ::score::crypto::algorithm_catalog_detail::EccFieldSize(algorithm.curve);
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

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_ALGORITHM_INFO_HPP
