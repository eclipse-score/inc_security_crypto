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

#ifndef SCORE_CRYPTO_SRC_API_TYPES_ALGORITHM_HPP
#define SCORE_CRYPTO_SRC_API_TYPES_ALGORITHM_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>

namespace score::crypto
{

/// @brief Operation class an algorithm identifier belongs to.
enum class AlgorithmCategory : std::uint8_t
{
    kUnknown,    ///< Not an identifier this build knows.
    kHash,       ///< Message digest.
    kMac,        ///< Message authentication code.
    kCipher,     ///< Unauthenticated symmetric cipher.
    kAead,       ///< Authenticated symmetric cipher.
    kSignature,  ///< Signature scheme: key family, curve and digest.
    kKey,        ///< Key algorithm only; names key material, not an operation.
    kRandom      ///< Random bit generator.
};

/// @brief Kind of key material an algorithm consumes.
enum class KeyType : std::uint8_t
{
    kNone,    ///< The algorithm takes no key.
    kSecret,  ///< Opaque symmetric secret of any length, e.g. an HMAC key.
    kAes,     ///< AES key; its length selects the AES variant.
    kEcc      ///< Elliptic-curve key pair or public key on one named curve.
};

/// @brief Message digest an algorithm is built on, or computes.
enum class HashFunction : std::uint8_t
{
    kNone,
    kMd5,
    kSha1,
    kSha224,
    kSha256,
    kSha384,
    kSha512
};

/// @brief Named elliptic curve.
enum class EccCurve : std::uint8_t
{
    kNone,
    kP256,  ///< NIST P-256 (secp256r1).
    kP384,  ///< NIST P-384 (secp384r1).
    kP521   ///< NIST P-521 (secp521r1).
};

/// @brief Block cipher mode of operation.
enum class CipherMode : std::uint8_t
{
    kNone,
    kCbc,
    kGcm
};

/// @brief Structured identifier of every algorithm this build knows by name.
///
/// The wire protocol and the context configs carry algorithms as AlgorithmId
/// strings. FromAlgorithmName() turns such a string into this enumerator by
/// exact match, so code that needs the properties of an algorithm reads them
/// from the catalog instead of searching the string for fragments.
enum class Algorithm : std::uint16_t
{
    kUnknown = 0,

    // Hash
    kMd5,
    kSha1,
    kSha224,
    kSha256,
    kSha384,
    kSha512,

    // MAC
    kHmacSha256,
    kHmacSha384,
    kHmacSha512,
    kAes128Cmac,
    kAes256Cmac,

    // Cipher
    kAes128Cbc,
    kAes192Cbc,
    kAes256Cbc,

    // AEAD
    kAes128Gcm,
    kAes192Gcm,
    kAes256Gcm,

    // Signature
    kEcdsaP256Sha256,
    kEcdsaP384Sha384,
    kEcdsaP521Sha512,

    // Key
    kAes128,
    kAes192,
    kAes256,
    kEcdsaP256,
    kEcdsaP384,
    kEcdsaP521,

    // Random
    kCtrDrbg
};

/// @brief Provider-independent properties of one algorithm.
///
/// @note @c key_bits is the nominal key length: the AES variant, the curve
///       order, or the default secret length for HMAC.
/// @note @c output_size is the fixed length in bytes of the digest, MAC or
///       signature. It is zero where the output length follows the input, as
///       for ciphers. Signatures use the fixed-length IEEE P1363 r||s form,
///       which is the wire format of this stack.
struct AlgorithmDescriptor
{
    Algorithm id{Algorithm::kUnknown};
    std::string_view name{};
    AlgorithmCategory category{AlgorithmCategory::kUnknown};
    KeyType key_type{KeyType::kNone};
    std::uint16_t key_bits{0U};
    HashFunction hash{HashFunction::kNone};
    EccCurve curve{EccCurve::kNone};
    CipherMode mode{CipherMode::kNone};
    std::uint16_t output_size{0U};
    std::uint8_t block_size{0U};
    std::uint8_t iv_size{0U};
};

namespace algorithm_catalog_detail
{

[[nodiscard]] constexpr AlgorithmDescriptor Hash(Algorithm id,
                                                 std::string_view name,
                                                 HashFunction hash,
                                                 std::uint16_t digest_size) noexcept
{
    return {id,
            name,
            AlgorithmCategory::kHash,
            KeyType::kNone,
            0U,
            hash,
            EccCurve::kNone,
            CipherMode::kNone,
            digest_size,
            0U,
            0U};
}

[[nodiscard]] constexpr AlgorithmDescriptor Hmac(Algorithm id,
                                                 std::string_view name,
                                                 HashFunction hash,
                                                 std::uint16_t mac_size) noexcept
{
    // The default HMAC key is as long as the digest.
    const auto key_bits = static_cast<std::uint16_t>(mac_size * 8U);
    return {id,
            name,
            AlgorithmCategory::kMac,
            KeyType::kSecret,
            key_bits,
            hash,
            EccCurve::kNone,
            CipherMode::kNone,
            mac_size,
            0U,
            0U};
}

[[nodiscard]] constexpr AlgorithmDescriptor Cmac(Algorithm id, std::string_view name, std::uint16_t key_bits) noexcept
{
    return {id,
            name,
            AlgorithmCategory::kMac,
            KeyType::kAes,
            key_bits,
            HashFunction::kNone,
            EccCurve::kNone,
            CipherMode::kNone,
            16U,
            16U,
            0U};
}

[[nodiscard]] constexpr AlgorithmDescriptor AesCbc(Algorithm id, std::string_view name, std::uint16_t key_bits) noexcept
{
    return {id,
            name,
            AlgorithmCategory::kCipher,
            KeyType::kAes,
            key_bits,
            HashFunction::kNone,
            EccCurve::kNone,
            CipherMode::kCbc,
            0U,
            16U,
            16U};
}

[[nodiscard]] constexpr AlgorithmDescriptor AesGcm(Algorithm id, std::string_view name, std::uint16_t key_bits) noexcept
{
    return {id,
            name,
            AlgorithmCategory::kAead,
            KeyType::kAes,
            key_bits,
            HashFunction::kNone,
            EccCurve::kNone,
            CipherMode::kGcm,
            0U,
            1U,
            12U};
}

[[nodiscard]] constexpr AlgorithmDescriptor Ecdsa(Algorithm id,
                                                  std::string_view name,
                                                  EccCurve curve,
                                                  std::uint16_t key_bits,
                                                  HashFunction hash,
                                                  std::uint16_t signature_size) noexcept
{
    return {id,
            name,
            AlgorithmCategory::kSignature,
            KeyType::kEcc,
            key_bits,
            hash,
            curve,
            CipherMode::kNone,
            signature_size,
            0U,
            0U};
}

[[nodiscard]] constexpr AlgorithmDescriptor AesKey(Algorithm id, std::string_view name, std::uint16_t key_bits) noexcept
{
    return {id,
            name,
            AlgorithmCategory::kKey,
            KeyType::kAes,
            key_bits,
            HashFunction::kNone,
            EccCurve::kNone,
            CipherMode::kNone,
            0U,
            0U,
            0U};
}

[[nodiscard]] constexpr AlgorithmDescriptor EccKey(Algorithm id,
                                                   std::string_view name,
                                                   EccCurve curve,
                                                   std::uint16_t key_bits) noexcept
{
    return {id,
            name,
            AlgorithmCategory::kKey,
            KeyType::kEcc,
            key_bits,
            HashFunction::kNone,
            curve,
            CipherMode::kNone,
            0U,
            0U,
            0U};
}

[[nodiscard]] constexpr AlgorithmDescriptor Rbg(Algorithm id, std::string_view name) noexcept
{
    return {id,
            name,
            AlgorithmCategory::kRandom,
            KeyType::kNone,
            0U,
            HashFunction::kNone,
            EccCurve::kNone,
            CipherMode::kNone,
            0U,
            0U,
            0U};
}

}  // namespace algorithm_catalog_detail

/// @brief Every algorithm identifier this build knows, with its properties.
///
/// A name in this table is not a promise that any provider serves it; use
/// ICryptoContext::QueryCapabilities() for that. Curve tokens are spelled
/// without an inner hyphen ("P256") so the hyphen stays the separator.
inline constexpr AlgorithmDescriptor kAlgorithmCatalog[] = {
    algorithm_catalog_detail::Hash(Algorithm::kMd5, "MD5", HashFunction::kMd5, 16U),
    algorithm_catalog_detail::Hash(Algorithm::kSha1, "SHA1", HashFunction::kSha1, 20U),
    algorithm_catalog_detail::Hash(Algorithm::kSha224, "SHA224", HashFunction::kSha224, 28U),
    algorithm_catalog_detail::Hash(Algorithm::kSha256, "SHA256", HashFunction::kSha256, 32U),
    algorithm_catalog_detail::Hash(Algorithm::kSha384, "SHA384", HashFunction::kSha384, 48U),
    algorithm_catalog_detail::Hash(Algorithm::kSha512, "SHA512", HashFunction::kSha512, 64U),

    algorithm_catalog_detail::Hmac(Algorithm::kHmacSha256, "HMAC-SHA256", HashFunction::kSha256, 32U),
    algorithm_catalog_detail::Hmac(Algorithm::kHmacSha384, "HMAC-SHA384", HashFunction::kSha384, 48U),
    algorithm_catalog_detail::Hmac(Algorithm::kHmacSha512, "HMAC-SHA512", HashFunction::kSha512, 64U),
    algorithm_catalog_detail::Cmac(Algorithm::kAes128Cmac, "AES-128-CMAC", 128U),
    algorithm_catalog_detail::Cmac(Algorithm::kAes256Cmac, "AES-256-CMAC", 256U),

    algorithm_catalog_detail::AesCbc(Algorithm::kAes128Cbc, "AES-128-CBC", 128U),
    algorithm_catalog_detail::AesCbc(Algorithm::kAes192Cbc, "AES-192-CBC", 192U),
    algorithm_catalog_detail::AesCbc(Algorithm::kAes256Cbc, "AES-256-CBC", 256U),

    algorithm_catalog_detail::AesGcm(Algorithm::kAes128Gcm, "AES-128-GCM", 128U),
    algorithm_catalog_detail::AesGcm(Algorithm::kAes192Gcm, "AES-192-GCM", 192U),
    algorithm_catalog_detail::AesGcm(Algorithm::kAes256Gcm, "AES-256-GCM", 256U),

    // NIST's largest prime curve is P-521 (not P-512); its coordinates are 66 bytes.
    algorithm_catalog_detail::Ecdsa(Algorithm::kEcdsaP256Sha256,
                                    "ECDSA-P256-SHA256",
                                    EccCurve::kP256,
                                    256U,
                                    HashFunction::kSha256,
                                    64U),
    algorithm_catalog_detail::Ecdsa(Algorithm::kEcdsaP384Sha384,
                                    "ECDSA-P384-SHA384",
                                    EccCurve::kP384,
                                    384U,
                                    HashFunction::kSha384,
                                    96U),
    algorithm_catalog_detail::Ecdsa(Algorithm::kEcdsaP521Sha512,
                                    "ECDSA-P521-SHA512",
                                    EccCurve::kP521,
                                    521U,
                                    HashFunction::kSha512,
                                    132U),

    algorithm_catalog_detail::AesKey(Algorithm::kAes128, "AES-128", 128U),
    algorithm_catalog_detail::AesKey(Algorithm::kAes192, "AES-192", 192U),
    algorithm_catalog_detail::AesKey(Algorithm::kAes256, "AES-256", 256U),
    algorithm_catalog_detail::EccKey(Algorithm::kEcdsaP256, "ECDSA-P256", EccCurve::kP256, 256U),
    algorithm_catalog_detail::EccKey(Algorithm::kEcdsaP384, "ECDSA-P384", EccCurve::kP384, 384U),
    algorithm_catalog_detail::EccKey(Algorithm::kEcdsaP521, "ECDSA-P521", EccCurve::kP521, 521U),

    algorithm_catalog_detail::Rbg(Algorithm::kCtrDrbg, "CTR-DRBG"),
};

/// @brief Look up the catalog row of an algorithm.
/// @return The row, or std::nullopt for Algorithm::kUnknown and values outside the catalog.
[[nodiscard]] inline constexpr std::optional<AlgorithmDescriptor> GetAlgorithmDescriptor(Algorithm algorithm) noexcept
{
    if (algorithm == Algorithm::kUnknown)
    {
        return std::nullopt;
    }
    for (const auto& row : kAlgorithmCatalog)
    {
        if (row.id == algorithm)
        {
            return row;
        }
    }
    return std::nullopt;
}

/// @brief Parse an algorithm identifier string by exact, case-sensitive match.
/// @return The structured identifier, or std::nullopt if the name is not in the catalog.
[[nodiscard]] inline constexpr std::optional<Algorithm> FromAlgorithmName(std::string_view name) noexcept
{
    if (name.empty())
    {
        return std::nullopt;
    }
    for (const auto& row : kAlgorithmCatalog)
    {
        if ((row.id != Algorithm::kUnknown) && (row.name == name))
        {
            return row.id;
        }
    }
    return std::nullopt;
}

/// @brief Canonical identifier string of an algorithm.
/// @return The name, or an empty view for Algorithm::kUnknown.
[[nodiscard]] inline constexpr std::string_view ToAlgorithmName(Algorithm algorithm) noexcept
{
    const auto row = GetAlgorithmDescriptor(algorithm);
    return row.has_value() ? row->name : std::string_view{};
}

/// @brief Look up the catalog row of an algorithm identifier string.
[[nodiscard]] inline constexpr std::optional<AlgorithmDescriptor> GetAlgorithmDescriptor(std::string_view name) noexcept
{
    const auto id = FromAlgorithmName(name);
    return id.has_value() ? GetAlgorithmDescriptor(*id) : std::nullopt;
}

/// @brief Operation class of an algorithm.
[[nodiscard]] inline constexpr AlgorithmCategory GetAlgorithmCategory(Algorithm algorithm) noexcept
{
    const auto row = GetAlgorithmDescriptor(algorithm);
    return row.has_value() ? row->category : AlgorithmCategory::kUnknown;
}

/// @brief Operation class of an algorithm identifier string.
[[nodiscard]] inline constexpr AlgorithmCategory GetAlgorithmCategory(std::string_view name) noexcept
{
    const auto row = GetAlgorithmDescriptor(name);
    return row.has_value() ? row->category : AlgorithmCategory::kUnknown;
}

/// @brief Key length in bytes implied by an algorithm.
///
/// For curves this is the byte length of one coordinate, so P-521 gives 66.
/// @return The length, or std::nullopt when the algorithm takes no key.
[[nodiscard]] inline constexpr std::optional<std::size_t> GetKeySizeBytes(Algorithm algorithm) noexcept
{
    const auto row = GetAlgorithmDescriptor(algorithm);
    if (!row.has_value() || (row->key_type == KeyType::kNone))
    {
        return std::nullopt;
    }
    return (static_cast<std::size_t>(row->key_bits) + 7U) / 8U;
}

/// @brief Output length in bytes of an algorithm whose output does not depend on its input.
///
/// Covers digests, MACs and signatures. Signatures are raw r || s, so
/// ECDSA-P384-SHA384 gives 96.
/// @return The length, or std::nullopt for algorithms without a fixed output.
[[nodiscard]] inline constexpr std::optional<std::size_t> GetFixedOutputSize(Algorithm algorithm) noexcept
{
    const auto row = GetAlgorithmDescriptor(algorithm);
    if (!row.has_value() || (row->output_size == 0U))
    {
        return std::nullopt;
    }
    return static_cast<std::size_t>(row->output_size);
}

/// @brief Upper bound on the bytes one call of an operation context writes.
///
/// Matches the context-level queries (GetDigestSize(), GetMacSize(),
/// GetSignatureSize(), ICipherContext::GetMaximumOutputSize()), so buffers can
/// be sized at compile time:
/// - digest, MAC, signature: the fixed output size, whatever @p input_size;
/// - block cipher: @p input_size plus one block, for update, single-shot and
///   finalize (input_size 0) in either direction.
///
/// @return The bound, or std::nullopt for algorithms without a defined bound
///         (keys, random generators, AEAD) and when the sum would overflow.
[[nodiscard]] inline constexpr std::optional<std::size_t> GetMaximumOutputSize(Algorithm algorithm,
                                                                               std::size_t input_size) noexcept
{
    const auto row = GetAlgorithmDescriptor(algorithm);
    if (!row.has_value())
    {
        return std::nullopt;
    }
    if (row->output_size != 0U)
    {
        return static_cast<std::size_t>(row->output_size);
    }
    if ((row->category != AlgorithmCategory::kCipher) || (row->block_size == 0U))
    {
        return std::nullopt;
    }
    const auto block_size = static_cast<std::size_t>(row->block_size);
    if (input_size > (std::numeric_limits<std::size_t>::max() - block_size))
    {
        return std::nullopt;
    }
    return input_size + block_size;
}

}  // namespace score::crypto

#endif  // SCORE_CRYPTO_SRC_API_TYPES_ALGORITHM_HPP
