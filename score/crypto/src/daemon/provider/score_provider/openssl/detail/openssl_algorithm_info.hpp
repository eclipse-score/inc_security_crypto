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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_OPENSSL_ALGORITHM_INFO_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_OPENSSL_ALGORITHM_INFO_HPP

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"

#include <openssl/evp.h>

#include <cstdint>
#include <initializer_list>
#include <string_view>

// The OpenSSL provider decides from the typed fields of a resolved catalog row
// whether it serves an algorithm. Every decision on a catalog enum is a switch
// without a default case, so a value added to the catalog does not compile
// until this provider has decided whether it serves it.

namespace score::crypto::daemon::provider::openssl::detail
{

/// @brief The EVP_MD the OpenSSL provider uses for a hash function.
/// @return EVP_MD pointer, or nullptr if this provider does not serve the hash function.
[[nodiscard]] inline const EVP_MD* ToEvpMd(::score::crypto::HashFunction hash) noexcept
{
    switch (hash)
    {
        case ::score::crypto::HashFunction::kSha224:
            return EVP_sha224();
        case ::score::crypto::HashFunction::kSha256:
            return EVP_sha256();
        case ::score::crypto::HashFunction::kSha384:
            return EVP_sha384();
        case ::score::crypto::HashFunction::kSha512:
            return EVP_sha512();
        case ::score::crypto::HashFunction::kNone:
        case ::score::crypto::HashFunction::kMd5:
        case ::score::crypto::HashFunction::kSha1:
            return nullptr;
    }
    return nullptr;
}

/// @brief The OpenSSL digest name of a hash function, for the *_ex() APIs that take a name.
/// @return e.g. "SHA256", or nullptr if this provider does not serve the hash function.
[[nodiscard]] inline constexpr const char* ToOpenSslDigestName(::score::crypto::HashFunction hash) noexcept
{
    switch (hash)
    {
        case ::score::crypto::HashFunction::kSha224:
            return "SHA224";
        case ::score::crypto::HashFunction::kSha256:
            return "SHA256";
        case ::score::crypto::HashFunction::kSha384:
            return "SHA384";
        case ::score::crypto::HashFunction::kSha512:
            return "SHA512";
        case ::score::crypto::HashFunction::kNone:
        case ::score::crypto::HashFunction::kMd5:
        case ::score::crypto::HashFunction::kSha1:
            return nullptr;
    }
    return nullptr;
}

/// @brief The OpenSSL group name of an elliptic curve.
/// @return e.g. "prime256v1" for EccCurve::kP256, or nullptr if this provider does not serve the curve.
[[nodiscard]] inline constexpr const char* ToOpenSslGroupName(::score::crypto::EccCurve curve) noexcept
{
    switch (curve)
    {
        case ::score::crypto::EccCurve::kP256:
            return "prime256v1";
        case ::score::crypto::EccCurve::kP384:
            return "secp384r1";
        case ::score::crypto::EccCurve::kP521:
            return "secp521r1";
        case ::score::crypto::EccCurve::kNone:
            return nullptr;
    }
    return nullptr;
}

/// @brief The elliptic curve named by an OpenSSL group name; the inverse of ToOpenSslGroupName.
/// @return The curve, or EccCurve::kNone if the group name is not one this provider names. The curve list is kept in
///         step with ToOpenSslGroupName by the round-trip test in openssl_algorithm_info_test.cpp.
[[nodiscard]] inline ::score::crypto::EccCurve FromOpenSslGroupName(std::string_view name) noexcept
{
    for (const auto curve :
         {::score::crypto::EccCurve::kP256, ::score::crypto::EccCurve::kP384, ::score::crypto::EccCurve::kP521})
    {
        if (name == ToOpenSslGroupName(curve))
        {
            return curve;
        }
    }
    return ::score::crypto::EccCurve::kNone;
}

/// @brief Whether the OpenSSL provider serves RSA keys of @p modulus_bits.
[[nodiscard]] inline constexpr bool IsRsaModulusSupported(std::uint16_t modulus_bits) noexcept
{
    return (modulus_bits == 2048U) || (modulus_bits == 3072U) || (modulus_bits == 4096U);
}

/// @brief The OpenSSL cipher name of a symmetric cipher row, for EVP_CIPHER_fetch().
/// @return e.g. "AES-256-CBC", or nullptr if this provider does not serve the row as a cipher.
[[nodiscard]] inline constexpr const char* ToEvpCipherName(
    const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    if (algorithm.category != ::score::crypto::AlgorithmCategory::kCipher)
    {
        return nullptr;
    }
    switch (algorithm.mode)
    {
        case ::score::crypto::CipherMode::kCbc:
            if (algorithm.key_bits == 128U)
            {
                return "AES-128-CBC";
            }
            if (algorithm.key_bits == 192U)
            {
                return "AES-192-CBC";
            }
            if (algorithm.key_bits == 256U)
            {
                return "AES-256-CBC";
            }
            return nullptr;
        case ::score::crypto::CipherMode::kNone:
        case ::score::crypto::CipherMode::kGcm:
            return nullptr;
    }
    return nullptr;
}

/// @brief Whether the OpenSSL provider serves @p algorithm as a hash.
[[nodiscard]] inline bool IsHashSupported(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    return (algorithm.category == ::score::crypto::AlgorithmCategory::kHash) && (ToEvpMd(algorithm.hash) != nullptr);
}

/// @brief Whether the OpenSSL provider serves @p algorithm as an HMAC.
///
/// CMAC rows are MACs too, but take an AES key and no hash, so they are refused.
[[nodiscard]] inline bool IsHmacSupported(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    if (algorithm.category != ::score::crypto::AlgorithmCategory::kMac)
    {
        return false;
    }
    switch (algorithm.key_type)
    {
        case ::score::crypto::KeyType::kSecret:
            return ToEvpMd(algorithm.hash) != nullptr;
        case ::score::crypto::KeyType::kNone:
        case ::score::crypto::KeyType::kAes:
        case ::score::crypto::KeyType::kEcc:
        case ::score::crypto::KeyType::kRsa:
        case ::score::crypto::KeyType::kEd25519:
            return false;
    }
    return false;
}

/// @brief Whether the OpenSSL provider serves @p algorithm for signing and verification.
///
/// ECDSA rows need a curve and a digest this provider serves; RSA-PSS rows a
/// supported modulus and digest; Ed25519 has no parameters. Key rows such as
/// "ECDSA-P256" are not signature schemes and are refused.
[[nodiscard]] inline bool IsSignatureSupported(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    if (algorithm.category != ::score::crypto::AlgorithmCategory::kSignature)
    {
        return false;
    }
    switch (algorithm.key_type)
    {
        case ::score::crypto::KeyType::kEcc:
            return (ToOpenSslGroupName(algorithm.curve) != nullptr) && (ToEvpMd(algorithm.hash) != nullptr);
        case ::score::crypto::KeyType::kRsa:
            return IsRsaModulusSupported(algorithm.key_bits) && (ToEvpMd(algorithm.hash) != nullptr);
        case ::score::crypto::KeyType::kEd25519:
            return true;
        case ::score::crypto::KeyType::kNone:
        case ::score::crypto::KeyType::kSecret:
        case ::score::crypto::KeyType::kAes:
            return false;
    }
    return false;
}

/// @brief Whether the OpenSSL provider serves @p algorithm as a random generator.
[[nodiscard]] inline constexpr bool IsRandomSupported(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    // OpenSSL's public RNG is a CTR-DRBG.
    return algorithm.id == ::score::crypto::Algorithm::kCtrDrbg;
}

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_OPENSSL_ALGORITHM_INFO_HPP
