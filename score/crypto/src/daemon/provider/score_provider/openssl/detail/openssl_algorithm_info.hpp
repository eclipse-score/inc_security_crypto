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

#include "score/crypto/src/api/types/algorithm.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"

#include <openssl/evp.h>

#include <cstddef>
#include <optional>
#include <string_view>

// The common algorithm tables in daemon/common/algorithm_info.hpp hold the
// provider-neutral properties (key, block, IV and field sizes). The lists in
// this header say which of those algorithms the OpenSSL provider serves. Both
// have to agree for an algorithm to be accepted: the common table supplies the
// properties the handler bases read, and the list here is the gate, so a row
// added to the common table does not enable an algorithm this provider has
// never been taught.

namespace score::crypto::daemon::provider::openssl::detail
{

/// @brief The EVP_MD the OpenSSL provider uses for a hash function.
/// @return EVP_MD pointer, or nullptr if this provider does not serve the hash function.
[[nodiscard]] inline const EVP_MD* ToEvpMd(::score::crypto::HashFunction hash) noexcept
{
    // Keep this switch exhaustive and without a default case so a hash function
    // added to the catalog requires an explicit OpenSSL support decision.
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

/// @brief Look up the EVP_MD for a hash algorithm name.
/// @return EVP_MD pointer, or nullptr if the algorithm is not supported.
[[nodiscard]] inline const EVP_MD* LookupHashEVPMD(std::string_view algorithm) noexcept
{
    const auto hash = common::LookupHashFunction(algorithm);
    return hash.has_value() ? ToEvpMd(*hash) : nullptr;
}

/// @brief Look up the EVP_MD for an HMAC algorithm name.
/// @return EVP_MD pointer, or nullptr if the algorithm is not supported.
[[nodiscard]] inline const EVP_MD* LookupHmacEVPMD(std::string_view algorithm) noexcept
{
    const auto hash = common::LookupHmacHashFunction(algorithm);
    return hash.has_value() ? ToEvpMd(*hash) : nullptr;
}

/// @brief Look up the OpenSSL canonical group name for a provider-neutral EC curve.
/// @return e.g. "prime256v1" for "P256", or nullopt if the curve is not supported.
[[nodiscard]] inline constexpr std::optional<std::string_view> LookupOpenSslGroupName(
    std::string_view curve_name) noexcept
{
    if (curve_name == "P256")
    {
        return "prime256v1";
    }
    if (curve_name == "P384")
    {
        return "secp384r1";
    }
    if (curve_name == "P521")
    {
        return "secp521r1";
    }
    return std::nullopt;
}

/// @brief Symmetric cipher identifiers the OpenSSL provider serves.
inline constexpr std::string_view kSupportedCiphers[] = {
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
};
static_assert(common::AllInCatalog(kSupportedCiphers, ::score::crypto::AlgorithmCategory::kCipher),
              "every OpenSSL cipher must be a cipher in score::crypto::kAlgorithmCatalog");

/// @brief Whether the OpenSSL provider serves @p algorithm as a cipher.
[[nodiscard]] inline constexpr bool IsCipherSupported(std::string_view algorithm) noexcept
{
    for (const auto& name : kSupportedCiphers)
    {
        if (name == algorithm)
        {
            return true;
        }
    }
    return false;
}

/// @brief Signature scheme identifiers the OpenSSL provider serves, apart from ECDSA.
///
/// ECDSA is served for every "ECDSA-<curve>-<hash>" whose hash ToEvpMd()
/// accepts; see IsSignatureAlgorithmSupported().
inline constexpr std::string_view kSupportedSignatureAlgorithms[] = {
    "RSA-PSS-2048-SHA256",
    "RSA-PSS-2048-SHA384",
    "RSA-PSS-2048-SHA512",
    "RSA-PSS-3072-SHA256",
    "RSA-PSS-3072-SHA384",
    "RSA-PSS-3072-SHA512",
    "RSA-PSS-4096-SHA256",
    "RSA-PSS-4096-SHA384",
    "RSA-PSS-4096-SHA512",
    "Ed25519",
};
static_assert(common::AllInCatalog(kSupportedSignatureAlgorithms, ::score::crypto::AlgorithmCategory::kSignature),
              "every OpenSSL signature scheme must be a signature scheme in score::crypto::kAlgorithmCatalog");

/// @brief Whether the OpenSSL provider serves @p algorithm for signing and verification.
///
/// The bare ECDSA key form ("ECDSA-P256") names no digest and is a key
/// algorithm, not a signature scheme.
[[nodiscard]] inline bool IsSignatureAlgorithmSupported(std::string_view algorithm) noexcept
{
    if (const auto ecdsa = common::ParseEcdsaName(algorithm); ecdsa.has_value())
    {
        return ecdsa->digest.has_value() && (LookupHashEVPMD(*ecdsa->digest) != nullptr);
    }
    for (const auto& name : kSupportedSignatureAlgorithms)
    {
        if (name == algorithm)
        {
            return true;
        }
    }
    return false;
}

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_OPENSSL_ALGORITHM_INFO_HPP
