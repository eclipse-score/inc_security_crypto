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

#include <openssl/evp.h>

#include <cstddef>
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

/// @brief Algorithm → OpenSSL EVP_MD mapping entry.
struct OpensslDigestInfo
{
    std::string_view name;
    const EVP_MD* (*evp_md_fn)();  ///< Function pointer returning the EVP_MD (avoids static init order)
};

/// @brief Static table of supported hash algorithms and their OpenSSL EVP_MD providers.
inline const OpensslDigestInfo kDigestAlgorithms[] = {
    {"SHA256", EVP_sha256},
    {"SHA384", EVP_sha384},
    {"SHA512", EVP_sha512},
    {"SHA224", EVP_sha224},
    {"SHA1", EVP_sha1},
    {"MD5", EVP_md5},
};

/// @brief Look up the EVP_MD for a hash algorithm name.
/// @return EVP_MD pointer, or nullptr if the algorithm is not supported.
[[nodiscard]] inline const EVP_MD* LookupHashEVPMD(std::string_view algorithm) noexcept
{
    for (const auto& entry : kDigestAlgorithms)
    {
        if (entry.name == algorithm)
        {
            return entry.evp_md_fn();
        }
    }
    return nullptr;
}

/// @brief Algorithm → OpenSSL EVP_MD mapping for HMAC algorithms.
///
/// HMAC algorithms use the same EVP_MD as their underlying digest.
/// The algorithm name is the HMAC-prefixed form (e.g. "HMAC-SHA256").
struct OpensslHmacInfo
{
    std::string_view name;
    const EVP_MD* (*evp_md_fn)();
};

inline const OpensslHmacInfo kHmacAlgorithms[] = {
    {"HMAC-SHA256", EVP_sha256},
    {"HMAC-SHA384", EVP_sha384},
    {"HMAC-SHA512", EVP_sha512},
};

/// @brief Look up the EVP_MD for an HMAC algorithm name.
/// @return EVP_MD pointer, or nullptr if the algorithm is not supported.
[[nodiscard]] inline const EVP_MD* LookupHmacEVPMD(std::string_view algorithm) noexcept
{
    for (const auto& entry : kHmacAlgorithms)
    {
        if (entry.name == algorithm)
        {
            return entry.evp_md_fn();
        }
    }
    return nullptr;
}

/// @brief Symmetric cipher identifiers the OpenSSL provider serves.
inline constexpr std::string_view kSupportedCiphers[] = {
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
};

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

/// @brief Signature scheme identifiers the OpenSSL provider serves.
///
/// Each entry names the curve and the digest; the bare key form ("ECDSA-P256")
/// is a key algorithm, not a signature scheme, and is absent on purpose.
inline constexpr std::string_view kSupportedSignatureAlgorithms[] = {
    "ECDSA-P256-SHA256",
    "ECDSA-P384-SHA384",
    "ECDSA-P521-SHA512",
};

/// @brief Whether the OpenSSL provider serves @p algorithm for signing and verification.
[[nodiscard]] inline constexpr bool IsSignatureAlgorithmSupported(std::string_view algorithm) noexcept
{
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
