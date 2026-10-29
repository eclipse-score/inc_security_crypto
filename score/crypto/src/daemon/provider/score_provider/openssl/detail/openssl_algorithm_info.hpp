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

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>

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

/// @brief Look up the EVP_MD for a hash algorithm name.
/// @return EVP_MD pointer, or nullptr if the algorithm is not supported.
[[nodiscard]] inline const EVP_MD* LookupHashEVPMD(std::string_view algorithm) noexcept
{
    const auto info = common::LookupHashAlgorithmInfo(algorithm);
    if (!info.has_value())
    {
        return nullptr;
    }

    switch (info->algorithm)
    {
        case common::HashAlgorithm::kSha256:
            return EVP_sha256();
        case common::HashAlgorithm::kSha384:
            return EVP_sha384();
        case common::HashAlgorithm::kSha512:
            return EVP_sha512();
        case common::HashAlgorithm::kSha224:
            return EVP_sha224();
    }
    return nullptr;
}

/// @brief Look up the EVP_MD for an HMAC algorithm name.
/// @return EVP_MD pointer, or nullptr if the algorithm is not supported.
[[nodiscard]] inline const EVP_MD* LookupHmacEVPMD(std::string_view algorithm) noexcept
{
    const auto info = common::LookupMacAlgorithmInfo(algorithm);
    if (!info.has_value())
    {
        return nullptr;
    }

    // Keep this switch exhaustive and without a default case so adding a
    // provider-neutral algorithm requires an explicit OpenSSL support decision.
    switch (info->algorithm)
    {
        case common::MacAlgorithm::kHmacSha256:
            return EVP_sha256();
        case common::MacAlgorithm::kHmacSha384:
            return EVP_sha384();
        case common::MacAlgorithm::kHmacSha512:
            return EVP_sha512();
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

/// @brief Configure RSA-PSS padding, salt length and MGF1 digest on a raw EVP_PKEY_CTX.
/// @return false if the context, digest, or any RSA-PSS parameter could not be set.
[[nodiscard]] inline bool ConfigureRsaPssPkeyContext(EVP_PKEY_CTX* pkey_context,
                                                     const EVP_MD* digest,
                                                     int salt_length) noexcept
{
    return pkey_context != nullptr && digest != nullptr &&
           EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_PSS_PADDING) == 1 &&
           EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_context, salt_length) == 1 &&
           EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_context, digest) == 1;
}

/// @brief Configure an initialized OpenSSL digest-sign/verify context for RSA-PSS.
/// @param salt_length RSA_PSS_SALTLEN_DIGEST for signing (fixed per RFC 8017 §9.1); RSA_PSS_SALTLEN_AUTO
///        for verification, so signatures using any legal salt length are accepted.
/// @return an initialization error if the context or any RSA-PSS parameter could not be configured.
[[nodiscard]] inline ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
ConfigureRsaPssContext(EVP_MD_CTX* context, std::string_view algorithm, int salt_length) noexcept
{
    EVP_PKEY_CTX* pkey_context = context == nullptr ? nullptr : EVP_MD_CTX_get_pkey_ctx(context);
    const auto digest_name = ::score::crypto::daemon::common::LookupSignatureDigest(algorithm);
    const EVP_MD* digest = digest_name.has_value() ? LookupHashEVPMD(digest_name.value()) : nullptr;
    if (!ConfigureRsaPssPkeyContext(pkey_context, digest, salt_length))
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kAlgorithmInitializationFailed);
    }
    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_OPENSSL_ALGORITHM_INFO_HPP
