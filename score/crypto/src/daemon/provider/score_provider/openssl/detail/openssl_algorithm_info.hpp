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

#include "score/crypto/src/daemon/common/algorithm_info.hpp"

#include <openssl/evp.h>

#include <cstddef>
#include <string_view>

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
        case common::HashAlgorithm::kSha1:
            return EVP_sha1();
        case common::HashAlgorithm::kMd5:
            return EVP_md5();
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

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_DETAIL_OPENSSL_ALGORITHM_INFO_HPP
