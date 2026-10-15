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

#ifndef SCORE_CRYPTO_SRC_API_CONFIG_HASH_CONTEXT_CONFIG_HPP
#define SCORE_CRYPTO_SRC_API_CONFIG_HASH_CONTEXT_CONFIG_HPP

#include "score/crypto/src/api/config/base_context_config.hpp"

namespace score
{

namespace crypto
{

/// @brief Configuration for hash context creation.
///
/// Requires only an algorithm identifier. SHA-256, SHA-384, and SHA-512 use
/// the identifiers "SHA256", "SHA384", and "SHA512", respectively.
/// Provider categories can be requested with SetProviderType(). Explicit
/// selection by a resolved provider resource is not supported.
///
/// @par Example
/// @code
///   HashContextConfig config;
///   config.SetAlgorithm("SHA256");
///   auto ctx = crypto_context->CreateHashContext(config);
/// @endcode
struct HashContextConfig : public BaseContextConfig
{

    HashContextConfig& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        BaseContextConfig::SetAlgorithm(alg);
        return *this;
    }

    HashContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        BaseContextConfig::SetProvider(prov);
        return *this;
    }

    HashContextConfig& SetProviderType(ProviderType type) noexcept
    {
        BaseContextConfig::SetProviderType(type);
        return *this;
    }

    HashContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(key, value);
        return *this;
    }
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONFIG_HASH_CONTEXT_CONFIG_HPP
