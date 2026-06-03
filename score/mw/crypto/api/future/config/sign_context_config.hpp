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

#ifndef SCORE_MW_CRYPTO_API_CONFIG_SIGN_CONTEXT_CONFIG_HPP
#define SCORE_MW_CRYPTO_API_CONFIG_SIGN_CONTEXT_CONFIG_HPP

#include "score/mw/crypto/api/config/base_context_config.hpp"

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Configuration for signature generation context creation.
///
/// Requires an algorithm and a private key. Supports classical
/// algorithms (RSA-PSS, ECDSA) and PQC algorithms (ML-DSA-65, SLH-DSA-SHA2-128s).
///
/// @par Example
/// @code
///   SignContextConfig config;
///   config.SetAlgorithm("ML-DSA-65").SetKey(signing_key);
///   auto ctx = crypto_context->CreateSignContext(config);
/// @endcode
struct SignContextConfig : public BaseContextConfig
{
    /// @brief Handle to the private signing key (required).
    /// Must be a CryptoResourceId with type == kKey.
    CryptoResourceId key{};

    // -- Fluent builder --

    SignContextConfig& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        BaseContextConfig::SetAlgorithm(alg);
        return *this;
    }

    SignContextConfig& SetKey(const CryptoResourceId& k) noexcept
    {
        key = k;
        return *this;
    }

    SignContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        BaseContextConfig::SetProvider(prov);
        return *this;
    }

    SignContextConfig& SetProviderType(ProviderType type) noexcept
    {
        BaseContextConfig::SetProviderType(type);
        return *this;
    }

    SignContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(key, value);
        return *this;
    }
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONFIG_SIGN_CONTEXT_CONFIG_HPP
