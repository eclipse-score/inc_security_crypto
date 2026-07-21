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

#ifndef SCORE_MW_CRYPTO_API_CONFIG_RANDOM_CONTEXT_CONFIG_HPP
#define SCORE_MW_CRYPTO_API_CONFIG_RANDOM_CONTEXT_CONFIG_HPP

#include "score/mw/crypto/api/config/base_context_config.hpp"

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Configuration for random number generation context creation.
///
/// Algorithm is optional — when omitted, the daemon selects the default
/// RNG source. Provider preference can be used to request hardware
/// entropy sources (e.g., TRNG) when available.
///
/// @par Example
/// @code
///   RandomContextConfig config;
///   config.SetProviderType(ProviderType::kHardwarePreferred);
///   auto ctx = crypto_context->CreateRandomContext(config);
/// @endcode
struct RandomContextConfig : public BaseContextConfig
{
    // -- Fluent builder --

    RandomContextConfig& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        BaseContextConfig::SetAlgorithm(alg);
        return *this;
    }

    RandomContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        BaseContextConfig::SetProvider(prov);
        return *this;
    }

    RandomContextConfig& SetProviderType(ProviderType type) noexcept
    {
        BaseContextConfig::SetProviderType(type);
        return *this;
    }

    RandomContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(key, value);
        return *this;
    }
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONFIG_RANDOM_CONTEXT_CONFIG_HPP
