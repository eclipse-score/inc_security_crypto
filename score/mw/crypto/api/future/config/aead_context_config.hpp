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

#ifndef SCORE_MW_CRYPTO_API_CONFIG_AEAD_CONTEXT_CONFIG_HPP
#define SCORE_MW_CRYPTO_API_CONFIG_AEAD_CONTEXT_CONFIG_HPP

#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/config/base_context_config.hpp"

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Configuration for AEAD context creation.
///
/// Requires an algorithm, key, and cipher direction. Typical algorithms
/// include AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.
///
/// @par Example
/// @code
///   AeadContextConfig config;
///   config.SetAlgorithm("AES-256-GCM")
///         .SetKey(aead_key)
///         .SetDirection(CipherDirection::kEncrypt);
///   auto ctx = crypto_context->CreateAeadContext(config);
/// @endcode
struct AeadContextConfig : public BaseContextConfig
{
    /// @brief Handle to the AEAD key (required).
    /// Must be a CryptoResourceId with type == kKey.
    CryptoResourceId key{};

    /// @brief Cipher direction: encrypt or decrypt (required).
    CipherDirection direction{CipherDirection::kEncrypt};

    // -- Fluent builder --

    AeadContextConfig& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        BaseContextConfig::SetAlgorithm(alg);
        return *this;
    }

    AeadContextConfig& SetKey(const CryptoResourceId& k) noexcept
    {
        key = k;
        return *this;
    }

    AeadContextConfig& SetDirection(CipherDirection dir) noexcept
    {
        direction = dir;
        return *this;
    }

    AeadContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        BaseContextConfig::SetProvider(prov);
        return *this;
    }

    AeadContextConfig& SetProviderType(ProviderType type) noexcept
    {
        BaseContextConfig::SetProviderType(type);
        return *this;
    }

    AeadContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(key, value);
        return *this;
    }
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONFIG_AEAD_CONTEXT_CONFIG_HPP
