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

#ifndef SCORE_MW_CRYPTO_API_CONFIG_CIPHER_CONTEXT_CONFIG_HPP
#define SCORE_MW_CRYPTO_API_CONFIG_CIPHER_CONTEXT_CONFIG_HPP

#include "score/mw/crypto/api/common/crypto_resource_guard.hpp"
#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/config/base_context_config.hpp"

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Configuration for cipher context creation (encryption or decryption).
///
/// Requires an algorithm, a key, and a cipher direction. Typical algorithms
/// include AES-128-CBC, AES-256-CBC, AES-256-CTR, ChaCha20.
/// When provider is omitted, the daemon auto-resolves from the key's
/// underlying primary_provider.
///
/// @par Example — encryption
/// @code
///   CipherContextConfig config;
///   config.SetAlgorithm("AES-256-CBC")
///         .SetKey(key_id)
///         .SetDirection(CipherDirection::kEncrypt);
///   auto ctx = crypto_context->CreateCipherContext(config);
/// @endcode
///
/// @par Example — decryption
/// @code
///   CipherContextConfig config;
///   config.SetAlgorithm("AES-256-CBC")
///         .SetKey(key_id)
///         .SetDirection(CipherDirection::kDecrypt);
///   auto ctx = crypto_context->CreateCipherContext(config);
/// @endcode
struct CipherContextConfig : public BaseContextConfig
{
    /// @brief Handle to the cipher key (required).
    /// Must be a CryptoResourceId with type == kKey.
    CryptoResourceId key{};

    /// @brief Cipher direction: encrypt or decrypt (required).
    CipherDirection direction{CipherDirection::kEncrypt};

    // -- Fluent builder --

    CipherContextConfig& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        BaseContextConfig::SetAlgorithm(alg);
        return *this;
    }

    CipherContextConfig& SetKey(const CryptoResourceId& k) noexcept
    {
        key = k;
        return *this;
    }

    CipherContextConfig& SetDirection(CipherDirection dir) noexcept
    {
        direction = dir;
        return *this;
    }

    CipherContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        BaseContextConfig::SetProvider(prov);
        return *this;
    }

    CipherContextConfig& SetProviderType(ProviderType type) noexcept
    {
        BaseContextConfig::SetProviderType(type);
        return *this;
    }

    CipherContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(key, value);
        return *this;
    }
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONFIG_CIPHER_CONTEXT_CONFIG_HPP
