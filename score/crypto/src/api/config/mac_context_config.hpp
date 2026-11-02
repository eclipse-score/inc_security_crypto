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

#ifndef SCORE_CRYPTO_SRC_API_CONFIG_MAC_CONTEXT_CONFIG_HPP
#define SCORE_CRYPTO_SRC_API_CONFIG_MAC_CONTEXT_CONFIG_HPP

#include "score/crypto/src/api/config/base_context_config.hpp"

namespace score
{

namespace crypto
{

/// @brief Configuration for MAC context creation.
///
/// Requires an algorithm and a key. Typical algorithms include
/// HMAC-SHA256, HMAC-SHA384, AES-128-CMAC, AES-256-CMAC.
///
/// @par Example
/// @code
///   MacContextConfig config;
///   config.SetAlgorithm(Algorithm::kHmacSha256).SetKey(mac_key);  // or "HMAC-SHA256"
///   auto ctx = crypto_context->CreateMacContext(config);
/// @endcode
struct MacContextConfig : public BaseContextConfig
{
    /// @brief Handle to the MAC key (required).
    /// Must be a CryptoResourceId with type == kKey.
    CryptoResourceId key{};

    // -- Fluent builder --

    MacContextConfig& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        BaseContextConfig::SetAlgorithm(alg);
        return *this;
    }

    /// @brief Select a catalog algorithm by enumerator; stores its catalog name.
    ///
    /// A value without a catalog row (e.g. Algorithm::kUnknown) stores a name
    /// that is refused with CryptoErrorCode::kUnsupportedAlgorithm.
    MacContextConfig& SetAlgorithm(const Algorithm alg) noexcept
    {
        BaseContextConfig::SetAlgorithm(alg);
        return *this;
    }

    MacContextConfig& SetKey(const CryptoResourceId& k) noexcept
    {
        key = k;
        return *this;
    }

    MacContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        BaseContextConfig::SetProvider(prov);
        return *this;
    }

    MacContextConfig& SetProviderType(ProviderType type) noexcept
    {
        BaseContextConfig::SetProviderType(type);
        return *this;
    }

    MacContextConfig& SetOperationMode(OperationMode mode) noexcept
    {
        BaseContextConfig::SetOperationMode(mode);
        return *this;
    }

    MacContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(key, value);
        return *this;
    }
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONFIG_MAC_CONTEXT_CONFIG_HPP
