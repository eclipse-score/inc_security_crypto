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

#ifndef SCORE_MW_CRYPTO_API_CONFIG_KEY_MANAGEMENT_CONTEXT_CONFIG_HPP
#define SCORE_MW_CRYPTO_API_CONFIG_KEY_MANAGEMENT_CONTEXT_CONFIG_HPP

#include "score/mw/crypto/api/config/base_context_config.hpp"

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Configuration for key management context creation.
///
/// Provider is optional — operations will use the provider associated
/// with each key's CryptoResourceId::primary_provider as needed.
/// Setting a provider explicitly scopes all key management operations
/// to that specific provider.
///
/// @par Example
/// @code
///   KeyManagementContextConfig config;
///   config.SetProviderType(ProviderType::kHardware);
///   auto ctx = crypto_context->CreateKeyManagementContext(config);
/// @endcode
struct KeyManagementContextConfig : public BaseContextConfig
{
    // -- Fluent builder --

    KeyManagementContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        BaseContextConfig::SetProvider(prov);
        return *this;
    }

    KeyManagementContextConfig& SetProviderType(ProviderType type) noexcept
    {
        BaseContextConfig::SetProviderType(type);
        return *this;
    }

    KeyManagementContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(key, value);
        return *this;
    }
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONFIG_KEY_MANAGEMENT_CONTEXT_CONFIG_HPP
