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

#ifndef SCORE_CRYPTO_SRC_API_CONFIG_TRUST_STORE_MANAGEMENT_CONTEXT_CONFIG_HPP
#define SCORE_CRYPTO_SRC_API_CONFIG_TRUST_STORE_MANAGEMENT_CONTEXT_CONFIG_HPP

#include "score/crypto/src/api/config/base_context_config.hpp"

namespace score
{

namespace crypto
{

/// @brief Configuration for trust-store management context creation.
///
/// Provider selection is optional. Trust-store management uses the
/// certificate-management provider capability and the CERT:TRUST_STORE
/// context type.
struct TrustStoreManagementContextConfig : public BaseContextConfig
{
    TrustStoreManagementContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        BaseContextConfig::SetProvider(prov);
        return *this;
    }

    TrustStoreManagementContextConfig& SetProviderType(ProviderType type) noexcept
    {
        BaseContextConfig::SetProviderType(type);
        return *this;
    }

    TrustStoreManagementContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(key, value);
        return *this;
    }
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONFIG_TRUST_STORE_MANAGEMENT_CONTEXT_CONFIG_HPP
