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

#ifndef SCORE_MW_CRYPTO_API_CONFIG_CERTIFICATE_CONTEXT_CONFIG_HPP
#define SCORE_MW_CRYPTO_API_CONFIG_CERTIFICATE_CONTEXT_CONFIG_HPP

#include "score/mw/crypto/api/config/base_context_config.hpp"

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Configuration for certificate management context creation.
///
/// Provider is optional — certificate operations use the provider
/// associated with each certificate's storage or the signing key's
/// primary_provider as appropriate. Setting a provider explicitly
/// scopes all certificate operations to that provider.
///
/// @par Example
/// @code
///   CertificateContextConfig config;
///   auto ctx = crypto_context->CreateCertificateManagementContext(config);
/// @endcode
struct CertificateContextConfig : public BaseContextConfig
{
    // -- Fluent builder --

    CertificateContextConfig& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        BaseContextConfig::SetAlgorithm(alg);
        return *this;
    }

    CertificateContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        BaseContextConfig::SetProvider(prov);
        return *this;
    }

    CertificateContextConfig& SetProviderType(ProviderType type) noexcept
    {
        BaseContextConfig::SetProviderType(type);
        return *this;
    }

    CertificateContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(key, value);
        return *this;
    }
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONFIG_CERTIFICATE_CONTEXT_CONFIG_HPP
