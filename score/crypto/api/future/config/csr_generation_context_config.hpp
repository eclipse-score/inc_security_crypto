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

#ifndef SCORE_MW_CRYPTO_API_CONFIG_CSR_GENERATION_CONTEXT_CONFIG_HPP
#define SCORE_MW_CRYPTO_API_CONFIG_CSR_GENERATION_CONTEXT_CONFIG_HPP

#include "score/mw/crypto/api/config/base_context_config.hpp"

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Configuration for CSR generation context creation.
///
/// Provider is optional — CSR generation uses the provider associated
/// with the signing key's primary_provider. Setting a provider explicitly
/// scopes the CSR generation to that provider.
///
/// @par Example
/// @code
///   CsrGenerationContextConfig config;
///   auto ctx = crypto_context->CreateCsrGenerationContext(config);
///   ctx->SetSubjectKey(signing_key);
///   ctx->SetSignatureAlgorithm("ML-DSA-65");
///   ctx->SetSubjectDn("CN=MyDevice,O=Corp,C=DE");
///   auto csr = ctx->Generate();
/// @endcode
struct CsrGenerationContextConfig : public BaseContextConfig
{
    // -- Fluent builder --

    CsrGenerationContextConfig& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        BaseContextConfig::SetAlgorithm(alg);
        return *this;
    }

    CsrGenerationContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        BaseContextConfig::SetProvider(prov);
        return *this;
    }

    CsrGenerationContextConfig& SetProviderType(ProviderType type) noexcept
    {
        BaseContextConfig::SetProviderType(type);
        return *this;
    }

    CsrGenerationContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(key, value);
        return *this;
    }
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONFIG_CSR_GENERATION_CONTEXT_CONFIG_HPP
