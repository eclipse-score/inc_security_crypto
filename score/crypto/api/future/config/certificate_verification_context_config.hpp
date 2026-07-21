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

#ifndef SCORE_MW_CRYPTO_API_CONFIG_CERTIFICATE_VERIFICATION_CONTEXT_CONFIG_HPP
#define SCORE_MW_CRYPTO_API_CONFIG_CERTIFICATE_VERIFICATION_CONTEXT_CONFIG_HPP

#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/config/base_context_config.hpp"

#include <optional>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Configuration for certificate verification context creation.
///
/// Provider is optional — certificate verification uses the provider
/// associated with the certificate's signing key. Setting a provider
/// explicitly scopes the verification to that provider.
///
/// An optional default RevocationCheckPolicy can be set at config time;
/// it can be overridden per-verification via SetRevocationCheckPolicy()
/// on the context itself.
///
/// @par Example
/// @code
///   CertificateVerificationContextConfig config;
///   config.SetRevocationPolicy(RevocationCheckPolicy::kOcspWithCrlFallback);
///   auto ctx = crypto_context->CreateCertificateVerificationContext(config);
///   ctx->SetCertificate(cert);
///   ctx->SetVerificationTrustStore(trust_anchor);
///   auto result = ctx->Verify();
/// @endcode
struct CertificateVerificationContextConfig : public BaseContextConfig
{
    /// @brief Default revocation check policy for verifications using this context.
    std::optional<RevocationCheckPolicy> revocation_policy{std::nullopt};

    // -- Fluent builder --

    CertificateVerificationContextConfig& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        BaseContextConfig::SetAlgorithm(alg);
        return *this;
    }

    CertificateVerificationContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        BaseContextConfig::SetProvider(prov);
        return *this;
    }

    CertificateVerificationContextConfig& SetProviderType(ProviderType type) noexcept
    {
        BaseContextConfig::SetProviderType(type);
        return *this;
    }

    CertificateVerificationContextConfig& SetRevocationPolicy(RevocationCheckPolicy policy) noexcept
    {
        revocation_policy = policy;
        return *this;
    }

    CertificateVerificationContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(key, value);
        return *this;
    }
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONFIG_CERTIFICATE_VERIFICATION_CONTEXT_CONFIG_HPP
