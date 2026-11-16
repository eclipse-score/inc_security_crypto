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

#ifndef SCORE_CRYPTO_SRC_API_CONFIG_CSR_GENERATION_CONTEXT_CONFIG_HPP
#define SCORE_CRYPTO_SRC_API_CONFIG_CSR_GENERATION_CONTEXT_CONFIG_HPP

#include "score/crypto/src/api/config/base_context_config.hpp"

namespace score::crypto
{
/// Key and signature algorithm are required and bound at creation, not at Generate().
/// Use a new context to change either. Provider support is checked by the daemon.
struct CsrGenerationContextConfig : BaseContextConfig
{
    CryptoResourceId key{};
    std::string submission_url{};

    CsrGenerationContextConfig& SetKey(const CryptoResourceId& value) noexcept
    {
        key = value;
        return *this;
    }
    CsrGenerationContextConfig& SetAlgorithm(const AlgorithmId& value) noexcept
    {
        algorithm = value;
        return *this;
    }
    CsrGenerationContextConfig& SetProvider(const CryptoResourceId& value) noexcept
    {
        provider = value;
        return *this;
    }
    CsrGenerationContextConfig& SetProviderType(ProviderType value) noexcept
    {
        provider_type = value;
        return *this;
    }
    CsrGenerationContextConfig& SetSubmissionUrl(std::string_view value)
    {
        submission_url = value;
        return *this;
    }
    CsrGenerationContextConfig& SetExtendedParameter(const std::string& name, const std::string& value)
    {
        BaseContextConfig::SetExtendedParameter(name, value);
        return *this;
    }
    CsrGenerationContextConfig& SetOperationTimeout(std::chrono::milliseconds value)
    {
        BaseContextConfig::SetOperationTimeout(value);
        return *this;
    }
    CsrGenerationContextConfig& DisableTimeout() noexcept
    {
        BaseContextConfig::DisableTimeout();
        return *this;
    }
    CsrGenerationContextConfig& EnableTimeout() noexcept
    {
        BaseContextConfig::EnableTimeout();
        return *this;
    }
};
}  // namespace score::crypto
#endif  // SCORE_CRYPTO_SRC_API_CONFIG_CSR_GENERATION_CONTEXT_CONFIG_HPP
