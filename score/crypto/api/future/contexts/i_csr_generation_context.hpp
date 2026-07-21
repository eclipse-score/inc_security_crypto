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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_CSR_GENERATION_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_CSR_GENERATION_CONTEXT_HPP

#include "score/mw/crypto/api/certificate/i_csr_export.hpp"
#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/contexts/i_context.hpp"
#include "score/result/result.h"

#include <memory>
#include <string_view>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Builder-style context for Certificate Signing Request (CSR) generation.
///
/// Created via ICryptoContext::CreateCsrGenerationContext(). Configure the CSR
/// parameters via setter methods, then call Generate() to produce the CSR.
///
/// Supports both classical algorithms (RSA-PSS, ECDSA) and PQC algorithms
/// (ML-DSA-65, SLH-DSA-SHA2-128s) for CSR signing.
///
/// @par Example
/// @code
///   auto ctx = crypto_context->CreateCsrGenerationContext(config);
///   ctx.value()->SetSubjectKey(signing_key);
///   ctx.value()->SetSignatureAlgorithm("ML-DSA-65");
///   ctx.value()->SetSubjectDn("CN=MyDevice,O=Corp,C=DE");
///   ctx.value()->AddSubjectAltName("DNS:mydevice.local");
///   auto csr = ctx.value()->Generate();
/// @endcode
class ICsrGenerationContext : public IContext
{
  public:
    using Uptr = std::unique_ptr<ICsrGenerationContext>;

    ~ICsrGenerationContext() override = default;

    ICsrGenerationContext(const ICsrGenerationContext&) = delete;
    ICsrGenerationContext& operator=(const ICsrGenerationContext&) = delete;
    ICsrGenerationContext(ICsrGenerationContext&&) = default;
    ICsrGenerationContext& operator=(ICsrGenerationContext&&) = default;

    // ---- Configuration setters (call before Generate()) ----

    /// @brief Sets the key for signing the CSR.
    /// @param key Handle to the signing key (CryptoResourceId with type = kKey)
    /// @return std::monostate on success, error if key resource is invalid
    virtual score::Result<std::monostate> SetSubjectKey(const CryptoResourceId& key) = 0;

    /// @brief Sets the CSR signature algorithm.
    /// @param algorithm Algorithm identifier (e.g., "SHA-256-RSA", "ML-DSA-65")
    /// @return std::monostate on success, error if algorithm is not supported
    virtual score::Result<std::monostate> SetSignatureAlgorithm(const AlgorithmId& algorithm) = 0;

    /// @brief Sets the subject distinguished name.
    /// @param dn Subject DN string (e.g., "CN=MyDevice,O=Corp,C=DE")
    /// @return std::monostate on success
    virtual score::Result<std::monostate> SetSubjectDn(std::string_view dn) = 0;

    /// @brief Adds a Subject Alternative Name (SAN).
    /// @param san SAN entry (e.g., "DNS:mydevice.local", "IP:192.168.1.1")
    /// @return std::monostate on success
    /// @note Can be called multiple times to add multiple SANs.
    virtual score::Result<std::monostate> AddSubjectAltName(std::string_view san) = 0;

    /// @brief Sets the optional challenge password.
    /// @param password Challenge password for the CSR
    /// @return std::monostate on success
    virtual score::Result<std::monostate> SetChallengePassword(std::string_view password) = 0;

    // ---- Execution ----

    /// @brief Generates the CSR from the configured parameters.
    /// @return Export object providing access to the encoded CSR data
    /// @note At minimum, subject key, signature algorithm, and subject DN
    ///       must be set before calling Generate().
    virtual score::Result<ICsrExport::Uptr> Generate() = 0;

  protected:
    ICsrGenerationContext() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_CSR_GENERATION_CONTEXT_HPP
