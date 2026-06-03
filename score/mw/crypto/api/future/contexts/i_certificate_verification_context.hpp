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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_CERTIFICATE_VERIFICATION_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_CERTIFICATE_VERIFICATION_CONTEXT_HPP

#include "score/mw/crypto/api/certificate/cert_types.hpp"
#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/contexts/i_context.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstdint>
#include <memory>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Builder-style context for certificate and chain verification.
///
/// Created via ICryptoContext::CreateCertificateVerificationContext().
/// Follows the same create-configure-execute pattern as other contexts
/// for uniformity. Configure the verification parameters via setter
/// methods, then call Verify() to execute.
///
/// @par Example — single certificate verification
/// @code
///   auto ctx = crypto_context->CreateCertificateVerificationContext(config).value();
///   ctx->SetCertificate(leaf_cert);
///   ctx->SetVerificationTrustStore(system_trust_store);
///   ctx->SetRevocationCheckPolicy(RevocationCheckPolicy::kOcspWithCrlFallback);
///   ctx->SetOcspResponse(ocsp_response_data);
///   auto result = ctx->Verify();
/// @endcode
///
/// @par Example — chain verification with additional trust anchors
/// @code
///   // ext_ca is a kCertificate from ParseCertificate() — not persisted.
///   std::array<CryptoResourceId, 1> extra = {ext_ca->GetId()};
///   auto ctx = crypto_context->CreateCertificateVerificationContext(config).value();
///   ctx->SetCertificateChain(chain);
///   ctx->SetVerificationTrustStore(system_trust_store);
///   ctx->SetAdditionalTrustAnchors(extra);  // local to this context, no system store change
///   auto result = ctx->Verify();
/// @endcode
class ICertificateVerificationContext : public IContext
{
  public:
    using Uptr = std::unique_ptr<ICertificateVerificationContext>;

    ~ICertificateVerificationContext() override = default;

    ICertificateVerificationContext(const ICertificateVerificationContext&) = delete;
    ICertificateVerificationContext& operator=(const ICertificateVerificationContext&) = delete;
    ICertificateVerificationContext(ICertificateVerificationContext&&) = default;
    ICertificateVerificationContext& operator=(ICertificateVerificationContext&&) = default;

    // ---- Configuration setters (call before Verify()) ----

    /// @brief Sets the leaf certificate to verify.
    /// @param cert Handle to the certificate to verify
    /// @return std::monostate on success, error if cert handle is invalid
    /// @note Mutually exclusive with SetCertificateChain().
    virtual score::Result<std::monostate> SetCertificate(const CryptoResourceId& cert) = 0;

    /// @brief Sets a certificate chain to verify (leaf first).
    /// @param chain Ordered chain of certificate handles (leaf first, root last)
    /// @return std::monostate on success, error if any handle is invalid
    /// @note Mutually exclusive with SetCertificate().
    virtual score::Result<std::monostate> SetCertificateChain(score::cpp::span<const CryptoResourceId> chain) = 0;

    /// @brief Sets the system trust store to use for certificate chain verification.
    ///
    /// The trust store is a manifest-configured named group of persistent certificate
    /// slots. Resolve it by name with ResourceType::kVerificationTrustStore.
    /// Empty slots in the store are silently skipped at verification time.
    ///
    /// @param trust_store Handle to the verification trust store
    ///        (type = kVerificationTrustStore)
    /// @return std::monostate on success, error if handle is invalid
    virtual score::Result<std::monostate> SetVerificationTrustStore(const CryptoResourceId& trust_store) = 0;

    /// @brief Supplies additional trust anchors for this verification, beyond the system trust store.
    ///
    /// Use this to trust certificates not provisioned in any system trust store —
    /// e.g. an external CA received at runtime, a rotation candidate, or a test root.
    /// Does not modify the system trust store; these roots are local to this context instance.
    ///
    /// Accepts both `kCertificate` (parsed, not persisted) and `kCertSlot` handles.
    /// The daemon validates each certificate immediately:
    /// - Expired certificates cause the whole call to fail.
    /// - Certificates already present in the configured system trust store are
    ///   accepted silently (idempotent union — no duplicate anchors).
    ///
    /// Replaces any previously set additional anchors on this context (set semantics).
    ///
    /// @param anchors Span of certificate handles (type = kCertificate or kCertSlot)
    /// @return std::monostate on success, error if any handle is invalid or any certificate has expired
    virtual score::Result<std::monostate> SetAdditionalTrustAnchors(
        score::cpp::span<const CryptoResourceId> anchors) = 0;

    /// @brief Provides an OCSP response for revocation checking.
    /// @param response_data DER-encoded OCSP response
    /// @return std::monostate on success, error on parse failure
    /// @note The context internally validates the OCSP responder's certificate
    ///       chain against the configured verification trust store.
    virtual score::Result<std::monostate> SetOcspResponse(score::cpp::span<const uint8_t> response_data) = 0;

    /// @brief References an imported CRL for revocation checking.
    /// @param crl Handle to a previously imported CRL
    /// @return std::monostate on success, error if handle is invalid
    virtual score::Result<std::monostate> SetCrl(const CryptoResourceId& crl) = 0;

    /// @brief Overrides the verification time.
    /// @param epoch_seconds Verification time as seconds since Unix epoch
    /// @return std::monostate on success
    /// @note Default: current system time. Use this for testing or for
    ///       verifying certificates at a specific point in time.
    virtual score::Result<std::monostate> SetVerificationTime(int64_t epoch_seconds) = 0;

    /// @brief Sets the revocation checking strategy.
    /// @param policy The revocation check policy to apply
    /// @return std::monostate on success
    /// @note Overrides the default policy set in the config.
    virtual score::Result<std::monostate> SetRevocationCheckPolicy(RevocationCheckPolicy policy) = 0;

    // ---- Execution ----

    /// @brief Executes the configured certificate verification.
    /// @return Verification result indicating validity or failure reason
    /// @note At minimum, a certificate (or chain) and trust anchor must be set.
    virtual score::Result<CertVerifyResult> Verify() = 0;

  protected:
    ICertificateVerificationContext() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_CERTIFICATE_VERIFICATION_CONTEXT_HPP
