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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_I_CERTIFICATE_VERIFICATION_CONTEXT_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_I_CERTIFICATE_VERIFICATION_CONTEXT_HPP

#include "score/crypto/src/api/certificate/cert_types.hpp"
#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/api/contexts/i_context.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstdint>
#include <memory>

namespace score
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
///   ctx->SetRevocationCheckPolicy(RevocationCheckPolicy::kCrlOnly);
///   auto result = ctx->Verify();
/// @endcode
///
/// @par Example — chain verification with additional untrusted certificates
/// @code
///   // ext_ca is a kCertificate from ParseCertificate() — not persisted.
///   std::array<CryptoResourceId, 1> extra = {ext_ca->GetId()};
///   auto ctx = crypto_context->CreateCertificateVerificationContext(config).value();
///   ctx->SetCertificateChain(chain);
///   ctx->SetVerificationTrustStore(system_trust_store);
///   ctx->SetAdditionalCertificates(extra);  // untrusted chain-building inputs
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

    /// @brief Sets the standalone trusted certificates for this verification context.
    ///
    /// This mode is mutually exclusive with SetVerificationTrustStore(). Each
    /// call replaces the previously configured set, so callers that discover
    /// anchors incrementally must collect them before calling this method.
    ///
    /// @param certs Span of certificate handles to treat as trust anchors
    ///        (type = kCertificate or kCertSlot)
    /// @return std::monostate on success, error if any handle is invalid
    virtual score::Result<std::monostate> SetTrustedCertificates(
        score::cpp::span<const CryptoResourceId> certs) = 0;

    /// @brief Selects the chain termination rule for trust-store verification.
    ///
    /// The default is ChainTerminationPolicy::kRootRequired. This setting has
    /// no effect in standalone trusted-certificate mode.
    virtual score::Result<std::monostate> SetChainTerminationPolicy(ChainTerminationPolicy policy) = 0;

    /// @brief Supplies additional untrusted certificates for chain building.
    ///
    /// Use this for intermediate certificates that are not provisioned in the
    /// system trust store, such as an intermediate received with a peer chain.
    /// These certificates are local to this context and do not establish trust.
    ///
    /// Accepts `kCertificate` and `kCertSlot` handles. Certificates already
    /// present in the trust store are deduplicated by fingerprint. The daemon
    /// uses these objects only as untrusted chain-building inputs; trust is
    /// established exclusively by the configured trust store or standalone
    /// trusted certificates.
    ///
    /// Replaces any previously set additional certificates on this context.
    ///
    /// @param certificates Span of untrusted certificate handles
    ///        (type = kCertificate or kCertSlot)
    /// @return std::monostate on success, or an error if a handle is invalid
    virtual score::Result<std::monostate> SetAdditionalCertificates(
      score::cpp::span<const CryptoResourceId> certificates) = 0;

    // ---- OCSP (not yet active — IPC implementation pending) ----
#if 0
    /// @brief Provides one or more OCSP responses for revocation checking.
    ///
    /// Each entry is a DER-encoded OCSP response. Supplying multiple responses
    /// covers chains where both the leaf and one or more intermediates have
    /// stapled OCSP responses (e.g. TLS 1.3 certificate_status records).
    /// The daemon matches each response to the appropriate certificate in the
    /// chain by the certID field embedded in the response; order does not matter.
    /// Replaces any previously set responses on this context.
    ///
    /// @param responses Span of DER-encoded OCSP response byte spans
    /// @return std::monostate on success, error if any response fails to parse
    virtual score::Result<std::monostate> SetOcspResponses(
        score::cpp::span<const score::cpp::span<const uint8_t>> responses) = 0;
#endif  // OCSP

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

    /// @brief Returns the number of certificates in the verified chain.
    ///
    /// Valid only after a successful Verify() call. The length is stable between
    /// this call and GetVerifiedChain() provided no intervening Verify() is made.
    ///
    /// @return Number of entries in the chain (leaf to terminating anchor inclusive),
    ///         or an error if Verify() has not yet succeeded.
    virtual score::Result<std::size_t> GetVerifiedChainLength() const = 0;

    /// @brief Fills caller-provided buffer with verified chain certificate IDs.
    ///
    /// Certificates are ordered leaf-first, terminating anchor last.
    /// The caller must size @p out to at least GetVerifiedChainLength() entries.
    ///
    /// @param out Caller-allocated span of CryptoResourceId to fill
    /// @return Number of entries written, or an error if @p out is too small
    ///         or Verify() has not yet succeeded.
    virtual score::Result<std::size_t> GetVerifiedChain(score::cpp::span<CryptoResourceId> out) const = 0;

  protected:
    ICertificateVerificationContext() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_I_CERTIFICATE_VERIFICATION_CONTEXT_HPP
