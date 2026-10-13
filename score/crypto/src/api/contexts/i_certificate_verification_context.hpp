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

#include "score/crypto/src/api/contexts/i_context.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
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
///   std::array<CryptoResourceId, 1> extra = {ext_ca.Id()};
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
    /// @note Replaces the certificate or chain configured on this context.
    virtual score::Result<std::monostate> SetCertificate(const CryptoResourceId& cert) = 0;

    /// @brief Sets a certificate chain to verify (leaf first).
    /// @param chain Ordered chain of certificate handles (leaf first, root last)
    /// @return std::monostate on success, error if any handle is invalid
    /// @note Replaces the certificate or chain configured on this context.
    virtual score::Result<std::monostate> SetCertificateChain(score::cpp::span<const CryptoResourceId> chain) = 0;

    /// @brief Sets the system trust store to use for certificate chain verification.
    ///
    /// The trust store is a manifest-configured named group of persistent certificate
    /// slots. Resolve it by name with ResourceType::kCertificateTrustStore.
    /// Empty slots in the store are silently skipped at verification time.
    ///
    /// @param trust_store Handle to the verification trust store
    ///        (type = kCertificateTrustStore)
    /// @return std::monostate on success, error if handle is invalid
    virtual score::Result<std::monostate> SetVerificationTrustStore(const CryptoResourceId& trust_store) = 0;

    /// @brief Sets explicit trusted certificates for this verification context.
    ///
    /// When a verification trust store is configured, these certificates are
    /// added to the trust-store anchors. Without a trust store, they form the
    /// complete standalone trust-anchor set. Each call replaces only the
    /// explicitly configured certificates.
    ///
    /// @param certs Span of certificate handles to treat as trust anchors
    ///        (type = kCertificate or kCertSlot)
    /// @return std::monostate on success, error if any handle is invalid
    virtual score::Result<std::monostate> SetTrustedCertificates(score::cpp::span<const CryptoResourceId> certs) = 0;

    /// @brief Selects the chain termination rule for configured-anchor verification.
    ///
    /// The default is ChainTerminationPolicy::kRootRequired. With
    /// kTrustStoreTerminated, verification stops at the first certificate in
    /// the effective trust-anchor set, including explicit trusted certificates.
    /// @param policy Rule for where the verified chain may terminate.
    /// @return std::monostate on success, or an error if the policy cannot be applied.
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
    /// Replaces the additional certificates configured on this context.
    ///
    /// @param certificates Span of untrusted certificate handles
    ///        (type = kCertificate or kCertSlot)
    /// @return std::monostate on success, or an error if a handle is invalid
    virtual score::Result<std::monostate> SetAdditionalCertificates(
        score::cpp::span<const CryptoResourceId> certificates) = 0;

    // ---- OCSP ----
#if 0
    /// @brief Provides one or more OCSP responses for revocation checking.
    ///
    /// Each entry is a DER-encoded OCSP response. Supplying multiple responses
    /// covers chains where both the leaf and one or more intermediates have
    /// stapled OCSP responses (e.g. TLS 1.3 certificate_status records).
    /// The daemon matches each response to the appropriate certificate in the
    /// chain by the certID field embedded in the response; order does not matter.
    /// Replaces the OCSP responses configured on this context.
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

    /// @brief Sets the evidence-coverage behavior for subsequent verification attempts.
    /// @param policy Fail closed when required fresh evidence is unavailable, or continue best-effort.
    /// @return std::monostate on success.
    /// @note Defaults to the policy in CertificateVerificationContextConfig, which is kFailClosed.
    virtual score::Result<std::monostate> SetRevocationCoveragePolicy(RevocationCoveragePolicy policy) = 0;

    /// @brief Selects which evidence is retained for the verification attempt.
    /// @note The default is kNone. Configure before Verify(). With kChainAndCrl,
    ///       selected CRL metadata can be queried after either a valid or failed
    ///       verification result.
    /// @param mode Evidence to retain for this verification attempt.
    /// @return std::monostate on success, or an error if the mode is unsupported.
    virtual score::Result<std::monostate> SetEvidenceMode(VerificationEvidenceMode mode) = 0;

    // ---- Execution ----

    /// @brief Executes the configured certificate verification.
    ///
    /// A completed verification returns a `CertVerifyResult`, including for
    /// negative outcomes such as expiration, revocation, or an untrusted chain.
    /// Only `CertVerifyResult::kValid` means the certificate passed the checks
    /// that ran. If verification cannot be performed or completed, this returns
    /// an error result carrying a `CryptoErrorCode` instead of an outcome value.
    /// @return Verification outcome when evaluation completes, or a `CryptoErrorCode`
    ///         if verification cannot be performed or completed.
    /// @note At minimum, a certificate (or chain) and trust anchor must be set.
    virtual score::Result<CertVerifyResult> Verify() = 0;

    /// @brief Returns the number of certificates in the verified chain.
    /// @return Number of certificates, or an error before Verify().
    virtual score::Result<std::size_t> GetVerifiedChainCertificateCount() const = 0;

    /// @brief Returns the encoded size of the verified chain.
    ///
    /// Certificates are ordered leaf-first. PEM output is a concatenated PEM
    /// chain; DER output is concatenated DER certificates in the same order.
    /// @param format Encoding to use for the exported chain.
    /// @return Required output-buffer size in bytes, or an error if no verified
    ///         chain is available.
    virtual score::Result<std::size_t> GetVerifiedChainExportSize(FormatType format) const = 0;

    /// @brief Exports the verified chain in leaf-first order.
    /// @param format Encoding to use for the exported chain.
    /// @param out Caller-provided buffer; size it using GetVerifiedChainExportSize().
    /// @return Number of bytes written, or an error if the buffer is too small
    ///         or no verified chain is available.
    virtual score::Result<std::size_t> ExportVerifiedChain(FormatType format, score::cpp::span<uint8_t> out) const = 0;

    /// @brief Returns the encoded size of one certificate in the verified chain.
    /// @param index Zero-based index in the leaf-first verified chain.
    /// @param format Encoding to use for the certificate.
    /// @return Required output-buffer size in bytes, or an error if the index is
    ///         invalid or no verified chain is available.
    virtual score::Result<std::size_t> GetVerifiedCertificateExportSize(std::size_t index, FormatType format) const = 0;

    /// @brief Exports one certificate from the verified chain.
    /// @param index Zero-based index in the leaf-first verified chain.
    /// @param format Encoding to use for the certificate.
    /// @param out Caller-provided buffer; size it using GetVerifiedCertificateExportSize().
    /// @return Number of bytes written, or an error if the index is invalid,
    ///         the buffer is too small, or no verified chain is available.
    virtual score::Result<std::size_t> ExportVerifiedCertificate(std::size_t index,
                                                                 FormatType format,
                                                                 score::cpp::span<uint8_t> out) const = 0;

    /// @brief Returns the number of CRLs selected during the verification attempt.
    /// @note Requires kChainAndCrl evidence mode. The count is available after
    ///       Verify() returns a verification result, whether valid or failed.
    /// @return Number of retained CRL metadata entries, or an error if the evidence is unavailable.
    virtual score::Result<std::size_t> GetSelectedCrlMetadataCount() const = 0;

    /// @brief Fills caller-provided storage with metadata for selected CRLs.
    /// @note Requires kChainAndCrl evidence mode. Missing metadata for an issuer
    ///       means no CRL was selected for it; it does not establish non-revocation.
    /// @param out Caller-provided storage for selected CRL metadata; query
    ///        GetSelectedCrlMetadataCount() to determine the required size.
    /// @return Number of entries written, or an error if the evidence is unavailable.
    virtual score::Result<std::size_t> GetSelectedCrlMetadata(score::cpp::span<CrlMetadata> out) const = 0;

  protected:
    ICertificateVerificationContext() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_I_CERTIFICATE_VERIFICATION_CONTEXT_HPP
