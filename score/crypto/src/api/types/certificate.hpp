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

#ifndef SCORE_CRYPTO_SRC_API_TYPES_CERTIFICATE_HPP
#define SCORE_CRYPTO_SRC_API_TYPES_CERTIFICATE_HPP

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/span.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>

namespace score::crypto
{

/// Byte length of a SHA-256 digest, shared by every certificate/CRL/trust-store
/// fingerprint field in this domain.
inline constexpr std::size_t kSha256FingerprintSize = 32U;

/// @brief Current occupancy or access state of a certificate slot.
enum class CertificateSlotState : uint8_t
{
    /// @brief The slot contains no certificate.
    kEmpty,
    /// @brief The slot contains a certificate.
    kOccupied,
    /// @brief The slot is locked.
    kLocked
};

/// @brief Outcome of a certificate verification attempt.
///
/// Each enumerator represents a completed verification decision. If verification
/// cannot be performed or completed, Verify() returns a score::Result error using
/// CryptoErrorCode instead of a CertVerifyResult.
///
/// A valid result means all checks that ran passed. With
/// RevocationCoveragePolicy::kBestEffort, revocation checks may be skipped when
/// fresh applicable evidence is unavailable, so kValid does not guarantee
/// complete revocation coverage.
enum class CertVerifyResult : uint8_t
{
    /// @brief The certificate passed the checks that were performed.
    kValid,
    /// @brief The certificate was past its notAfter time at the verification time.
    kExpired,
    /// @brief The certificate was before its notBefore time at the verification time.
    kNotYetValid,
    /// @brief Available revocation evidence identifies the certificate as revoked.
    kRevoked,
    /// @brief Under kFailClosed, fresh revocation evidence was unavailable for a certificate that needed checking.
    ///
    /// This includes a missing applicable CRL or OCSP response for a required issuer.
    kRevocationStatusUnavailable,
    /// @brief A candidate path was built, but none of its certificates matched a configured trust anchor.
    kNoRootFound,
    /// @brief A complete issuer path could not be built, for example because a required intermediate is missing.
    kChainIncomplete,
    /// @brief A certificate signature in the chain failed verification.
    kSignatureInvalid,
    /// @brief The certificate is not valid for the requested purpose.
    kInvalidPurpose
};

/// @brief Selects where a verified certificate chain is allowed to terminate.
enum class ChainTerminationPolicy : uint8_t
{
    /// @brief Require the chain to reach a self-signed root in the trust anchors.
    kRootRequired,
    /// @brief Allow the chain to terminate at the first configured trust anchor, including an intermediate.
    kTrustStoreTerminated
};

/// @brief Selects the revocation sources consulted during certificate verification.
///
/// Evidence-coverage behavior when selected CRL or OCSP evidence is missing or
/// stale is controlled separately by RevocationCoveragePolicy.
///
/// @note Support for OCSP-based policies depends on the selected provider.
enum class RevocationCheckPolicy : uint8_t
{
    /// @brief Do not perform revocation checks.
    kNone,
    /// @brief Check revocation using CRLs; missing or stale coverage follows the configured coverage policy.
    kCrlOnly,
    /// @brief Check revocation using OCSP only; do not use CRLs as a fallback.
    kOcspOnly,
    /// @brief Check using OCSP and fall back to CRLs when OCSP cannot provide usable evidence.
    kOcspWithCrlFallback
};

/// @brief Controls behavior when selected CRL or OCSP sources lack fresh applicable evidence.
///
/// This policy is independent of RevocationCheckPolicy, which selects the evidence
/// source and any source fallback. Freshness is evaluated according to the selected
/// source's validity rules. An available CRL past `nextUpdate` may still be inspected
/// for positive revocation evidence, and its metadata exposes that refresh time; its
/// absence of a certificate does not establish that the certificate is unrevoked.
enum class RevocationCoveragePolicy : uint8_t
{
    /// @brief Require fresh applicable evidence for every certificate that needs checking.
    /// @note Missing or stale-only evidence, including a missing issuer CRL or OCSP
    ///       response after configured fallback, produces kRevocationStatusUnavailable
    ///       unless a more specific result applies.
    kFailClosed,
    /// @brief Continue when no selected source or configured fallback provides fresh
    ///        evidence; this alone does not fail verification, but skipped checks do
    ///        not establish non-revocation.
    kBestEffort
};

/// @brief Selects which verification evidence is retained after a verification attempt.
enum class VerificationEvidenceMode : uint8_t
{
    /// @brief Retain no verification evidence.
    kNone,
    /// @brief Retain the constructed certificate chain.
    kChain,
    /// @brief Retain the chain and metadata for CRLs selected during verification.
    ///
    /// The metadata lists CRLs actually selected, and can be queried after a
    /// verification result whether it is valid or a failure. An issuer with no
    /// selected CRL has no corresponding entry; absence does not mean unrevoked.
    kChainAndCrl
};

/// @brief Metadata identifying a CRL selected during certificate verification.
struct CrlMetadata
{
    std::array<uint8_t, kSha256FingerprintSize> fingerprint{};  ///< SHA-256 fingerprint of the CRL.
    std::array<uint8_t, kSha256FingerprintSize>
        issuer_fingerprint{};  ///< SHA-256 fingerprint of the certificate that issued the CRL.
    int64_t this_update{0};    ///< CRL thisUpdate time in seconds since Unix epoch.
    int64_t next_update{0};    ///< Advertised refresh time in seconds since Unix epoch.
    uint64_t crl_number{0U};   ///< CRL number, or zero if the CRL has no number.
};

struct CrlMetadataWireLayout final
{
    static constexpr std::size_t kFingerprintSize = kSha256FingerprintSize;
    static constexpr std::size_t kCrlFingerprintOffset = 0U;
    static constexpr std::size_t kIssuerFingerprintOffset = kCrlFingerprintOffset + kFingerprintSize;
    static constexpr std::size_t kThisUpdateOffset = kIssuerFingerprintOffset + kFingerprintSize;
    static constexpr std::size_t kNextUpdateOffset = kThisUpdateOffset + sizeof(std::int64_t);
    static constexpr std::size_t kCrlNumberOffset = kNextUpdateOffset + sizeof(std::int64_t);
    static constexpr std::size_t kEntrySize = kCrlNumberOffset + sizeof(std::uint64_t);

    static void Encode(const CrlMetadata& metadata, std::array<uint8_t, kEntrySize>& encoded) noexcept
    {
        for (std::size_t i = 0U; i < kFingerprintSize; ++i)
        {
            encoded[kCrlFingerprintOffset + i] = metadata.fingerprint[i];
            encoded[kIssuerFingerprintOffset + i] = metadata.issuer_fingerprint[i];
        }

        const auto append_uint64 = [&encoded](std::size_t offset, std::uint64_t value) {
            for (std::size_t i = 0U; i < sizeof(value); ++i)
                encoded[offset + i] = static_cast<uint8_t>(value >> (i * 8U));
        };
        append_uint64(kThisUpdateOffset, static_cast<std::uint64_t>(metadata.this_update));
        append_uint64(kNextUpdateOffset, static_cast<std::uint64_t>(metadata.next_update));
        append_uint64(kCrlNumberOffset, metadata.crl_number);
    }

    static score::Result<std::monostate> Decode(score::cpp::span<const uint8_t> encoded, CrlMetadata& metadata) noexcept
    {
        if (encoded.size() != kEntrySize)
        {
            return score::Result<std::monostate>{
                score::unexpect, MakeError(CryptoErrorCode::kInvalidArgument, "Invalid CRL metadata wire size")};
        }

        CrlMetadata decoded{};
        for (std::size_t i = 0U; i < kFingerprintSize; ++i)
        {
            decoded.fingerprint[i] = encoded[kCrlFingerprintOffset + i];
            decoded.issuer_fingerprint[i] = encoded[kIssuerFingerprintOffset + i];
        }

        const auto read_uint64 = [&encoded](std::size_t offset) {
            std::uint64_t value{0U};
            for (std::size_t i = 0U; i < sizeof(value); ++i)
                value |= static_cast<std::uint64_t>(encoded[offset + i]) << (i * 8U);
            return value;
        };
        decoded.this_update = static_cast<std::int64_t>(read_uint64(kThisUpdateOffset));
        decoded.next_update = static_cast<std::int64_t>(read_uint64(kNextUpdateOffset));
        decoded.crl_number = read_uint64(kCrlNumberOffset);
        metadata = decoded;
        return std::monostate{};
    }
};

/// @brief Snapshot of a certificate slot's state and persistent CRL presence.
struct CertificateSlotInfo
{
    CertificateSlotState state{CertificateSlotState::kEmpty};  ///< Current slot state.
    bool has_crl{false};                                       ///< Whether the slot stores a persistent CRL.
};

/// Membership kind of a trust store anchor.
enum class MemberKind : uint8_t
{
    kSharedStatic = 0U,        ///< Externally managed slot; read-only from trust store perspective.
    kExclusiveMutable = 1U,    ///< Trust-store-owned exclusive slot; mutable via management context.
    kConditionalExternal = 2U  ///< External slot; disabled after unexpected content change.
};

/// Effective status of a trust store member as seen at snapshot time.
enum class MemberStatus : uint8_t
{
    kEnabled = 0U,                 ///< Active anchor for chain building.
    kDisabled = 1U,                ///< Explicitly disabled (or removed from use); can be re-enabled.
    kFingerprintMismatch = 2U,     ///< Conditional-external content differs from the accepted fingerprint.
    kAwaitingAcknowledgement = 3U  ///< Conditional-external content never accepted; acknowledgement required.
};

/// Snapshot of a single trust store member.
///
/// Both slot_id and sha256_fingerprint are provided so callers can:
/// - Use slot_id directly for enable/disable/importCrl operations without a round-trip.
/// - Use sha256_fingerprint for quick identity matching against externally known fingerprints
///   (e.g., from a security bulletin) without loading the full certificate.
/// - Use subject + issuer + serial_number for human-readable identification and logging.
struct MemberInfo
{
    CryptoResourceId slot_id{};  ///< kCertSlot resource — use for management ops.
    std::array<uint8_t, kSha256FingerprintSize>
        sha256_fingerprint{};                     ///< SHA-256 fingerprint of the member certificate.
    std::string subject;                          ///< RFC 4514 Subject DN (e.g., "CN=Root CA,O=ACME,C=DE").
    std::string issuer;                           ///< RFC 4514 Issuer DN.
    std::string serial_number;                    ///< Uppercase hex serial (e.g., "01ABCDEF").
    MemberKind kind{MemberKind::kSharedStatic};   ///< Membership type.
    MemberStatus status{MemberStatus::kEnabled};  ///< Only kEnabled members are active anchors.
};

}  // namespace score::crypto

#endif  // SCORE_CRYPTO_SRC_API_TYPES_CERTIFICATE_HPP
