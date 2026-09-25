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

#include "score/crypto/src/api/types/common.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace score::crypto
{

/// Byte length of a SHA-256 digest, shared by every certificate/CRL/trust-store
/// fingerprint field in this domain.
inline constexpr std::size_t kSha256FingerprintSize = 32U;

enum class CertificateSlotState : uint8_t
{
    kEmpty,
    kOccupied,
    kLocked
};

enum class CertificateStatus : uint8_t
{
    kValid,
    kRevoked,
    kExpired,
    kUnknown
};

enum class CertVerifyResult : uint8_t
{
    kValid,
    kExpired,
    kNotYetValid,
    kRevoked,
    kNoRootFound,
    kChainIncomplete,
    kSignatureInvalid,
    kInvalidPurpose,
    kUnknownAlgorithm,
    kUnknownError
};

enum class ChainTerminationPolicy : uint8_t
{
    kRootRequired,
    kTrustStoreTerminated
};

enum class OcspStatus : uint8_t
{
    kGood,
    kRevoked,
    kUnknown,
    kError
};

enum class RevocationCheckPolicy : uint8_t
{
    kNone,
    kCrlOnly,
    kOcspOnly,
    kOcspWithCrlFallback
};

enum class VerificationEvidenceMode : uint8_t
{
    kNone,
    kChain,
    kChainAndCrl
};

struct CrlMetadata
{
    std::array<uint8_t, kSha256FingerprintSize> fingerprint{};
    std::array<uint8_t, kSha256FingerprintSize> issuer_fingerprint{};
    int64_t this_update{0};
    int64_t next_update{0};
    uint64_t crl_number{0U};
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
};

struct CertificateSlotInfo
{
    CertificateSlotState state{CertificateSlotState::kEmpty};
    bool has_crl{false};
};

/// Membership kind of a trust store anchor.
enum class MemberKind : uint8_t
{
    kSharedStatic = 0U,        ///< Externally managed slot; read-only from trust store perspective.
    kExclusiveMutable = 1U,    ///< Trust-store-owned exclusive slot; mutable via management context.
    kConditionalExternal = 2U  ///< External slot; disabled after unexpected content change.
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
        sha256_fingerprint{};                    ///< SHA-256 fingerprint of the member certificate.
    std::string subject;                         ///< RFC 4514 Subject DN (e.g., "CN=Root CA,O=ACME,C=DE").
    std::string issuer;                          ///< RFC 4514 Issuer DN.
    std::string serial_number;                   ///< Uppercase hex serial (e.g., "01ABCDEF").
    MemberKind kind{MemberKind::kSharedStatic};  ///< Membership type.
    bool is_enabled{true};                       ///< Whether anchor is active for chain building.
};

}  // namespace score::crypto

#endif  // SCORE_CRYPTO_SRC_API_TYPES_CERTIFICATE_HPP
