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

namespace score::crypto
{

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
    std::array<uint8_t, 32U> fingerprint{};
    std::array<uint8_t, 32U> issuer_fingerprint{};
    int64_t this_update{0};
    int64_t next_update{0};
    uint64_t crl_number{0U};
};

struct CrlMetadataWireLayout final
{
    static constexpr std::size_t kFingerprintSize = 32U;
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

}  // namespace score::crypto

#endif  // SCORE_CRYPTO_SRC_API_TYPES_CERTIFICATE_HPP
