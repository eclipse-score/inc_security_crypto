/*******************************************************************************
 *
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
 *******************************************************************************
 */

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CRL_METADATA_WIRE_LAYOUT_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CRL_METADATA_WIRE_LAYOUT_HPP

#include "score/crypto/src/api/types/certificate.hpp"

#include "score/span.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace score::crypto::daemon::cert_management
{

/// @brief Fixed-width wire layout of one CrlMetadata entry. Integer fields are stored least significant byte first.
///
/// The daemon writes entries with Encode(), and the library reads them with Decode(). Both sides use the same offsets,
/// so the layout is defined once.
struct CrlMetadataWireLayout final
{
    static constexpr std::size_t kFingerprintSize = score::crypto::kSha256FingerprintSize;
    static constexpr std::size_t kCrlFingerprintOffset = 0U;
    static constexpr std::size_t kIssuerFingerprintOffset = kCrlFingerprintOffset + kFingerprintSize;
    static constexpr std::size_t kThisUpdateOffset = kIssuerFingerprintOffset + kFingerprintSize;
    static constexpr std::size_t kNextUpdateOffset = kThisUpdateOffset + sizeof(std::int64_t);
    static constexpr std::size_t kCrlNumberOffset = kNextUpdateOffset + sizeof(std::int64_t);
    static constexpr std::size_t kEntrySize = kCrlNumberOffset + sizeof(std::uint64_t);

    /// @brief Writes @p metadata into one wire entry.
    static void Encode(const score::crypto::CrlMetadata& metadata,
                       std::array<std::uint8_t, kEntrySize>& encoded) noexcept
    {
        for (std::size_t i = 0U; i < kFingerprintSize; ++i)
        {
            encoded[kCrlFingerprintOffset + i] = metadata.fingerprint[i];
            encoded[kIssuerFingerprintOffset + i] = metadata.issuer_fingerprint[i];
        }

        const auto append_uint64 = [&encoded](std::size_t offset, std::uint64_t value) {
            for (std::size_t i = 0U; i < sizeof(value); ++i)
            {
                encoded[offset + i] = static_cast<std::uint8_t>(value >> (i * 8U));
            }
        };
        append_uint64(kThisUpdateOffset, static_cast<std::uint64_t>(metadata.this_update));
        append_uint64(kNextUpdateOffset, static_cast<std::uint64_t>(metadata.next_update));
        append_uint64(kCrlNumberOffset, metadata.crl_number);
    }

    /// @brief Reads one wire entry. Returns false when @p encoded is not exactly kEntrySize bytes.
    [[nodiscard]] static bool Decode(score::cpp::span<const std::uint8_t> encoded,
                                     score::crypto::CrlMetadata& metadata) noexcept
    {
        if (encoded.size() != kEntrySize)
        {
            return false;
        }

        score::crypto::CrlMetadata decoded{};
        for (std::size_t i = 0U; i < kFingerprintSize; ++i)
        {
            decoded.fingerprint[i] = encoded[kCrlFingerprintOffset + i];
            decoded.issuer_fingerprint[i] = encoded[kIssuerFingerprintOffset + i];
        }

        const auto read_uint64 = [&encoded](std::size_t offset) {
            std::uint64_t value{0U};
            for (std::size_t i = 0U; i < sizeof(value); ++i)
            {
                value |= static_cast<std::uint64_t>(encoded[offset + i]) << (i * 8U);
            }
            return value;
        };
        decoded.this_update = static_cast<std::int64_t>(read_uint64(kThisUpdateOffset));
        decoded.next_update = static_cast<std::int64_t>(read_uint64(kNextUpdateOffset));
        decoded.crl_number = read_uint64(kCrlNumberOffset);
        metadata = decoded;
        return true;
    }
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CRL_METADATA_WIRE_LAYOUT_HPP
