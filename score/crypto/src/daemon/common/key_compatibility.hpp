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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_KEY_COMPATIBILITY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_KEY_COMPATIBILITY_HPP

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"

#include <cstddef>
#include <optional>

namespace score::crypto::daemon::common
{

/// @brief Decide whether a key can be used with an operation algorithm.
///
/// Both algorithms are catalog rows, resolved where the request entered the
/// daemon, so no name is parsed here.
///
/// @param operation       Row the context was created for, e.g. ECDSA-P384-SHA384.
/// @param key             Row recorded for the key or slot, e.g. ECDSA-P256 or AES-256.
/// @param key_size_bytes  Length of the key material if known, 0 otherwise.
///
/// Rules:
///   - ECDSA needs an EC key on the same curve; the hash is free.
///   - RSA-PSS needs an RSA key with the modulus length of the row.
///   - Ed25519 needs an Ed25519 key.
///   - AES-CBC, AES-GCM and AES-CMAC need an AES key of the length of the row.
///     For a symmetric key the length of the material held wins over the
///     nominal length of its row; an asymmetric key's recorded size may be its
///     encoding, so its length comes from the row.
///   - HMAC takes any symmetric key (AES or generic secret).
///   - Hash, random and key rows describe no keyed operation, so no key fits.
[[nodiscard]] inline constexpr bool IsKeyCompatible(const ::score::crypto::AlgorithmDescriptor& operation,
                                                    const ::score::crypto::AlgorithmDescriptor& key,
                                                    const std::size_t key_size_bytes) noexcept
{
    using ::score::crypto::AlgorithmCategory;
    using ::score::crypto::KeyType;

    switch (operation.category)
    {
        case AlgorithmCategory::kCipher:
        case AlgorithmCategory::kAead:
        case AlgorithmCategory::kMac:
        case AlgorithmCategory::kSignature:
            break;
        case AlgorithmCategory::kUnknown:
        case AlgorithmCategory::kHash:
        case AlgorithmCategory::kKey:
        case AlgorithmCategory::kRandom:
            return false;
    }

    const bool symmetric_key = (key.key_type == KeyType::kAes) || (key.key_type == KeyType::kSecret);
    if (operation.key_type == KeyType::kSecret)
    {
        return symmetric_key;
    }

    const std::size_t key_bits = (symmetric_key && (key_size_bytes != 0U)) ? key_size_bytes * 8U : key.key_bits;
    return (key.key_type != KeyType::kNone) && (key.key_type == operation.key_type) &&
           (key_bits == operation.key_bits) && (key.curve == operation.curve);
}

/// @brief Decide whether a key pinned to one algorithm may serve an operation.
///
/// A key fits many algorithms: an AES-256 key fits AES-256-CBC, AES-256-GCM
/// and HMAC alike. Using one key in two modes can leak secrets one mode relies
/// on, e.g. a single CBC block under a zero IV returns the GCM hash subkey.
/// A key with a permitted algorithm is therefore usable for that catalog row
/// only.
///
/// @param operation  Row the context was created for.
/// @param permitted  Row the key is pinned to; std::nullopt means no pin.
[[nodiscard]] inline constexpr bool IsPermittedAlgorithm(
    const ::score::crypto::AlgorithmDescriptor& operation,
    const std::optional<::score::crypto::AlgorithmDescriptor>& permitted) noexcept
{
    return !permitted.has_value() || (operation.id == permitted->id);
}

/// @brief Decide whether a permitted algorithm can be set on a key at all.
///
/// Refuses a pin the key could never serve, such as an AES-128 key pinned to
/// AES-256-GCM, and a pin that names no keyed operation, such as "AES-256" or
/// "SHA256", which no context would ever match. The mistake is reported when
/// the key is created or the slot is loaded rather than at every later use.
[[nodiscard]] inline constexpr bool IsValidPermittedAlgorithm(const ::score::crypto::AlgorithmDescriptor& permitted,
                                                              const ::score::crypto::AlgorithmDescriptor& key,
                                                              const std::size_t key_size_bytes) noexcept
{
    // IsKeyCompatible() already refuses hash, key and random rows as operations.
    return IsKeyCompatible(permitted, key, key_size_bytes);
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_KEY_COMPATIBILITY_HPP
