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

#include "score/crypto/src/api/types/algorithm.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace score::crypto::daemon::common
{

/// @brief Outcome of comparing a key's algorithm with an operation's algorithm.
enum class KeyCompatibility : std::uint8_t
{
    kCompatible,    ///< The key can serve the operation
    kIncompatible,  ///< Key type, length or curve does not fit the operation
    kUnchecked,     ///< The operation algorithm is unknown here; the provider decides
};

namespace key_compatibility_detail
{

/// @brief Kind and length of a key as far as its algorithm and size say.
struct KeyShape
{
    ::score::crypto::KeyType type;
    std::size_t bits;
    ::score::crypto::EccCurve curve;
};

[[nodiscard]] inline constexpr std::optional<KeyShape> ShapeOfKey(std::string_view key_algorithm,
                                                                  std::size_t key_size_bytes) noexcept
{
    if (const auto ecdsa = ParseEcdsaName(key_algorithm); ecdsa.has_value())
    {
        return KeyShape{::score::crypto::KeyType::kEcc, ecdsa->curve.key_bits, ecdsa->curve.curve};
    }
    const auto descriptor = ::score::crypto::GetAlgorithmDescriptor(key_algorithm);
    if (!descriptor.has_value() || (descriptor->key_type == ::score::crypto::KeyType::kNone))
    {
        return std::nullopt;
    }
    // The material that is actually held wins over the nominal length of the
    // algorithm name, e.g. an HMAC key may be longer than its digest.
    const std::size_t bits = (key_size_bytes != 0U) ? key_size_bytes * 8U : descriptor->key_bits;
    return KeyShape{descriptor->key_type, bits, descriptor->curve};
}

}  // namespace key_compatibility_detail

/// @brief Decide whether a key can be used with an operation algorithm.
///
/// @param operation_algorithm  Algorithm the context was created for, e.g. "ECDSA-P384-SHA384".
/// @param key_algorithm        Algorithm recorded for the key or slot, e.g. "ECDSA-P256" or "AES-256".
/// @param key_size_bytes       Length of the key material if known, 0 otherwise.
///
/// Rules:
///   - ECDSA needs an EC key on the same curve; the hash is free.
///   - AES-CBC, AES-GCM and AES-CMAC need an AES key of the length the name states.
///   - HMAC takes any symmetric key (AES or generic secret).
///   - An operation algorithm this table does not know is left to the provider.
///   - A known operation with a key whose algorithm is unknown is refused.
[[nodiscard]] inline constexpr KeyCompatibility CheckKeyCompatibility(std::string_view operation_algorithm,
                                                                      std::string_view key_algorithm,
                                                                      std::size_t key_size_bytes) noexcept
{
    using ::score::crypto::AlgorithmCategory;
    using ::score::crypto::KeyType;

    const auto key = key_compatibility_detail::ShapeOfKey(key_algorithm, key_size_bytes);

    if (const auto ecdsa = ParseEcdsaName(operation_algorithm); ecdsa.has_value())
    {
        if (!ecdsa->digest.has_value())
        {
            // "ECDSA-<curve>" names a key, not an operation.
            return KeyCompatibility::kUnchecked;
        }
        const bool fits = key.has_value() && (key->type == KeyType::kEcc) && (key->curve == ecdsa->curve.curve);
        return fits ? KeyCompatibility::kCompatible : KeyCompatibility::kIncompatible;
    }

    const auto operation = ::score::crypto::GetAlgorithmDescriptor(operation_algorithm);
    if (!operation.has_value())
    {
        return KeyCompatibility::kUnchecked;
    }

    switch (operation->category)
    {
        case AlgorithmCategory::kCipher:
        case AlgorithmCategory::kAead:
        case AlgorithmCategory::kMac:
            break;
        default:
            // Hash, random and key rows describe no keyed operation.
            return KeyCompatibility::kUnchecked;
    }

    if (!key.has_value())
    {
        return KeyCompatibility::kIncompatible;
    }

    if (operation->key_type == KeyType::kSecret)
    {
        const bool symmetric = (key->type == KeyType::kSecret) || (key->type == KeyType::kAes);
        return symmetric ? KeyCompatibility::kCompatible : KeyCompatibility::kIncompatible;
    }

    const bool fits = (key->type == operation->key_type) && (key->bits == operation->key_bits);
    return fits ? KeyCompatibility::kCompatible : KeyCompatibility::kIncompatible;
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_KEY_COMPATIBILITY_HPP
