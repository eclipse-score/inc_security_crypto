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
/// The key's row says what the key is for:
///   - A key row (AES-256, ECDSA-P256, RSA-2048) names key material only and
///     serves every operation of its family: an AES key every AES mode of its
///     length, an EC key ECDSA on its curve with any hash, an RSA key RSA-PSS
///     with its modulus and any hash.
///   - Any other row (AES-256-GCM, HMAC-SHA256, Ed25519) names an operation;
///     the key serves that operation only. HMAC keys have no key row, so an
///     HMAC takes only a key labelled with that HMAC, never an AES key.
///
/// The length of an AES key's material must be the length its row states:
/// a key labelled AES-256 that holds 16 bytes fits no operation. An HMAC key
/// may have any length, and an asymmetric key's recorded size may be its
/// encoding, so neither is compared.
///
/// Hash, random and key rows describe no keyed operation, so no key fits them.
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

    if ((key.key_type == KeyType::kAes) && (key_size_bytes != 0U) &&
        ((key_size_bytes * 8U) != static_cast<std::size_t>(key.key_bits)))
    {
        return false;
    }

    if (key.category != AlgorithmCategory::kKey)
    {
        return key.id == operation.id;
    }

    return (key.key_type == operation.key_type) && (key.key_bits == operation.key_bits) &&
           (key.curve == operation.curve);
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_KEY_COMPATIBILITY_HPP
