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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_DETAIL_PKCS11_ALGORITHM_INFO_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_DETAIL_PKCS11_ALGORITHM_INFO_HPP

#include "score/crypto/daemon/common/types.hpp"

#include <cryptoki.h>
#include <pkcs11.h>

#include <cstdint>
#include <optional>
#include <string_view>

namespace score::crypto::daemon::provider::pkcs11::detail
{

/// @brief PKCS#11 algorithm parameters derived from a daemon algorithm identifier.
struct Pkcs11AlgoInfo
{
    CK_KEY_TYPE ck_key_type{CKK_GENERIC_SECRET};                  ///< CKA_KEY_TYPE attribute value
    CK_MECHANISM_TYPE gen_mechanism{CKM_GENERIC_SECRET_KEY_GEN};  ///< For C_GenerateKey
    CK_ULONG value_len{0U};                                       ///< CKA_VALUE_LEN in bytes
};

/// @brief Lookup table entry mapping algorithm identifier substring to PKCS#11 parameters.
struct Pkcs11AlgoEntry
{
    std::string_view algorithm;
    Pkcs11AlgoInfo info;
};

/// @brief Lookup table for algorithm identifier to PKCS#11 parameters mapping.
///
/// Each entry maps a daemon algorithm identifier substring (case-sensitive, uppercase
/// expected) to its corresponding PKCS#11 parameters. Used by LookupAlgorithm for
/// O(n) linear search; extend this table when adding new algorithm support.
inline constexpr Pkcs11AlgoEntry kAlgoEntries[] = {
    // HMAC family — generic secret keys; size varies by hash length
    {"HMAC-SHA256", {CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 32U}},
    {"HMAC-SHA384", {CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 48U}},
    {"HMAC-SHA512", {CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 64U}},
    // AES family
    {"AES-128", {CKK_AES, CKM_AES_KEY_GEN, 16U}},
    {"AES-192", {CKK_AES, CKM_AES_KEY_GEN, 24U}},
    {"AES-256", {CKK_AES, CKM_AES_KEY_GEN, 32U}},
};

/// @brief Map a daemon algorithm identifier string to PKCS#11 parameters.
///
/// Returns an empty optional for unknown or unsupported algorithms.
/// Case-sensitive substring matching (uppercase expected, matching the AlgorithmId
/// values used by the daemon).
///
/// Adding a new algorithm: extend kAlgoEntries and add a matching entry to
/// OpenSslKeyHandler::DetermineKeySize() for cross-provider consistency.
[[nodiscard]] inline std::optional<Pkcs11AlgoInfo> LookupAlgorithm(const common::AlgorithmId& algo) noexcept
{
    for (const auto& entry : kAlgoEntries)
    {
        if (algo.find(entry.algorithm) != std::string::npos)
        {
            return entry.info;
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Hash algorithm → CK_MECHANISM_TYPE
// ---------------------------------------------------------------------------

struct Pkcs11HashMechanism
{
    std::string_view name;
    CK_MECHANISM_TYPE mechanism;
};

inline constexpr Pkcs11HashMechanism kHashMechanisms[] = {
    {"SHA256", CKM_SHA256},
    {"SHA384", CKM_SHA384},
    {"SHA512", CKM_SHA512},
    {"SHA224", CKM_SHA224},
    {"SHA1", CKM_SHA_1},
    {"MD5", CKM_MD5},
};

/// @brief Look up the PKCS#11 mechanism type for a hash algorithm.
[[nodiscard]] inline CK_MECHANISM_TYPE LookupHashMechanism(std::string_view algorithm) noexcept
{
    for (const auto& entry : kHashMechanisms)
    {
        if (entry.name == algorithm)
        {
            return entry.mechanism;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

// ---------------------------------------------------------------------------
// MAC algorithm → CK_MECHANISM_TYPE
// ---------------------------------------------------------------------------

struct Pkcs11MacMechanism
{
    std::string_view name;
    CK_MECHANISM_TYPE mechanism;
};

inline constexpr Pkcs11MacMechanism kMacMechanisms[] = {
    {"HMAC-SHA256", CKM_SHA256_HMAC},
    {"HMAC-SHA384", CKM_SHA384_HMAC},
    {"HMAC-SHA512", CKM_SHA512_HMAC},
};

/// @brief Look up the PKCS#11 mechanism type for a MAC algorithm.
[[nodiscard]] inline CK_MECHANISM_TYPE LookupMacMechanism(std::string_view algorithm) noexcept
{
    for (const auto& entry : kMacMechanisms)
    {
        if (entry.name == algorithm)
        {
            return entry.mechanism;
        }
    }
    return CK_UNAVAILABLE_INFORMATION;
}

/// @brief Decode a hex string (e.g. "0102abcd") into a byte vector.
///
/// Returns an empty vector if the input is empty or has odd length.
inline std::vector<uint8_t> HexDecode(std::string_view hex) noexcept
{
    if (hex.empty() || (hex.size() % 2U != 0U))
    {
        return {};
    }
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0U; i < hex.size(); i += 2U)
    {
        const auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9')
                return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f')
                return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F')
                return static_cast<uint8_t>(c - 'A' + 10);
            return 0U;
        };
        out.push_back(static_cast<uint8_t>((nibble(hex[i]) << 4U) | nibble(hex[i + 1U])));
    }
    return out;
}

}  // namespace score::crypto::daemon::provider::pkcs11::detail

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_DETAIL_PKCS11_ALGORITHM_INFO_HPP
