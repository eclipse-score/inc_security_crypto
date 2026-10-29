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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_DETAIL_PKCS11_ALGORITHM_INFO_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_DETAIL_PKCS11_ALGORITHM_INFO_HPP

#include "score/crypto/src/api/types/algorithm.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

#include <pkcs11.h>

#include <cstddef>
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

/// @brief Map a key or operation algorithm to the PKCS#11 key it needs.
///
/// The key type and length come from score::crypto::kAlgorithmCatalog by exact
/// name, so "AES-256", "AES-256-CBC" and "AES-256-CMAC" all resolve to a
/// 32-byte CKK_AES key and "HMAC-SHA256" to a 32-byte generic secret.
/// @return the key attributes, or std::nullopt for unknown names and for key
///         types this provider does not generate (elliptic-curve keys).
[[nodiscard]] inline std::optional<Pkcs11AlgoInfo> LookupAlgorithm(const common::AlgorithmId& algo) noexcept
{
    const auto row = ::score::crypto::GetAlgorithmDescriptor(std::string_view{algo.data(), algo.size()});
    if (!row.has_value())
    {
        return std::nullopt;
    }
    const auto value_len = static_cast<CK_ULONG>((static_cast<std::size_t>(row->key_bits) + 7U) / 8U);
    switch (row->key_type)
    {
        case ::score::crypto::KeyType::kSecret:
            return Pkcs11AlgoInfo{CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, value_len};
        case ::score::crypto::KeyType::kAes:
            return Pkcs11AlgoInfo{CKK_AES, CKM_AES_KEY_GEN, value_len};
        case ::score::crypto::KeyType::kNone:
        case ::score::crypto::KeyType::kEcc:
        default:
            return std::nullopt;
    }
}

// ---------------------------------------------------------------------------
// Hash algorithm → CK_MECHANISM_TYPE
// ---------------------------------------------------------------------------

/// @brief Look up the PKCS#11 mechanism type for a hash algorithm.
[[nodiscard]] inline CK_MECHANISM_TYPE LookupHashMechanism(std::string_view algorithm) noexcept
{
    const auto info = common::LookupHashAlgorithmInfo(algorithm);
    if (!info.has_value())
    {
        return CK_UNAVAILABLE_INFORMATION;
    }

    // Keep this switch exhaustive and without a default case so adding a
    // provider-neutral algorithm requires an explicit PKCS#11 support decision.
    switch (info->algorithm)
    {
        case common::HashAlgorithm::kSha256:
            return CKM_SHA256;
        case common::HashAlgorithm::kSha384:
            return CKM_SHA384;
        case common::HashAlgorithm::kSha512:
            return CKM_SHA512;
        case common::HashAlgorithm::kSha224:
            return CKM_SHA224;
    }
    return CK_UNAVAILABLE_INFORMATION;
}

// ---------------------------------------------------------------------------
// MAC algorithm → CK_MECHANISM_TYPE
// ---------------------------------------------------------------------------

/// @brief Look up the PKCS#11 mechanism type for a MAC algorithm.
[[nodiscard]] inline CK_MECHANISM_TYPE LookupMacMechanism(std::string_view algorithm) noexcept
{
    const auto info = common::LookupMacAlgorithmInfo(algorithm);
    if (!info.has_value())
    {
        return CK_UNAVAILABLE_INFORMATION;
    }

    // Keep this switch exhaustive and without a default case so adding a
    // provider-neutral algorithm requires an explicit PKCS#11 support decision.
    switch (info->algorithm)
    {
        case common::MacAlgorithm::kHmacSha256:
            return CKM_SHA256_HMAC;
        case common::MacAlgorithm::kHmacSha384:
            return CKM_SHA384_HMAC;
        case common::MacAlgorithm::kHmacSha512:
            return CKM_SHA512_HMAC;
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

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_DETAIL_PKCS11_ALGORITHM_INFO_HPP
