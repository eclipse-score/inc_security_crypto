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

#ifndef SCORE_CRYPTO_SRC_API_TYPES_KEY_HPP
#define SCORE_CRYPTO_SRC_API_TYPES_KEY_HPP

#include "score/crypto/src/api/types/common.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace score::crypto
{

/// @brief Current occupancy or access state of a key slot.
enum class KeySlotState : uint8_t
{
    kEmpty,     ///< The slot contains no key.
    kOccupied,  ///< The slot contains a key.
    kLocked     ///< The slot is in use and cannot be modified.
};

/// @brief Bitmask of operations permitted for a key or key slot.
///
/// Individual permissions can be combined with the bitwise operators. Group
/// values such as kDataProtection and kAuthentication are convenience masks.
enum class KeyOperationPermission : uint32_t
{
    kNone = 0x0000U,            ///< No operations permitted.
    kEncrypt = 0x0001U,         ///< Encrypt data with the key.
    kDecrypt = 0x0002U,         ///< Decrypt data with the key.
    kWrap = 0x0004U,            ///< Wrap another key.
    kUnwrap = 0x0008U,          ///< Unwrap another key.
    kSign = 0x0010U,            ///< Sign data or a digest.
    kVerify = 0x0020U,          ///< Verify a signature.
    kMac = 0x0040U,             ///< Generate or verify a MAC.
    kAgree = 0x0080U,           ///< Perform key agreement.
    kDerive = 0x0100U,          ///< Derive another key.
    kExport = 0x0200U,          ///< Export key material.
    kImport = 0x0400U,          ///< Import key material.
    kDataProtection = 0x000FU,  ///< Group mask for encrypt, decrypt, wrap, and unwrap.
    kAuthentication = 0x00F0U,  ///< Group mask for sign, verify, and MAC operations.
    kFullLifecycle = 0x0700U,   ///< Group mask for agree, derive, export, and import.
    kAll = 0x07FFU,             ///< All defined operation permissions.
};

/// @brief Combines two key-operation permission masks.
inline constexpr KeyOperationPermission operator|(KeyOperationPermission lhs, KeyOperationPermission rhs) noexcept
{
    return static_cast<KeyOperationPermission>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}

/// @brief Returns the permissions common to two masks.
inline constexpr KeyOperationPermission operator&(KeyOperationPermission lhs, KeyOperationPermission rhs) noexcept
{
    return static_cast<KeyOperationPermission>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}

/// @brief Returns the complement of a permission mask, restricted to defined bits.
inline constexpr KeyOperationPermission operator~(KeyOperationPermission perm) noexcept
{
    constexpr uint32_t kValidBitsMask = 0x07FFU;
    return static_cast<KeyOperationPermission>((~static_cast<uint32_t>(perm)) & kValidBitsMask);
}

/// @brief Adds permissions to a mask.
inline constexpr KeyOperationPermission& operator|=(KeyOperationPermission& lhs, KeyOperationPermission rhs) noexcept
{
    lhs = lhs | rhs;
    return lhs;
}

/// @brief Retains only permissions present in both masks.
inline constexpr KeyOperationPermission& operator&=(KeyOperationPermission& lhs, KeyOperationPermission rhs) noexcept
{
    lhs = lhs & rhs;
    return lhs;
}

/// @brief Tests whether all required permission bits are granted.
inline constexpr bool HasPermission(KeyOperationPermission granted, KeyOperationPermission required) noexcept
{
    constexpr uint32_t kValidBitsMask = 0x07FFU;
    const uint32_t g = static_cast<uint32_t>(granted) & kValidBitsMask;
    const uint32_t r = static_cast<uint32_t>(required) & kValidBitsMask;
    return (g & r) == r;
}

/// @brief Snapshot of a key slot's state, constraints, provider bindings, and permissions.
struct KeySlotInfo
{
    KeySlotState state{KeySlotState::kEmpty};  ///< Current slot state.
    AlgorithmId algorithm{};                   ///< Required algorithm, or empty when unconstrained.
    uint16_t primary_provider{0U};             ///< Owning provider id.
    static constexpr std::size_t kMaxCompatibleProviders = 8U;
    std::array<uint16_t, kMaxCompatibleProviders> compatible_providers{};  ///< Other permitted providers.
    std::size_t compatible_provider_count{0U};  ///< Number of valid entries in compatible_providers.
    KeyOperationPermission permitted_operations{KeyOperationPermission::kAll};  ///< Allowed key operations.
};

}  // namespace score::crypto

#endif  // SCORE_CRYPTO_SRC_API_TYPES_KEY_HPP
