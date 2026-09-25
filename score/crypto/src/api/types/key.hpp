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

enum class KeySlotState : uint8_t
{
    kEmpty,
    kOccupied,
    kLocked
};

enum class KeyOperationPermission : uint32_t
{
    kNone = 0x0000U,
    kEncrypt = 0x0001U,
    kDecrypt = 0x0002U,
    kWrap = 0x0004U,
    kUnwrap = 0x0008U,
    kSign = 0x0010U,
    kVerify = 0x0020U,
    kMac = 0x0040U,
    kAgree = 0x0080U,
    kDerive = 0x0100U,
    kExport = 0x0200U,
    kImport = 0x0400U,
    kDataProtection = 0x000FU,
    kAuthentication = 0x00F0U,
    kFullLifecycle = 0x0700U,
    kAll = 0x07FFU,
};

inline constexpr KeyOperationPermission operator|(KeyOperationPermission lhs, KeyOperationPermission rhs) noexcept
{
    return static_cast<KeyOperationPermission>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}

inline constexpr KeyOperationPermission operator&(KeyOperationPermission lhs, KeyOperationPermission rhs) noexcept
{
    return static_cast<KeyOperationPermission>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}

inline constexpr KeyOperationPermission operator~(KeyOperationPermission perm) noexcept
{
    constexpr uint32_t kValidBitsMask = 0x07FFU;
    return static_cast<KeyOperationPermission>((~static_cast<uint32_t>(perm)) & kValidBitsMask);
}

inline constexpr KeyOperationPermission& operator|=(KeyOperationPermission& lhs, KeyOperationPermission rhs) noexcept
{
    lhs = lhs | rhs;
    return lhs;
}

inline constexpr KeyOperationPermission& operator&=(KeyOperationPermission& lhs, KeyOperationPermission rhs) noexcept
{
    lhs = lhs & rhs;
    return lhs;
}

inline constexpr bool HasPermission(KeyOperationPermission granted, KeyOperationPermission required) noexcept
{
    constexpr uint32_t kValidBitsMask = 0x07FFU;
    const uint32_t g = static_cast<uint32_t>(granted) & kValidBitsMask;
    const uint32_t r = static_cast<uint32_t>(required) & kValidBitsMask;
    return (g & r) == r;
}

struct KeySlotInfo
{
    KeySlotState state{KeySlotState::kEmpty};
    AlgorithmId algorithm{};
    uint16_t primary_provider{0U};
    static constexpr std::size_t kMaxCompatibleProviders = 8U;
    std::array<uint16_t, kMaxCompatibleProviders> compatible_providers{};
    std::size_t compatible_provider_count{0U};
    KeyOperationPermission permitted_operations{KeyOperationPermission::kAll};
};

}  // namespace score::crypto

#endif  // SCORE_CRYPTO_SRC_API_TYPES_KEY_HPP
