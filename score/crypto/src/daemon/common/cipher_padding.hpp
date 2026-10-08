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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_CIPHER_PADDING_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_CIPHER_PADDING_HPP

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <variant>

namespace score::crypto::daemon::common
{

/// @brief CTX_CREATE wire slot that carries the CipherPadding byte of a cipher context.
inline constexpr std::size_t kCipherPaddingParamIndex = 5U;

/// @brief Decodes a wire byte; std::nullopt for a value outside the vocabulary.
[[nodiscard]] inline constexpr std::optional<score::crypto::CipherPadding> ParseCipherPadding(std::uint8_t raw) noexcept
{
    if (raw > static_cast<std::uint8_t>(score::crypto::CipherPadding::kNone))
    {
        return std::nullopt;
    }
    return static_cast<score::crypto::CipherPadding>(raw);
}

/// @brief Reads the CipherPadding from CTX_CREATE parameters.
/// @return std::nullopt when the slot is absent, not a byte, or outside the vocabulary.
[[nodiscard]] inline std::optional<score::crypto::CipherPadding> ExtractCipherPadding(
    const RequestParameters& params) noexcept
{
    if (params.size() <= kCipherPaddingParamIndex)
    {
        return std::nullopt;
    }
    const auto* raw = std::get_if<std::uint8_t>(&params[kCipherPaddingParamIndex]);
    if (raw == nullptr)
    {
        return std::nullopt;
    }
    return ParseCipherPadding(*raw);
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_CIPHER_PADDING_HPP
