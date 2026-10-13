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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_MODE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_MODE_HPP

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <variant>

namespace score::crypto::daemon::common
{

/// @brief The fixed mode of a context as it travels in CTX_CREATE param[4].
///
/// One wire vocabulary for every keyed context type, so the mediator reads the
/// mode without knowing which API enum the client started from. A cipher
/// context carries kEncrypt or kDecrypt; a MAC, SIGN or VERIFY context carries
/// kGenerate or kVerify. Values are stable wire identifiers.
enum class ContextMode : std::uint8_t
{
    kGenerate = 0,  ///< MAC generation / signature creation
    kVerify = 1,    ///< MAC verification / signature verification
    kEncrypt = 2,   ///< Cipher encryption direction
    kDecrypt = 3,   ///< Cipher decryption direction
};

/// @brief CTX_CREATE wire slot that carries the ContextMode byte.
inline constexpr std::size_t kContextModeParamIndex = 4U;

[[nodiscard]] inline constexpr ContextMode ToContextMode(score::crypto::CipherDirection direction) noexcept
{
    return (direction == score::crypto::CipherDirection::kEncrypt) ? ContextMode::kEncrypt : ContextMode::kDecrypt;
}

[[nodiscard]] inline constexpr ContextMode ToContextMode(score::crypto::OperationMode mode) noexcept
{
    return (mode == score::crypto::OperationMode::kVerify) ? ContextMode::kVerify : ContextMode::kGenerate;
}

/// @brief Decodes a wire byte; std::nullopt for a value outside the vocabulary.
[[nodiscard]] inline constexpr std::optional<ContextMode> ParseContextMode(std::uint8_t raw) noexcept
{
    if (raw > static_cast<std::uint8_t>(ContextMode::kDecrypt))
    {
        return std::nullopt;
    }
    return static_cast<ContextMode>(raw);
}

/// @brief The cipher direction a mode denotes; std::nullopt for a MAC/signature mode.
[[nodiscard]] inline constexpr std::optional<score::crypto::CipherDirection> ToCipherDirection(
    ContextMode mode) noexcept
{
    switch (mode)
    {
        case ContextMode::kEncrypt:
            return score::crypto::CipherDirection::kEncrypt;
        case ContextMode::kDecrypt:
            return score::crypto::CipherDirection::kDecrypt;
        default:
            return std::nullopt;
    }
}

/// @brief The MAC/signature mode a value denotes; std::nullopt for a cipher direction.
[[nodiscard]] inline constexpr std::optional<score::crypto::OperationMode> ToOperationMode(ContextMode mode) noexcept
{
    switch (mode)
    {
        case ContextMode::kGenerate:
            return score::crypto::OperationMode::kGenerate;
        case ContextMode::kVerify:
            return score::crypto::OperationMode::kVerify;
        default:
            return std::nullopt;
    }
}

/// @brief Reads the ContextMode from CTX_CREATE parameters.
/// @return std::nullopt when the slot is absent, not a byte, or outside the vocabulary.
[[nodiscard]] inline std::optional<ContextMode> ExtractContextMode(const RequestParameters& params) noexcept
{
    if (params.size() <= kContextModeParamIndex)
    {
        return std::nullopt;
    }
    const auto* raw = std::get_if<std::uint8_t>(&params[kContextModeParamIndex]);
    if (raw == nullptr)
    {
        return std::nullopt;
    }
    return ParseContextMode(*raw);
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_MODE_HPP
