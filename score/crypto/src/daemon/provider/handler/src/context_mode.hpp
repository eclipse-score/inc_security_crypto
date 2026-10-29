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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_SRC_CONTEXT_MODE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_SRC_CONTEXT_MODE_HPP

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"

#include <cstddef>
#include <cstdint>

// The signature input mode wire parameter is read by every provider's sign and
// verify handlers (OpenSSL today, others later), so its parsing lives here
// rather than under any one provider's detail folder.

namespace score::crypto::daemon::provider::handler
{

inline constexpr std::size_t kSignatureInputModeParamIndex{6U};

using SignatureInputModeResult =
    ::score::crypto::Expected<::score::crypto::SignatureInputMode, ::score::crypto::daemon::common::DaemonErrorCode>;

[[nodiscard]] inline SignatureInputModeResult ParseInputMode(const InitializationParams& params) noexcept
{
    if (params.context_creation_params.size() <= kSignatureInputModeParamIndex)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    const auto* const mode = std::get_if<std::uint8_t>(&params.context_creation_params[kSignatureInputModeParamIndex]);
    if (mode == nullptr)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    switch (*mode)
    {
        case static_cast<std::uint8_t>(::score::crypto::SignatureInputMode::kMessage):
            return ::score::crypto::SignatureInputMode::kMessage;
        case static_cast<std::uint8_t>(::score::crypto::SignatureInputMode::kPrehashed):
            return ::score::crypto::SignatureInputMode::kPrehashed;
        default:
            return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
}

}  // namespace score::crypto::daemon::provider::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_SRC_CONTEXT_MODE_HPP
