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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_CONTEXT_CREATION_DECODER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_CONTEXT_CREATION_DECODER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/context/context_creation_request.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <cstdint>
#include <optional>

namespace score::crypto::daemon::mediator
{

/// @brief Decode the stable ProviderType wire contract without losing preferred-provider fallback semantics.
/// @param wire_value Encoded preference: 0 default, 1 hardware, 2 software, 3 hardware then software, or 4 software
/// then hardware.
/// @return The decoded preference, or std::nullopt for an unknown wire value.
[[nodiscard]] std::optional<common::ProviderTypePreference> DecodeProviderTypePreference(
    std::uint8_t wire_value) noexcept;

/// @brief Decodes and validates the parameters of a CTX_CREATE operation.
///
/// Performs no provider or data-node work. Checks run in a fixed order, and the first
/// failure is returned: parameter count, context type, algorithm, provider preference,
/// key reference, key requirement for the context type, and algorithm catalog lookup.
/// @param operation CTX_CREATE operation whose parameters are decoded and validated.
/// @return the validated request, or the error the client receives.
[[nodiscard]] score::crypto::Expected<common::ContextCreationRequest, score::crypto::CryptoErrorCode>
DecodeContextCreationRequest(const control_plane::protocol::SingleOperationRequest& operation);

}  // namespace score::crypto::daemon::mediator

#endif  // SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_CONTEXT_CREATION_DECODER_HPP
