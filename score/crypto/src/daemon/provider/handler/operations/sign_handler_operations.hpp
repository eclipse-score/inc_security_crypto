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

/// @file sign_handler_operations.hpp
/// @brief Operation identifiers for provider-neutral signature handlers.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_SIGN_HANDLER_OPERATIONS_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_SIGN_HANDLER_OPERATIONS_HPP

#include "score/crypto/src/daemon/common/types.hpp"
#include <limits>

namespace score::crypto::daemon::provider::handler::sign_handler_operations
{
/// @brief Initialize a streaming signature operation.
inline constexpr common::OperationAction SIGN_INIT = 1;
/// @brief Add a message fragment to the signature operation.
inline constexpr common::OperationAction SIGN_UPDATE = 2;
/// @brief Finalize a streaming signature operation.
inline constexpr common::OperationAction SIGN_FINALIZE = 3;
/// @brief Sign a complete message in one operation.
inline constexpr common::OperationAction SIGN_SS = 4;
/// @brief Query the signature size for the selected algorithm.
inline constexpr common::OperationAction SIGN_GET_SIGNATURE_SIZE = 5;
/// @brief Reset the signature operation state.
inline constexpr common::OperationAction SIGN_RESET = 6;

/// @brief First operation identifier reserved for custom signature operations.
///
/// The highest bit separates custom operation identifiers from the
/// built-in signature handler operations.
inline constexpr common::OperationAction SIGN_CUSTOM_OP_START =
    1 << (std::numeric_limits<common::OperationAction>::digits - 1);
}  // namespace score::crypto::daemon::provider::handler::sign_handler_operations

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_SIGN_HANDLER_OPERATIONS_HPP
