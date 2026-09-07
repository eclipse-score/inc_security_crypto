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

/// @file verify_handler_operations.hpp
/// @brief Operation identifiers for provider-neutral signature verification handlers.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_VERIFY_HANDLER_OPERATIONS_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_VERIFY_HANDLER_OPERATIONS_HPP

#include "score/crypto/src/daemon/common/types.hpp"
#include <limits>

namespace score::crypto::daemon::provider::handler::verify_handler_operations
{
/// @brief Initialize a streaming verification operation.
inline constexpr common::OperationAction VERIFY_INIT = 1;
/// @brief Add a message fragment to the verification operation.
inline constexpr common::OperationAction VERIFY_UPDATE = 2;
/// @brief Verify a signature against the accumulated message.
inline constexpr common::OperationAction VERIFY_FINALIZE = 3;
/// @brief Verify a complete message in one operation.
inline constexpr common::OperationAction VERIFY_SS = 4;
/// @brief Reset the verification operation state.
inline constexpr common::OperationAction VERIFY_RESET = 5;

/// @brief First operation identifier reserved for custom verification operations.
///
/// The highest bit separates custom operation identifiers from the
/// built-in verification handler operations.
inline constexpr common::OperationAction VERIFY_CUSTOM_OP_START =
    1 << (std::numeric_limits<common::OperationAction>::digits - 1);
}  // namespace score::crypto::daemon::provider::handler::verify_handler_operations

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_VERIFY_HANDLER_OPERATIONS_HPP
