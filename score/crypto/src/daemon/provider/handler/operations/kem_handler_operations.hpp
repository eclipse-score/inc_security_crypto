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

/// @file kem_handler_operations.hpp
/// @brief Operation identifiers for provider-neutral KEM handlers.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_KEM_HANDLER_OPERATIONS_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_KEM_HANDLER_OPERATIONS_HPP

#include "score/crypto/src/daemon/common/types.hpp"
#include <limits>

namespace score::crypto::daemon::provider::handler::kem_handler_operations
{
/// @brief Generate a KEM key pair.
inline constexpr common::OperationAction KEM_KEYGEN = 1;
/// @brief Encapsulate a shared secret using a peer public key.
inline constexpr common::OperationAction KEM_ENCAPSULATE = 2;
/// @brief Decapsulate a ciphertext with the bound private key.
inline constexpr common::OperationAction KEM_DECAPSULATE = 3;
/// @brief Reset the KEM handler state.
inline constexpr common::OperationAction KEM_RESET = 4;

/// @brief First operation identifier reserved for custom KEM operations.
///
/// The highest bit separates custom operation identifiers from the
/// built-in KEM handler operations.
inline constexpr common::OperationAction KEM_CUSTOM_OP_START =
    1 << (std::numeric_limits<common::OperationAction>::digits - 1);
}  // namespace score::crypto::daemon::provider::handler::kem_handler_operations

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_HANDLER_KEM_HANDLER_OPERATIONS_HPP
