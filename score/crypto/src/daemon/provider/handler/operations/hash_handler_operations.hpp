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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_HASH_HANDLER_OPERATIONS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_HASH_HANDLER_OPERATIONS_HPP

#include "score/crypto/src/daemon/common/types.hpp"

#include <limits>

namespace score
{
namespace crypto
{
namespace daemon
{
namespace provider
{
namespace handler
{
namespace hash_handler_operations
{
using OperationAction = common::OperationAction;

// ============================================================================
// Common Hash Operations
// ============================================================================
// These base operations are reserved in the lower 16-bits of OperationAction
// and are shared across all hash handler implementations.
// ============================================================================

// HASH_INIT
// Request:  data_node_id = context_id,
//           param[0]: optional DataBuffer — initial data to hash or IV
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Calls InitHash(), initializes hash stream context, transitions state IDLE → INITIALIZED
inline constexpr OperationAction HASH_INIT = 1;

// HASH_UPDATE
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — data to hash
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Calls UpdateHash(data), processes data into stream, transitions state INITIALIZED/ACTIVE → ACTIVE
inline constexpr OperationAction HASH_UPDATE = 2;

// HASH_FINALIZE
// Request:  data_node_id = context_id,
//           param[0]: optional DataBuffer — output buffer for hash digest (modified in-place)
//           param[1]: optional DataBuffer — final data chunk to include
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — digest length in bytes (hash bytes written to request param[0])
// Effect:   Calls FinalizeHash(), computes final hash into param[0] buffer, clears stream context, transitions state →
// IDLE
inline constexpr OperationAction HASH_FINALIZE = 3;

// HASH_SS (Single-Shot Hash)
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — data to hash
//           param[1]: optional DataBuffer — output buffer for hash digest (modified in-place)
//           param[2]: optional DataBuffer — initialization vector (unused for hash)
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — digest length in bytes (hash bytes written to request param[1])
// Effect:   Calls SingleShotHash(), requires IDLE state, performs init+update+finalize in one call
inline constexpr OperationAction HASH_SS = 4;

// HASH_GET_DIGEST_SIZE
// Request:  data_node_id = context_id,
//           no operation parameters
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — hash output size in bytes (e.g., 32 for SHA256, 64 for SHA512)
// Effect:   Queries hash algorithm's digest size, does not affect state
inline constexpr OperationAction HASH_GET_DIGEST_SIZE = 5;

// HASH_RESET
// Request:  data_node_id = context_id,
//           no operation parameters
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Calls Reset(), clears intermediate hash state, transitions state → IDLE
inline constexpr OperationAction HASH_RESET = 6;

inline constexpr OperationAction HASH_CUSTOM_OP_START = 1 << (std::numeric_limits<OperationAction>::digits - 1);

}  // namespace hash_handler_operations
}  // namespace handler
}  // namespace provider
}  // namespace daemon
}  // namespace crypto
}  // namespace score

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_HASH_HANDLER_OPERATIONS_HPP
