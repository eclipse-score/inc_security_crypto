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

#ifndef CRYPTO_DAEMON_PROVIDER_CRYPTO_HANDLERS_MAC_HANDLER_OPERATIONS_HPP
#define CRYPTO_DAEMON_PROVIDER_CRYPTO_HANDLERS_MAC_HANDLER_OPERATIONS_HPP

#include "score/crypto/daemon/common/types.hpp"

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
namespace mac_handler_operations
{
using OperationAction = common::OperationAction;

// ============================================================================
// Common MAC Operations
// ============================================================================

// TODO: I guess for GMAC we want an IV, but the API does currenlty not allow one

// MAC_INIT
// Request:  data_node_id = context_id,
//           param[0]: optional DataBuffer — initial data or IV
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Calls InitMac(), initializes MAC stream context, transitions state IDLE → INITIALIZED
inline constexpr OperationAction MAC_INIT = 1;

// MAC_UPDATE
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — data to MAC
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Calls UpdateMac(data), processes data into stream, transitions state INITIALIZED/ACTIVE → ACTIVE
inline constexpr OperationAction MAC_UPDATE = 2;

// TODO: Do we need here a final chunk?

// MAC_FINALIZE
// Request:  data_node_id = context_id,
//           param[0]: optional DataBuffer — output buffer for MAC tag (This can only be a resolved SHM region)
//           param[1]: optional DataBuffer — final data chunk to include
// Response: status_code (SUCCESS/error)
//           param[0]: DataBuffer — computed MAC tag bytes
// Effect:   Calls FinalizeMac(), computes final MAC, clears stream context, transitions state → IDLE
inline constexpr OperationAction MAC_FINALIZE = 3;

// MAC_VERIFY
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — MAC tag to verify against accumulated data
// Response: status_code (SUCCESS/error)
//           param[0]: bool — true if MAC is valid, false if invalid
// Effect:   Calls VerifyMac(), computes MAC and compares, transitions state → IDLE
inline constexpr OperationAction MAC_VERIFY = 4;

// MAC_GET_SIZE
// Request:  data_node_id = context_id,
//           no operation parameters
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — MAC output size in bytes (e.g., 32 for HMAC-SHA256)
// Effect:   Queries MAC algorithm's tag size, does not affect state
inline constexpr OperationAction MAC_GET_SIZE = 5;

// MAC_RESET
// Request:  data_node_id = context_id,
//           no operation parameters
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Calls Reset(), clears intermediate MAC state, transitions state → IDLE
inline constexpr OperationAction MAC_RESET = 6;

// MAC_SS -> TODO TBD
inline constexpr OperationAction MAC_SS = 7;

inline constexpr OperationAction MAC_CUSTOM_OP_START = 1 << (std::numeric_limits<OperationAction>::digits - 1);

}  // namespace mac_handler_operations
}  // namespace handler
}  // namespace provider
}  // namespace daemon
}  // namespace crypto
}  // namespace score

#endif  // CRYPTO_DAEMON_PROVIDER_CRYPTO_HANDLERS_MAC_HANDLER_OPERATIONS_HPP
