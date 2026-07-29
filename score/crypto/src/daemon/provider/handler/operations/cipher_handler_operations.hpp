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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_CIPHER_HANDLER_OPERATIONS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_CIPHER_HANDLER_OPERATIONS_HPP

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
namespace cipher_handler_operations
{
using OperationAction = common::OperationAction;

// ============================================================================
// Common symmetric cipher operations
// ============================================================================
// The direction (encrypt / decrypt) is fixed at CTX_CREATE time via param[4]
// and is therefore not repeated on any of the operations below.
// ============================================================================

// CIPHER_INIT
// Request:  data_node_id = context_id,
//           param[0]: optional DataBuffer — initialization vector / nonce.
//                     Required for IV-based modes (CBC, CTR); absent for ECB.
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Calls InitCipher(), transitions state IDLE → INITIALIZED
inline constexpr OperationAction CIPHER_INIT = 1;

// CIPHER_UPDATE
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — input chunk (plaintext when encrypting,
//                     ciphertext when decrypting)
//           param[1]: DataShm(InOut) — caller's output buffer. Must hold the
//                     input length plus one block: EVP emits a buffered partial
//                     block ahead of the current chunk.
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — bytes written. May be shorter than the input
//                     (block buffering) or zero.
// Effect:   Calls UpdateCipher(), transitions state INITIALIZED/ACTIVE → ACTIVE
inline constexpr OperationAction CIPHER_UPDATE = 2;

// CIPHER_FINALIZE
// Request:  data_node_id = context_id,
//           param[0]: DataShm(InOut) — caller's output buffer for the trailing
//                     bytes (final padded block for CBC-with-padding, nothing
//                     for stream modes)
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — bytes written
// Effect:   Calls FinalizeCipher(), clears stream context, transitions state → IDLE
inline constexpr OperationAction CIPHER_FINALIZE = 3;

// CIPHER_SS (Single-Shot)
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — initialization vector (may be empty for ECB)
//           param[1]: DataBuffer — full input
//           param[2]: DataShm(InOut) — caller's output buffer, sized for the
//                     input length plus one block
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — bytes written
// Effect:   Requires IDLE state; performs init + update + finalize in one call
inline constexpr OperationAction CIPHER_SS = 4;

// CIPHER_GET_OUTPUT_SIZE
// Request:  data_node_id = context_id,
//           no operation parameters
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — cipher block size in bytes (16 for AES,
//                     1 for stream modes such as CTR)
// Effect:   Stateless query; does not affect the stream state
inline constexpr OperationAction CIPHER_GET_OUTPUT_SIZE = 5;

// CIPHER_RESET
// Request:  data_node_id = context_id,
//           no operation parameters
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Calls Reset(), discards intermediate state, transitions state → IDLE.
//           Key binding, algorithm and direction are preserved.
inline constexpr OperationAction CIPHER_RESET = 6;

// CIPHER_GET_IV_SIZE
// Request:  data_node_id = context_id,
//           no operation parameters
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — required IV length in bytes (0 for ECB)
// Effect:   Stateless query; does not affect the stream state
inline constexpr OperationAction CIPHER_GET_IV_SIZE = 7;

inline constexpr OperationAction CIPHER_CUSTOM_OP_START = 1 << (std::numeric_limits<OperationAction>::digits - 1);

}  // namespace cipher_handler_operations
}  // namespace handler
}  // namespace provider
}  // namespace daemon
}  // namespace crypto
}  // namespace score

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_CIPHER_HANDLER_OPERATIONS_HPP
