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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_SIGNATURE_HANDLER_OPERATIONS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_SIGNATURE_HANDLER_OPERATIONS_HPP

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

// ============================================================================
// Signature generation operations (OP_ACTOR_SIGN_HANDLER)
// ============================================================================
namespace sign_handler_operations
{
using OperationAction = common::OperationAction;

// SIGN_INIT
// Request:  data_node_id = context_id, no operation parameters
// Response: status_code (SUCCESS/error), no output parameters
// Effect:   Calls InitSign(), transitions state IDLE → INITIALIZED
inline constexpr OperationAction SIGN_INIT = 1;

// SIGN_UPDATE
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — message chunk to be signed
// Response: status_code (SUCCESS/error), no output parameters
// Effect:   Calls UpdateSign(), transitions state INITIALIZED/ACTIVE → ACTIVE
inline constexpr OperationAction SIGN_UPDATE = 2;

// SIGN_FINALIZE
// Request:  data_node_id = context_id,
//           param[0]: DataShm(InOut) — caller's signature output buffer, at
//                     least GetSignatureSize() bytes.  For ECDSA the signature
//                     is the fixed-length IEEE P1363 form r‖s.
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — bytes written
// Effect:   Calls FinalizeSign(), transitions state → IDLE
inline constexpr OperationAction SIGN_FINALIZE = 3;

// SIGN_SS (Single-Shot)
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — full message to sign
//           param[1]: DataShm(InOut) — caller's signature output buffer
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — bytes written
// Effect:   Requires IDLE state; performs init + update + finalize in one call
inline constexpr OperationAction SIGN_SS = 4;

// SIGN_GET_SIZE
// Request:  data_node_id = context_id, no operation parameters
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — signature length in bytes
//                     (64 for P-256, 96 for P-384, 132 for P-521)
// Effect:   Stateless query; does not affect the stream state
inline constexpr OperationAction SIGN_GET_SIZE = 5;

// SIGN_RESET
// Request:  data_node_id = context_id, no operation parameters
// Response: status_code (SUCCESS/error), no output parameters
// Effect:   Calls Reset(); key binding and algorithm are preserved
inline constexpr OperationAction SIGN_RESET = 6;

inline constexpr OperationAction SIGN_CUSTOM_OP_START = 1 << (std::numeric_limits<OperationAction>::digits - 1);

}  // namespace sign_handler_operations

// ============================================================================
// Signature verification operations (OP_ACTOR_VERIFY_HANDLER)
// ============================================================================
namespace verify_handler_operations
{
using OperationAction = common::OperationAction;

// VERIFY_INIT
// Request:  data_node_id = context_id, no operation parameters
// Response: status_code (SUCCESS/error), no output parameters
// Effect:   Calls InitVerify(), transitions state IDLE → INITIALIZED
inline constexpr OperationAction VERIFY_INIT = 1;

// VERIFY_UPDATE
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — message chunk whose signature is checked
// Response: status_code (SUCCESS/error), no output parameters
// Effect:   Calls UpdateVerify(), transitions state INITIALIZED/ACTIVE → ACTIVE
inline constexpr OperationAction VERIFY_UPDATE = 2;

// VERIFY_FINALIZE
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — signature to check (P1363 r‖s for ECDSA)
// Response: status_code (SUCCESS/error)
//           param[0]: bool — true when the signature is valid
// Effect:   Calls FinalizeVerify(), transitions state → IDLE.
//           An invalid signature is reported as SUCCESS + false, not as an error.
inline constexpr OperationAction VERIFY_FINALIZE = 3;

// VERIFY_SS (Single-Shot)
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — full message
//           param[1]: DataBuffer — signature to check
// Response: status_code (SUCCESS/error)
//           param[0]: bool — true when the signature is valid
// Effect:   Requires IDLE state; performs init + update + finalize in one call
inline constexpr OperationAction VERIFY_SS = 4;

// VERIFY_GET_SIZE
// Request:  data_node_id = context_id, no operation parameters
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — expected signature length in bytes
// Effect:   Stateless query; does not affect the stream state
inline constexpr OperationAction VERIFY_GET_SIZE = 5;

// VERIFY_RESET
// Request:  data_node_id = context_id, no operation parameters
// Response: status_code (SUCCESS/error), no output parameters
// Effect:   Calls Reset(); key binding and algorithm are preserved
inline constexpr OperationAction VERIFY_RESET = 6;

inline constexpr OperationAction VERIFY_CUSTOM_OP_START = 1 << (std::numeric_limits<OperationAction>::digits - 1);

}  // namespace verify_handler_operations
}  // namespace handler
}  // namespace provider
}  // namespace daemon
}  // namespace crypto
}  // namespace score

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_SIGNATURE_HANDLER_OPERATIONS_HPP
