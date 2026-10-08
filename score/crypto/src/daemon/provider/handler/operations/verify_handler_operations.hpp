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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_VERIFY_HANDLER_OPERATIONS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_VERIFY_HANDLER_OPERATIONS_HPP

#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/stream_operation.hpp"

#include <limits>
#include <optional>

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

/// @brief The stream state-machine step an action performs, if any.
/// @return std::nullopt for an action that does not take part in the stream.
[[nodiscard]] inline constexpr std::optional<StreamOperation> ToStreamOperation(OperationAction action) noexcept
{
    if (action == VERIFY_INIT)
    {
        return StreamOperation::kInit;
    }
    if (action == VERIFY_UPDATE)
    {
        return StreamOperation::kUpdate;
    }
    if (action == VERIFY_FINALIZE)
    {
        return StreamOperation::kFinalize;
    }
    return std::nullopt;
}

}  // namespace verify_handler_operations

}  // namespace handler
}  // namespace provider
}  // namespace daemon
}  // namespace crypto
}  // namespace score

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_VERIFY_HANDLER_OPERATIONS_HPP
