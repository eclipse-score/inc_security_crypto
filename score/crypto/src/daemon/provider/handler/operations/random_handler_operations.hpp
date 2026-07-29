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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_RANDOM_HANDLER_OPERATIONS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_RANDOM_HANDLER_OPERATIONS_HPP

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
namespace random_handler_operations
{
using OperationAction = common::OperationAction;

// ============================================================================
// Random number generation operations
// ============================================================================
// The random context is non-streaming: there is no state machine and every
// operation is valid at any time.
// ============================================================================

// RANDOM_GENERATE
// Request:  data_node_id = context_id,
//           param[0]: DataShm(InOut) — caller's output buffer; its length is the
//                     number of random bytes requested
// Response: status_code (SUCCESS/error)
//           param[0]: uint64_t — bytes written, always the full buffer length
inline constexpr OperationAction RANDOM_GENERATE = 1;

// RANDOM_SEED
// Request:  data_node_id = context_id,
//           param[0]: DataBuffer — additional entropy to mix into the RNG state
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Providers whose entropy source cannot be seeded externally report
//           SUCCESS without changing any state.
inline constexpr OperationAction RANDOM_SEED = 2;

inline constexpr OperationAction RANDOM_CUSTOM_OP_START = 1 << (std::numeric_limits<OperationAction>::digits - 1);

}  // namespace random_handler_operations
}  // namespace handler
}  // namespace provider
}  // namespace daemon
}  // namespace crypto
}  // namespace score

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_HANDLER_OPERATIONS_RANDOM_HANDLER_OPERATIONS_HPP
