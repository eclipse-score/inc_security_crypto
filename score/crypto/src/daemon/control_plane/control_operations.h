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

#ifndef SCORE_CRYPTO_DAEMON_CONTROL_PLANE_CONTROL_OPERATIONS_H
#define SCORE_CRYPTO_DAEMON_CONTROL_PLANE_CONTROL_OPERATIONS_H

#include "control_protocol.h"
#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/common/types.hpp"

#include <limits>

namespace score::crypto::daemon::control_plane::operations
{

using OperationAction = common::OperationAction;

// ============================================================================
// Common Control Plane Operations
// ============================================================================

// CONNECTION_OPEN
// Request:  data_node_id = 0 (no parent),
//           no operation parameters
// Response: status_code (SUCCESS/error)
//           uint64_t — daemon-assigned connection_id (root DataNodeId)
// Effect:   Creates a root DataNode, initializes connection context
inline constexpr OperationAction CONNECTION_OPEN = 1;

// CONNECTION_CLOSE
// Request:  data_node_id = connection_id,
//           no operation parameters
// Response: status_code (SUCCESS)
//           no output parameters
// Effect:   Deletes the connection node and cascade-deletes all child context nodes
inline constexpr OperationAction CONNECTION_CLOSE = 2;

// Starting point for custom OPs
inline constexpr OperationAction CUSTOM_OP_START = 1 << (std::numeric_limits<OperationAction>::digits - 1);

// Helpers
inline protocol::OperationIdentifier OpenConnection()
{
    return protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_CONTROL,
                                         .operationAction = operations::CONNECTION_OPEN};
}

inline protocol::OperationIdentifier CloseConnection()
{
    return protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_CONTROL,
                                         .operationAction = operations::CONNECTION_CLOSE};
}

}  // namespace score::crypto::daemon::control_plane::operations

#endif  // SCORE_CRYPTO_DAEMON_CONTROL_PLANE_CONTROL_OPERATIONS_H
