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

#ifndef SCORE_CRYPTO_DAEMON_MEDIATOR_MEDIATOR_OPERATIONS_HPP_
#define SCORE_CRYPTO_DAEMON_MEDIATOR_MEDIATOR_OPERATIONS_HPP_

#include <limits>

#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"

namespace score::crypto::daemon::mediator::operations
{

using OperationAction = common::OperationAction;

// ============================================================================
// Common Mediator Operations
// ============================================================================

// CTX_CREATE
// Request:  data_node_id = connection_id (parent node),
//           param[0]: string — handler type (e.g. "HASH")
//           param[1]: string — algorithm name (e.g. "SHA256", "SHA512")
//           param[2]: optional uint8 — provider type preference (defaults to DEFAULT)
//           param[3]: optional uint64_t — node_id of key resource (CryptoResourceId.id)
// Response: status_code (SUCCESS/error)
//           uint64_t — daemon-assigned context_id (DataNodeId)
// Effect:   Creates cryptographic context, initializes handler with specified algorithm
inline constexpr OperationAction CTX_CREATE = 1;

// CTX_CLOSE
// Request:  data_node_id = context_id (the context to close),
//           no operation parameters
// Response: status_code (SUCCESS)
//           no output parameters
// Effect:   Deletes the context node from DataManager
inline constexpr OperationAction CTX_CLOSE = 2;

// RESOURCE_RESOLVE
// Request:  data_node_id = connection_id,
//           param[0]: string — application-defined resource name (e.g., "HMAC_SHA256_IntegrationTestKey")
//           param[1]: uint8  — ResourceType enum value (e.g., 1 = kKeySlot)
// Response: status_code (SUCCESS/error)
//           param[0]: uint64 — daemon-assigned resource id
//           param[1]: uint8  — ResourceType enum value
//           param[2]: bool  — True if resource is persistent, false if ephemeral
//           param[3]: uint16 — primary_provider id
// Effect:   Resolves a named resource to a daemon-scoped CryptoResourceId.
//           Access control (uid-based) is enforced during resolution.
inline constexpr OperationAction RESOLVE_RESOURCE = 3;

inline control_plane::protocol::OperationIdentifier CreateContext()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::CTX_CREATE};
}
inline control_plane::protocol::OperationIdentifier CloseContext()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::CTX_CLOSE};
}
inline control_plane::protocol::OperationIdentifier ResolveResource()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::RESOLVE_RESOURCE};
}

// Starting point for custom OPs
inline constexpr OperationAction CUSTOM_OP_START = 1 << (std::numeric_limits<OperationAction>::digits - 1);

}  // namespace score::crypto::daemon::mediator::operations

#endif  // SCORE_CRYPTO_DAEMON_MEDIATOR_MEDIATOR_OPERATIONS_HPP_
