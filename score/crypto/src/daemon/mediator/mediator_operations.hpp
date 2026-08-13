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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_OPERATIONS_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_OPERATIONS_HPP

#include <cstddef>
#include <cstdint>
#include <limits>

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

namespace score::crypto::daemon::mediator::operations
{

/// @brief Identifies the shared memory transport backend used for a region.
///
/// The daemon returns this in the SHM_SETUP response (param[3]) so the
/// client knows how to open and map the shared memory region.
enum class ShmTransportType : std::uint8_t
{
    kPosixNamed = 0,
    kTypedRegion = 1,
};

/// @brief Wire sentinel: indicates transport type was not included in the response (backward compat).
inline constexpr std::uint64_t SHM_WIRE_TRANSPORT_TYPE_ABSENT = 0xFFU;

inline constexpr std::uint64_t SHM_WIRE_PROVIDER_TYPE_ABSENT = 0xFFU;

inline constexpr std::uint64_t SHM_WIRE_PROVIDER_ID_UNBOUND = 0U;

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

// SHM_SETUP
// Request:  uint64_t — size (bytes; 0 for pool — daemon uses deployment config size)
//           uint64_t — wire ProviderType hint (SHM_WIRE_PROVIDER_TYPE_ABSENT if absent)
//           uint64_t — numeric provider id hint (SHM_WIRE_PROVIDER_ID_UNBOUND if absent)
//           uint64_t — is_pool (0 = bulk object, 1 = pool object)
//
// Response (is_pool=0 — bulk):
//           status_code (SUCCESS)
//           param[0]: uint64_t   — node_id
//           param[1]: uint64_t   — actual_size
//           param[2]: DataBuffer — wire_token
//           param[3]: uint64_t   — transport_type
//
// Response (is_pool=1 — pool, extends bulk layout at params [4..5]):
//           same as is_pool=0 PLUS:
//           param[4]: uint64_t — pool_slot_size
//           param[5]: uint64_t — total_quota
inline constexpr OperationAction SHM_SETUP = 4;

// SHM_SETUP response parameter indices (wire protocol contract shared by daemon and client).
inline constexpr std::size_t SHM_PARAM_NODE_ID = 0;
inline constexpr std::size_t SHM_PARAM_SIZE = 1;
inline constexpr std::size_t SHM_PARAM_TOKEN = 2;
inline constexpr std::size_t SHM_PARAM_TRANSPORT = 3;
inline constexpr std::size_t SHM_PARAM_SLOT_SIZE = 4;
inline constexpr std::size_t SHM_PARAM_TOTAL_QUOTA = 5;

// SHM_DESTROY_OBJECT
// Request:  uint64_t — node_id
// Response: status_code (SUCCESS/error)
//           no output parameters
// Effect:   Unmaps and unlinks the SHM object, removes it from the daemon registry.
inline constexpr OperationAction SHM_DESTROY_OBJECT = 5;

inline control_plane::protocol::OperationIdentifier CreateShmObject()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::SHM_SETUP};
}
inline control_plane::protocol::OperationIdentifier DestroyShmObject()
{
    return control_plane::protocol::OperationIdentifier{.operationActor = common::actors::OP_ACTOR_MEDIATOR,
                                                        .operationAction = operations::SHM_DESTROY_OBJECT};
}

// Starting point for custom OPs
inline constexpr OperationAction CUSTOM_OP_START = 1 << (std::numeric_limits<OperationAction>::digits - 1);

}  // namespace score::crypto::daemon::mediator::operations

#endif  // SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_MEDIATOR_OPERATIONS_HPP
