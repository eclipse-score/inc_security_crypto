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

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/context_types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
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

/// @brief Wire sentinel indicating that no provider ID hint is available.
///
/// Provider IDs are zero-based, so zero cannot represent an absent provider.
inline constexpr std::uint64_t SHM_WIRE_PROVIDER_ID_UNBOUND = common::kInvalidProviderId;
static_assert(SHM_WIRE_PROVIDER_ID_UNBOUND == score::crypto::kUnboundProviderId);

using OperationAction = common::OperationAction;

/// @brief Classification of a provider ID received through the SHM wire contract.
enum class ProviderIdHintState : std::uint8_t
{
    kBound,    ///< A valid provider ID was supplied.
    kUnbound,  ///< The explicit unbound sentinel was supplied.
    kInvalid,  ///< The wire value cannot be represented as a ProviderId.
};

/// @brief Validated provider ID hint decoded from the SHM wire contract.
struct ProviderIdHint final
{
    ProviderIdHintState state{ProviderIdHintState::kInvalid};
    common::ProviderId provider_id{common::kInvalidProviderId};
};

/// @brief Validate and decode a provider ID received as a 64-bit wire value.
///
/// The unbound sentinel is reserved and therefore is not a usable provider ID.
/// Values wider than ProviderId are rejected before narrowing.
[[nodiscard]] inline constexpr ProviderIdHint DecodeProviderIdHint(const std::uint64_t wire_value) noexcept
{
    if (wire_value == SHM_WIRE_PROVIDER_ID_UNBOUND)
    {
        return ProviderIdHint{ProviderIdHintState::kUnbound, common::kInvalidProviderId};
    }
    if (wire_value > std::numeric_limits<common::ProviderId>::max())
    {
        return ProviderIdHint{ProviderIdHintState::kInvalid, common::kInvalidProviderId};
    }
    return ProviderIdHint{ProviderIdHintState::kBound, static_cast<common::ProviderId>(wire_value)};
}

/// @brief Convert provider resolution into a resource/SHM provider hint.
///
/// Provider resolution is advisory for resource lookup. Any resolution error
/// therefore becomes the invalid-provider sentinel instead of failing an
/// otherwise valid resource resolution.
[[nodiscard]] inline common::ProviderId ProviderHintOrInvalid(
    const score::crypto::Expected<common::ProviderId, common::DaemonErrorCode>& provider_result)
{
    return provider_result.has_value() ? provider_result.value() : common::kInvalidProviderId;
}

/// @brief Append a successful key-slot resource response with an advisory provider hint.
///
/// A provider-resolution error is encoded as kInvalidProviderId while the
/// resource response remains successful.
inline void ReturnResolvedKeySlot(
    const std::uint64_t node_id,
    const score::crypto::Expected<common::ProviderId, common::DaemonErrorCode>& provider_result,
    const common::OperationIdentifier& operation_id,
    control_plane::protocol::OperationResponseBuilder& response_builder)
{
    response_builder.operation(operation_id)
        .return_value_uint64(node_id)
        .return_value_uint8(static_cast<std::uint8_t>(score::crypto::ResourceType::kKeySlot))
        .return_value_bool(true)
        .return_value_uint16(ProviderHintOrInvalid(provider_result))
        .return_success();
}

// ============================================================================
// Common Mediator Operations
// ============================================================================

/// @brief Maps a CTX_CREATE context-type scope prefix to its required capability.
struct ContextScopeCapability final
{
    std::string_view scope;
    common::ProviderCapability capability;
};

/// @brief Scope prefixes recognized by CTX_CREATE for capability-based provider routing.
///
/// The scope is the case-sensitive substring before the first ':' in the context type
/// (common::context_types::ScopeOf). Context types without a recognized scope add no
/// capability constraint.
inline constexpr std::array<ContextScopeCapability, 2> kContextScopeCapabilities{{
    {common::context_types::kCertScope, common::ProviderCapability::kCertManagement},
    {common::context_types::kKeyScope, common::ProviderCapability::kKeyManagement},
}};

/// @brief The provider capability a CTX_CREATE of @p context_type requires.
/// @return the capability mapped to the type's scope, or kNone if the type is
///         unscoped or its scope is not in kContextScopeCapabilities.
[[nodiscard]] inline constexpr common::ProviderCapability RequiredProviderCapability(
    const std::string_view context_type) noexcept
{
    const auto scope = common::context_types::ScopeOf(context_type);
    if (scope.empty())
    {
        return common::ProviderCapability::kNone;
    }
    for (const auto& scope_capability : kContextScopeCapabilities)
    {
        if (scope == scope_capability.scope)
        {
            return scope_capability.capability;
        }
    }
    return common::ProviderCapability::kNone;
}

/// @brief Daemon-side interpretation of a public ProviderType wire value.
struct ProviderTypePreference final
{
    common::CryptoProviderType primary;
    std::optional<common::CryptoProviderType> fallback;
};

/// @brief Decode the stable ProviderType wire contract without losing preferred-provider fallback semantics.
/// @return The decoded preference, or std::nullopt for an unknown wire value.
[[nodiscard]] inline constexpr std::optional<ProviderTypePreference> DecodeProviderTypePreference(
    const std::uint8_t wire_value) noexcept
{
    using ProviderType = common::CryptoProviderType;

    switch (wire_value)
    {
        case 0U:
            return ProviderTypePreference{ProviderType::DEFAULT, std::nullopt};
        case 1U:
            return ProviderTypePreference{ProviderType::HARDWARE, std::nullopt};
        case 2U:
            return ProviderTypePreference{ProviderType::SOFTWARE, std::nullopt};
        case 3U:
            return ProviderTypePreference{ProviderType::HARDWARE, ProviderType::SOFTWARE};
        case 4U:
            return ProviderTypePreference{ProviderType::SOFTWARE, ProviderType::HARDWARE};
        default:
            return std::nullopt;
    }
}

// CTX_CREATE
// Request:  data_node_id = connection_id (parent node),
//           param[0]: string — handler context type (e.g. "HASH" or "CERT:...")
//           param[1]: string — algorithm name (e.g. "SHA256", "SHA512")
//           param[2]: optional uint8 — provider type preference (defaults to DEFAULT)
//           param[3]: optional uint64_t — node_id of key resource (CryptoResourceId.id)
//           param[4]: optional uint8 — common::ContextMode (keyed contexts)
//           param[5]: optional uint8 — CipherPadding (cipher contexts)
//           param[6]: optional uint8 — SignatureInputMode (sign/verify contexts; param[5] is no-param)
// Capability routing: a recognized scope uses capability-based selection when the provider
// preference is DEFAULT. Explicit provider preferences and key-bound selection are still
// checked against the scope's required capability. Unrecognized or absent scopes add no
// capability constraint and follow existing provider selection rules (provider-type
// preference or key affinity). The full context type is passed to the handler factory unchanged.
// Response: status_code (SUCCESS/error)
//           uint64_t — daemon-assigned context_id (DataNodeId)
// Effect:   Creates cryptographic context, initializes handler with specified algorithm
inline constexpr OperationAction CTX_CREATE = 1;

// Stable CTX_CREATE parameter positions. Handler-specific extensions may use
// later positions; the mediator validates only the common prefix.
inline constexpr std::size_t CTX_PARAM_HANDLER_TYPE = 0U;
inline constexpr std::size_t CTX_PARAM_ALGORITHM = 1U;
inline constexpr std::size_t CTX_PARAM_PROVIDER_TYPE = 2U;
inline constexpr std::size_t CTX_PARAM_KEY_NODE_ID = 3U;
inline constexpr std::size_t CTX_PARAM_OPERATION_MODE = 4U;
inline constexpr std::size_t CTX_PARAM_CIPHER_PADDING = 5U;

/// @brief Defensive upper bound for malformed CTX_CREATE requests.
///
/// This is intentionally larger than the common prefix so handlers can add
/// opaque parameters without requiring mediator changes.
inline constexpr std::size_t CTX_MAX_PARAMETER_COUNT = 10U;

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
