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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_OPERATION_NAMES_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_OPERATION_NAMES_HPP

/// @file operation_names.hpp
/// @brief Human-readable names for OperationActor and OperationAction values.
///
/// Provides constexpr lookup functions and a stream-insertable wrapper so that
/// daemon log messages display symbolic operation names instead of raw integers.
///
/// ### Usage
/// @code
///   // Instead of:
///   score::mw::log::LogDebug() << "action=" << opId.operationAction ;
///
///   // Write:
///   score::mw::log::LogDebug() << common::OpId{opId} ;
///   // Output: "HASH_HANDLER::HASH_FINALIZE [actor=4, action=3]"
/// @endcode
///
/// ### Design notes
/// - Header-only: lookup functions are constexpr and do not use runtime tables.
/// - Covers the operation namespaces currently registered by this component.
/// - Falls back to "<unknown_actor>" / "<unknown_op>" for future or custom values,
///   while still printing the numeric ids so nothing is lost.

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

// Operation constants — these headers only depend on types.hpp (no circular risk).
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/kem_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/mac_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/sign_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/verify_handler_operations.hpp"

#include "score/mw/log/logging.h"
#include <ostream>
#include <string_view>

namespace score::crypto::daemon::common
{

/// @brief Returns the symbolic name for a registered OperationActor value.
/// @return Symbolic actor name, or "<unknown_actor>" for unknown actors.
constexpr std::string_view ActorName(OperationActor actor) noexcept
{
    switch (actor)
    {
        case actors::OP_ACTOR_CONTROL:
            return "CONTROL";
        case actors::OP_ACTOR_MEDIATOR:
            return "MEDIATOR";
        case actors::OP_ACTOR_PROVIDER:
            return "PROVIDER";
        case actors::OP_ACTOR_HASH_HANDLER:
            return "HASH_HANDLER";
        case actors::OP_ACTOR_KEY_MANAGEMENT:
            return "KEY_MGMT";
        case actors::OP_ACTOR_MAC_HANDLER:
            return "MAC_HANDLER";
        case actors::OP_ACTOR_SIGN_HANDLER:
            return "SIGN_HANDLER";
        case actors::OP_ACTOR_VERIFY_HANDLER:
            return "VERIFY_HANDLER";
        case actors::OP_ACTOR_KEM_HANDLER:
            return "KEM_HANDLER";
        default:
            return "<unknown_actor>";
    }
}

/// @brief Returns the symbolic name for an OperationAction within the given actor's namespace.
///
/// The actor context is required because the same action integer has different meanings
/// across actors (e.g., action=1 is CTX_CREATE for MEDIATOR but HASH_INIT for HASH_HANDLER).
/// @return Symbolic operation name, or an actor-specific unknown-operation marker
///         if the action is not registered.
constexpr std::string_view ActionName(OperationActor actor, OperationAction action) noexcept
{
    // Mediator action constants (mediator_operations.hpp cannot be included here without
    // pulling in control_protocol.h — the values are stable and documented there).
    constexpr OperationAction kMediatorCtxCreate = 1;
    constexpr OperationAction kMediatorCtxClose = 2;
    constexpr OperationAction kMediatorResolveResource = 3;

    namespace hash_ops = provider::handler::hash_handler_operations;
    namespace mac_ops = provider::handler::mac_handler_operations;
    namespace km_ops = key_management::operations;

    switch (actor)
    {
        case actors::OP_ACTOR_MEDIATOR:
            switch (action)
            {
                case kMediatorCtxCreate:
                    return "CTX_CREATE";
                case kMediatorCtxClose:
                    return "CTX_CLOSE";
                case kMediatorResolveResource:
                    return "RESOLVE_RESOURCE";
                default:
                    return "<unknown_mediator_op>";
            }

        case actors::OP_ACTOR_HASH_HANDLER:
            switch (action)
            {
                case hash_ops::HASH_INIT:
                    return "HASH_INIT";
                case hash_ops::HASH_UPDATE:
                    return "HASH_UPDATE";
                case hash_ops::HASH_FINALIZE:
                    return "HASH_FINALIZE";
                case hash_ops::HASH_SS:
                    return "HASH_SS";
                case hash_ops::HASH_GET_DIGEST_SIZE:
                    return "HASH_GET_DIGEST_SIZE";
                case hash_ops::HASH_RESET:
                    return "HASH_RESET";
                default:
                    return "<unknown_hash_op>";
            }

        case actors::OP_ACTOR_MAC_HANDLER:
            switch (action)
            {
                case mac_ops::MAC_INIT:
                    return "MAC_INIT";
                case mac_ops::MAC_UPDATE:
                    return "MAC_UPDATE";
                case mac_ops::MAC_FINALIZE:
                    return "MAC_FINALIZE";
                case mac_ops::MAC_VERIFY:
                    return "MAC_VERIFY";
                case mac_ops::MAC_GET_SIZE:
                    return "MAC_GET_SIZE";
                case mac_ops::MAC_RESET:
                    return "MAC_RESET";
                case mac_ops::MAC_SS:
                    return "MAC_SS";
                default:
                    return "<unknown_mac_op>";
            }

        case actors::OP_ACTOR_SIGN_HANDLER:
            switch (action)
            {
                case provider::handler::sign_handler_operations::SIGN_INIT:
                    return "SIGN_INIT";
                case provider::handler::sign_handler_operations::SIGN_UPDATE:
                    return "SIGN_UPDATE";
                case provider::handler::sign_handler_operations::SIGN_FINALIZE:
                    return "SIGN_FINALIZE";
                case provider::handler::sign_handler_operations::SIGN_SS:
                    return "SIGN_SS";
                case provider::handler::sign_handler_operations::SIGN_GET_SIGNATURE_SIZE:
                    return "SIGN_GET_SIGNATURE_SIZE";
                case provider::handler::sign_handler_operations::SIGN_RESET:
                    return "SIGN_RESET";
                default:
                    return "<unknown_sign_op>";
            }

        case actors::OP_ACTOR_VERIFY_HANDLER:
            switch (action)
            {
                case provider::handler::verify_handler_operations::VERIFY_INIT:
                    return "VERIFY_INIT";
                case provider::handler::verify_handler_operations::VERIFY_UPDATE:
                    return "VERIFY_UPDATE";
                case provider::handler::verify_handler_operations::VERIFY_FINALIZE:
                    return "VERIFY_FINALIZE";
                case provider::handler::verify_handler_operations::VERIFY_SS:
                    return "VERIFY_SS";
                case provider::handler::verify_handler_operations::VERIFY_RESET:
                    return "VERIFY_RESET";
                default:
                    return "<unknown_verify_op>";
            }

        case actors::OP_ACTOR_KEM_HANDLER:
            switch (action)
            {
                case provider::handler::kem_handler_operations::KEM_KEYGEN:
                    return "KEM_KEYGEN";
                case provider::handler::kem_handler_operations::KEM_ENCAPSULATE:
                    return "KEM_ENCAPSULATE";
                case provider::handler::kem_handler_operations::KEM_DECAPSULATE:
                    return "KEM_DECAPSULATE";
                case provider::handler::kem_handler_operations::KEM_RESET:
                    return "KEM_RESET";
                default:
                    return "<unknown_kem_op>";
            }

        case actors::OP_ACTOR_KEY_MANAGEMENT:
            switch (action)
            {
                case km_ops::KEY_GENERATE:
                    return "KEY_GENERATE";
                case km_ops::KEY_GENERATE_TO_SLOT:
                    return "KEY_GENERATE_TO_SLOT";
                case km_ops::KEY_PERSIST:
                    return "KEY_PERSIST";
                case km_ops::KEY_DERIVE:
                    return "KEY_DERIVE";
                case km_ops::KEY_DERIVE_TO_SLOT:
                    return "KEY_DERIVE_TO_SLOT";
                case km_ops::KEY_AGREE:
                    return "KEY_AGREE";
                case km_ops::KEY_AGREE_TO_SLOT:
                    return "KEY_AGREE_TO_SLOT";
                case km_ops::KEY_WRAP:
                    return "KEY_WRAP";
                case km_ops::KEY_GET_WRAP_SIZE:
                    return "KEY_GET_WRAP_SIZE";
                case km_ops::KEY_UNWRAP:
                    return "KEY_UNWRAP";
                case km_ops::KEY_UNWRAP_TO_SLOT:
                    return "KEY_UNWRAP_TO_SLOT";
                case km_ops::KEY_IMPORT:
                    return "KEY_IMPORT";
                case km_ops::KEY_IMPORT_TO_SLOT:
                    return "KEY_IMPORT_TO_SLOT";
                case km_ops::KEY_LOAD:
                    return "KEY_LOAD";
                case km_ops::KEY_EXPORT:
                    return "KEY_EXPORT";
                case km_ops::KEY_GET_EXPORT_SIZE:
                    return "KEY_GET_EXPORT_SIZE";
                case km_ops::KEY_SLOT_INFO:
                    return "KEY_SLOT_INFO";
                case km_ops::KEY_CLEAR:
                    return "KEY_CLEAR";
                case km_ops::KEY_RELEASE:
                    return "KEY_RELEASE";
                default:
                    return "<unknown_key_mgmt_op>";
            }

        default:
            return "<unknown_op>";
    }
}

/// @brief Lightweight stream-insertable wrapper for OperationIdentifier.
///
/// Prints both the symbolic name and the numeric ids so logs are unambiguous even
/// for custom or future operations not yet registered in ActionName().
///
/// @code
///   score::mw::log::LogDebug() << "[MED] dispatching" << common::OpId{opId} ;
///   // → "[MED] dispatching HASH_HANDLER::HASH_UPDATE [actor=4, action=2]"
/// @endcode
struct OpId
{
    const OperationIdentifier& id;
};

inline std::ostream& operator<<(std::ostream& os, const OpId& op)
{
    return os << ActorName(op.id.operationActor) << "::" << ActionName(op.id.operationActor, op.id.operationAction)
              << " [actor=" << op.id.operationActor << ", action=" << op.id.operationAction << "]";
}

inline score::mw::log::LogStream& operator<<(score::mw::log::LogStream& os, const OpId& op)
{
    return os << ActorName(op.id.operationActor) << "::" << ActionName(op.id.operationActor, op.id.operationAction)
              << " [actor=" << static_cast<uint32_t>(op.id.operationActor)
              << ", action=" << static_cast<uint32_t>(op.id.operationAction) << "]";
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_OPERATION_NAMES_HPP
