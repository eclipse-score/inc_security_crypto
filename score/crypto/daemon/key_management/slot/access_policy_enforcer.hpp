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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_ACCESS_POLICY_ENFORCER_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_ACCESS_POLICY_ENFORCER_HPP

#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include <variant>

namespace score::crypto::daemon::key_management
{

/// @brief Centralized access control and policy enforcement.
///
/// All access decisions are made here — providers never implement access control.
/// Enforces UID-based access control, operation permission bitmasks, and resource
/// quotas. GID, application identity, and lifecycle state enforcement are
/// extension points.
class AccessPolicyEnforcer
{
  public:
    /// @brief Check if client UID is in the slot's allowed_uids list.
    ///
    /// @param slot       The slot configuration containing the access policy.
    /// @param client_id  Composite PID|UID of the requesting connection.
    /// @return std::monostate on success, or kAccessDenied.
    static score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> CheckSlotAccess(
        const KeySlotConfig& slot,
        data_manager::ClientId client_id);

    /// @brief Check if client UID is in the slot's allowed_write_uids list.
    ///
    /// Write access governs GenerateKey and key persist/import operations.
    ///
    /// @param slot       The slot configuration containing the access policy.
    /// @param client_id  Composite PID|UID of the requesting connection.
    /// @return std::monostate on success, or kAccessDenied.
    static score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> CheckWritePermission(
        const KeySlotConfig& slot,
        data_manager::ClientId client_id);

    /// @brief Check if the requested operation is in the slot's allowed_operations.
    ///
    /// @param slot           The slot configuration containing the permission set.
    /// @param requested_op   The operation being requested.
    /// @return std::monostate on success, or kKeyOperationNotPermitted.
    static score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    CheckOperationPermission(const KeySlotConfig& slot, score::mw::crypto::KeyOperationPermission requested_op);

    /// @brief Combined: access + operation check.
    ///
    /// @param slot           The slot configuration.
    /// @param client_id      Composite PID|UID.
    /// @param requested_op   The operation being requested.
    /// @return std::monostate on success, or the first error encountered.
    static score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Authorize(
        const KeySlotConfig& slot,
        data_manager::ClientId client_id,
        score::mw::crypto::KeyOperationPermission requested_op);

    /// @brief Check that `provider_id` is allowed to use this slot.
    ///
    /// For write operations (`is_write == true`), only the primary provider
    /// (`slot.provider_ids[0]`) is accepted. For read operations, any provider
    /// listed in `slot.provider_ids` is accepted.
    ///
    /// @param slot        The slot configuration containing the provider list.
    /// @param provider_id The provider requesting access.
    /// @param is_write    True for mutating operations (generate, store, delete).
    /// @return std::monostate on success, or kAccessDenied if the provider is not permitted.
    static score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    CheckProviderAccess(const KeySlotConfig& slot, const common::ProviderId& provider_id, bool is_write);
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_ACCESS_POLICY_ENFORCER_HPP
