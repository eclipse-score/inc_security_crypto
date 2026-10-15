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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_POLICY_ACCESS_POLICY_ENFORCER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_POLICY_ACCESS_POLICY_ENFORCER_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/trust_store_config.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <variant>

namespace score::crypto::daemon::cert_management
{

/// @brief UID-based access control for certificate slots and trust stores.
///
/// All access decisions are made here — providers never implement access control.
/// Kept local to cert_management (mirrors key_management::AccessPolicyEnforcer).
class AccessPolicyEnforcer
{
  public:
    /// @brief Certificate reads are unrestricted after resource resolution.
    static score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> CheckSlotAccess(
        const CertSlotConfig& slot,
        data_manager::ClientId client_id);

    /// @brief Check if client UID is in the slot's allowed_write_uids list.
    static score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> CheckWritePermission(
        const CertSlotConfig& slot,
        data_manager::ClientId client_id);

    /// @brief Trust-store reads are unrestricted after resource resolution.
    static score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    CheckTrustStoreAccess(const TrustStoreConfig& store, data_manager::ClientId client_id);

    /// @brief Check if client UID is in the trust store's allowed_write_uids list.
    static score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    CheckTrustStoreWritePermission(const TrustStoreConfig& store, data_manager::ClientId client_id);
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_POLICY_ACCESS_POLICY_ENFORCER_HPP
