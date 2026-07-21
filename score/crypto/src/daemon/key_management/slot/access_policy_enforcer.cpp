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

#include "score/crypto/daemon/key_management/slot/access_policy_enforcer.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"

#include <algorithm>

namespace score::crypto::daemon::key_management
{

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
AccessPolicyEnforcer::CheckSlotAccess(const KeySlotConfig& slot, data_manager::ClientId client_id)
{
    const uint32_t uid = control_plane::protocol::GetUidFromClientId(client_id);

    const auto& allowed = slot.access_policy.allowed_uids;
    if (std::find(allowed.begin(), allowed.end(), uid) != allowed.end())
    {
        return std::monostate{};
    }

    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAccessDenied);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
AccessPolicyEnforcer::CheckWritePermission(const KeySlotConfig& slot, data_manager::ClientId client_id)
{
    const uint32_t uid = control_plane::protocol::GetUidFromClientId(client_id);

    const auto& allowed = slot.access_policy.allowed_write_uids;
    if (std::find(allowed.begin(), allowed.end(), uid) != allowed.end())
    {
        return std::monostate{};
    }

    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAccessDenied);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
AccessPolicyEnforcer::CheckOperationPermission(const KeySlotConfig& slot,
                                               score::mw::crypto::KeyOperationPermission requested_op)
{
    if (score::mw::crypto::HasPermission(slot.allowed_operations, requested_op))
    {
        return std::monostate{};
    }

    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kKeyOperationNotPermitted);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> AccessPolicyEnforcer::Authorize(
    const KeySlotConfig& slot,
    data_manager::ClientId client_id,
    score::mw::crypto::KeyOperationPermission requested_op)
{
    auto access_result = CheckSlotAccess(slot, client_id);
    if (!access_result.has_value())
    {
        return access_result;
    }

    // kNone means no specific operation check needed (e.g., ResolveResource)
    if (requested_op != score::mw::crypto::KeyOperationPermission::kNone)
    {
        auto perm_result = CheckOperationPermission(slot, requested_op);
        if (!perm_result.has_value())
        {
            return perm_result;
        }
    }

    return std::monostate{};
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
AccessPolicyEnforcer::CheckProviderAccess(const KeySlotConfig& slot,
                                          const common::ProviderId& provider_id,
                                          bool is_write)
{
    if (is_write)
    {
        // Only the primary provider (index 0) may mutate the slot.
        if (!slot.provider_ids.empty() && slot.provider_ids.front() == provider_id)
        {
            return std::monostate{};
        }
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAccessDenied);
    }

    // Read / consume: any listed provider is accepted.
    if (slot.IsProviderAllowed(provider_id))
    {
        return std::monostate{};
    }
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAccessDenied);
}

}  // namespace score::crypto::daemon::key_management
