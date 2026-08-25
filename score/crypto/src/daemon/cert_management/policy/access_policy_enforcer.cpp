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

#include "score/crypto/src/daemon/cert_management/policy/access_policy_enforcer.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <algorithm>

namespace score::crypto::daemon::cert_management
{

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
AccessPolicyEnforcer::CheckSlotAccess(const CertSlotConfig& slot, data_manager::ClientId client_id)
{
    // Certificate material is public information. Resource resolution still
    // uses the caller UID, but reading a resolved certificate is unrestricted.
    static_cast<void>(slot);
    static_cast<void>(client_id);
    return std::monostate{};
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
AccessPolicyEnforcer::CheckWritePermission(const CertSlotConfig& slot, data_manager::ClientId client_id)
{
    const uint32_t uid = control_plane::protocol::GetUidFromClientId(client_id);

    const auto& allowed = slot.access_policy.allowed_write_uids;
    // An omitted write allowlist must never grant mutation access.
    if (!allowed.empty() && std::find(allowed.begin(), allowed.end(), uid) != allowed.end())
    {
        return std::monostate{};
    }

    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAccessDenied);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
AccessPolicyEnforcer::CheckTrustStoreAccess(const TrustStoreConfig& store, data_manager::ClientId client_id)
{
    // Trust-store reads expose certificates, not private key material. The
    // application-resource mapping has already selected the store for UID.
    static_cast<void>(store);
    static_cast<void>(client_id);
    return std::monostate{};
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
AccessPolicyEnforcer::CheckTrustStoreWritePermission(const TrustStoreConfig& store, data_manager::ClientId client_id)
{
    const uint32_t uid = control_plane::protocol::GetUidFromClientId(client_id);

    const auto& allowed = store.access_policy.allowed_write_uids;
    // Trust-store mutations are default-deny: an explicit writer UID is
    // required even when read access is unrestricted.
    if (!allowed.empty() && std::find(allowed.begin(), allowed.end(), uid) != allowed.end())
    {
        return std::monostate{};
    }

    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAccessDenied);
}

}  // namespace score::crypto::daemon::cert_management
