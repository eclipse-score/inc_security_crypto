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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_TRUST_STORE_CONFIG_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_TRUST_STORE_CONFIG_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/access_policy.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace score::crypto::daemon::cert_management
{

enum class TrustStoreMemberKind : uint8_t
{
    kSharedStatic = 0U,
    kExclusiveMutable = 1U,
    kConditionalExternal = 2U,
};

enum class ConditionalSlotInitialization : uint8_t
{
    kEnableAndAcceptCurrent = 0U,
    kDisableUntilAccepted = 1U,
};

struct TrustStoreMemberConfig
{
    std::string slot_name;
    TrustStoreMemberKind kind{TrustStoreMemberKind::kSharedStatic};
};

/// Configuration for a named trust store entry.
///
/// A trust store is a logical collection of trust anchors (CA certificates)
/// used for certificate chain verification. Member slots are certificate slots
/// already defined in the cert slot catalog; the trust store references them
/// by name. The same cert slot can back multiple trust stores.
///
/// Membership policy is fixed at startup. Runtime enablement, conditional
/// acceptance, and mutable membership state are deployment state; member-slot
/// certificate content is daemon-mediated through the slot handler.
struct TrustStoreConfig
{
    /// Human-readable name for this trust store (e.g., "tls-server-auth", "code-signing").
    std::string store_name;

    /// Certificate slots serving as trust anchors, with explicit membership policy.
    std::vector<TrustStoreMemberConfig> members;

    /// Default used only for conditional members without persisted state.
    ConditionalSlotInitialization conditional_slot_initialization{ConditionalSlotInitialization::kDisableUntilAccepted};

    /// UID-based access control for this trust store.
    AccessPolicy access_policy;

    /// Path to the deployment descriptor for this trust store entry.
    ///
    /// Used by the deployment layer to persist mutable trust-store state,
    /// including exclusive membership and conditional acceptance state.
    std::string deployment_path;
    std::string deployment_format{"kv"};
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_TRUST_STORE_CONFIG_HPP
