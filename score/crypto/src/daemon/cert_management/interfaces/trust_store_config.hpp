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

/// Describes how a trust store manages a member certificate slot.
enum class TrustStoreMemberKind : uint8_t
{
    /// Slot content is externally managed; the trust store cannot add or remove
    /// the slot through its membership mutation operations.
    kSharedStatic = 0U,

    /// Slot content and membership are owned by the trust store, which may
    /// populate or clear the slot through trust-store operations.
    kExclusiveMutable = 1U,

    /// Slot content is externally managed and tracked by fingerprint. An
    /// unexpected content change disables the member until it is acknowledged.
    kConditionalExternal = 2U,
};

/// Initial state policy for conditional-external members without persisted state.
enum class ConditionalSlotInitialization : uint8_t
{
    /// Enable the member and record its current certificate fingerprint as accepted. When the store
    /// has a deployment path the acceptance is persisted first. A memory-only store (no deployment
    /// path) keeps it only for the life of the process, so each restart accepts whatever certificate
    /// the slot holds at that time.
    kEnableAndAcceptCurrent = 0U,

    /// Keep the member disabled until its current fingerprint is acknowledged.
    kDisableUntilAccepted = 1U,
};

/// Configured certificate-slot membership and its ownership policy.
struct TrustStoreMemberConfig
{
    /// Name of a certificate slot registered in the certificate-slot catalog.
    std::string slot_name;

    /// Ownership and change-acceptance policy for this member slot.
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

    /// Certificate slots serving as trust anchors, with explicit ownership policy.
    std::vector<TrustStoreMemberConfig> members;

    /// Default used only for conditional members without persisted state.
    ConditionalSlotInitialization conditional_slot_initialization{ConditionalSlotInitialization::kDisableUntilAccepted};

    /// UID-based access control for this trust store.
    AccessPolicy access_policy;

    /// Deployment descriptor for enabled state and accepted fingerprints; empty keeps them in memory only.
    std::string deployment_path;

    /// Serialization format identifier for the deployment descriptor.
    /// Defaults to "kv".
    std::string deployment_format{"kv"};
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_TRUST_STORE_CONFIG_HPP
