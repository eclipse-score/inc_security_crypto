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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_TRUST_STORE_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_TRUST_STORE_HANDLER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <span>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// Per-trust-store object managing a named collection of trust anchors.
///
/// A trust store is a logical set of CA certificates used as verification
/// anchors by the cert verification context handler.
///
/// All anchors are loaded from named certificate slots via the
/// CertSlotRegistry. Their content is daemon-mediated: a certificate write to
/// any member slot through CertManagementService refreshes the affected member
/// in every referencing store.
///
/// This interface is the read side that verification consumers use. Membership
/// is represented by typed certificate-slot references; runtime membership and
/// acceptance mutations belong to the concrete TrustStoreHandler, which
/// persists them in the trust-store deployment descriptor, and are reached
/// through TrustStoreManager.
///
/// Chain-building support:
///   FindBySubject and FindBySkid return nullable CertObject::Sptr for
///   efficient O(1) / O(log n) anchor lookup during chain building.
///
/// Thread safety: implementations synchronize their own state, so the read
/// methods may be called concurrently with member updates.
class ITrustStoreHandler
{
  public:
    using Sptr = std::shared_ptr<ITrustStoreHandler>;

    ITrustStoreHandler() = default;

    virtual ~ITrustStoreHandler() = default;

    ITrustStoreHandler(const ITrustStoreHandler&) = delete;
    ITrustStoreHandler& operator=(const ITrustStoreHandler&) = delete;
    ITrustStoreHandler(ITrustStoreHandler&&) = delete;
    ITrustStoreHandler& operator=(ITrustStoreHandler&&) = delete;

    // -----------------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------------

    /// Return the runtime handle for this trust store.
    ///
    /// The handle encodes the index in TrustStoreManager's internal table.
    /// Valid for the lifetime of the daemon; do not persist across restarts.
    [[nodiscard]] virtual TrustStoreHandle GetHandle() const noexcept = 0;

    // -----------------------------------------------------------------------
    // Anchor enumeration
    // -----------------------------------------------------------------------

    /// Return the enabled trust anchors of this store. Every entry is non-null.
    ///
    /// The result is complete: either every enabled member is resolved or an error is returned,
    /// never a partial set. An empty member slot contributes no anchor and is not an error.
    /// A failure to read an existing member certificate or CRL is returned.
    ///
    /// Caching: while a client holds the store (see TrustStoreManager::AddRef()) the result is
    /// served from the store's cache. Without a holder the members are resolved on each call and
    /// the result is not cached, so a call is correct but slower and keeps nothing alive.
    [[nodiscard]] virtual score::crypto::Expected<std::vector<CertObject::Sptr>,
                                                  score::crypto::daemon::common::DaemonErrorCode>
    GetAnchors() = 0;

    // -----------------------------------------------------------------------
    // CRL access — same caching behaviour as the anchors
    // -----------------------------------------------------------------------

    /// Return the CRL snapshots of the enabled members that have one. Every entry is non-null.
    ///
    /// Used by the verification handler when CRL-based revocation checking is active. The
    /// snapshots are immutable and shared with the slot-level cache; a CRL update replaces a
    /// member's snapshot and does not modify one already returned. A failure to read an
    /// existing CRL is returned, so a CRL is never silently omitted. Caching follows
    /// GetAnchors().
    [[nodiscard]] virtual score::crypto::Expected<std::vector<CrlData::Sptrc>,
                                                  score::crypto::daemon::common::DaemonErrorCode>
    GetCrls() = 0;

    // -----------------------------------------------------------------------
    // Chain-building lookup indices
    // -----------------------------------------------------------------------

    /// Find a trust anchor by its RFC 4514 canonical Subject DN.
    ///
    /// Used during chain building to match an intermediate certificate's
    /// issuer field against the anchors in this trust store.
    ///
    /// Returns a non-null CertObject::Sptr when a matching anchor is found,
    /// nullptr otherwise, including when the anchors cannot be resolved (callers
    /// must check before dereferencing).
    [[nodiscard]] virtual CertObject::Sptr FindBySubject(const std::string& canonical_subject) = 0;

    /// Find a trust anchor by its Subject Key Identifier (SKID) extension value.
    ///
    /// Used during chain building to match an intermediate certificate's
    /// Authority Key Identifier (AKID) against the anchors in this trust store.
    ///
    /// skid contains the raw SKID extension bytes (variable length; typically 20).
    ///
    /// Returns a non-null CertObject::Sptr when a matching anchor is found,
    /// nullptr otherwise, including when the anchors cannot be resolved.
    [[nodiscard]] virtual CertObject::Sptr FindBySkid(score::crypto::span<const uint8_t> skid) = 0;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_TRUST_STORE_HANDLER_HPP
