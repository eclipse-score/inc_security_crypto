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
/// CertSlotRegistry. Their content is daemon-mediated: a SaveCertificate to
/// any member slot triggers NotifySlotUpdate() on every referencing store.
///
/// Membership is represented by typed certificate-slot references. Runtime
/// membership and acceptance mutations are coordinated by TrustStoreManager
/// and persisted in the trust-store deployment descriptor.
///
/// Chain-building support:
///   FindBySubject and FindBySkid return nullable CertObject::Sptr for
///   efficient O(1) / O(log n) anchor lookup during chain building.
///
/// Thread safety: ITrustStoreHandler instances are not individually thread-safe.
/// TrustStoreManager coordinates concurrent access.
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

    /// Return all current enabled slot-backed trust anchors.
    ///
    /// Slot-backed anchors may be null if the underlying cert slot is empty.
    /// Callers should filter out null entries before passing to a verifier.
    ///
    /// Returns kInternalError when the anchor set cannot be assembled
    /// (e.g., static file I/O failure during lazy reload).
    ///
    /// Lifetime contract: callers must bracket every usage of GetAnchors() with
    /// TrustStoreManager::AddRef() before the first call and ReleaseRef() after
    /// the last call. AddRef pins the anchor cache so it is not evicted while
    /// certs are in use; ReleaseRef allows eviction when no client holds refs.
    /// Calling GetAnchors() without a matching AddRef/ReleaseRef pair populates
    /// the cache with no corresponding cleanup trigger — the loaded certs will
    /// remain in memory until an unrelated ReleaseRef happens to evict them.
    /// The sole production call path (ScoreCertVerificationHandler) already
    /// satisfies this contract; direct calls are only safe in tests or
    /// read-only tooling where memory lifetime is not a concern.
    [[nodiscard]] virtual score::crypto::Expected<std::vector<CertObject::Sptr>,
                                                  score::crypto::daemon::common::DaemonErrorCode>
    GetAnchors() = 0;

    // -----------------------------------------------------------------------
    // Slot update notification (called by TrustStoreManager)
    // -----------------------------------------------------------------------

    /// Update the in-memory anchor for the given cert slot.
    ///
    /// Called by TrustStoreManager::NotifyUpdate() when SaveCertificate writes
    /// to a member slot. If cert is nullptr, the slot's anchor entry is
    /// cleared (models an empty slot).
    ///
    /// Implementations must update the internal slot->anchor mapping and
    /// invalidate / refresh the chain-building indices (FindBySubject, FindBySkid).
    virtual void NotifySlotUpdate(CertSlotHandle slot, CertObject::Sptr cert) = 0;

    // -----------------------------------------------------------------------
    // CRL cache — co-located with the anchor cache
    // -----------------------------------------------------------------------

    /// Return all CRL entries currently cached for enabled member slots.
    ///
    /// Entries are loaded lazily alongside the anchor cache (EnsureLoaded).
    /// Used by the OpenSSL verification handler when kCrlOnly revocation
    /// checking is active — avoids re-reading CRL files on every Verify() call.
    [[nodiscard]] virtual std::vector<CrlEntry> GetCrls() = 0;

    /// Update the in-memory CRL cache for a single slot.
    ///
    /// Called by TrustStoreManager after a successful StoreCrl (AddMember or
    /// ImportCrlForMember) to keep the cache coherent without a full reload.
    /// An empty @p entry evicts the slot's CRL from the cache.
    virtual void NotifyCrlUpdate(CertSlotHandle slot, std::optional<CrlEntry> entry) = 0;

    // -----------------------------------------------------------------------
    // Chain-building lookup indices
    // -----------------------------------------------------------------------

    /// Find a trust anchor by its RFC 4514 canonical Subject DN.
    ///
    /// Used during chain building to match an intermediate certificate's
    /// issuer field against the anchors in this trust store.
    ///
    /// Returns a non-null CertObject::Sptr when a matching anchor is found,
    /// nullptr otherwise (callers must check before dereferencing).
    [[nodiscard]] virtual CertObject::Sptr FindBySubject(const std::string& canonical_subject) const = 0;

    /// Find a trust anchor by its Subject Key Identifier (SKID) extension value.
    ///
    /// Used during chain building to match an intermediate certificate's
    /// Authority Key Identifier (AKID) against the anchors in this trust store.
    ///
    /// skid contains the raw SKID extension bytes (variable length; typically 20).
    ///
    /// Returns a non-null CertObject::Sptr when a matching anchor is found,
    /// nullptr otherwise.
    [[nodiscard]] virtual CertObject::Sptr FindBySkid(score::crypto::span<const uint8_t> skid) const = 0;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_I_TRUST_STORE_HANDLER_HPP
