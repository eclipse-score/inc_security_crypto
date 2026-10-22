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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_TRUST_STORE_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_TRUST_STORE_HANDLER_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_trust_store_handler.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/trust_store_config.hpp"
#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// @brief Resolved, point-in-time detail of one trust store member.
struct TrustStoreMemberSnapshot
{
    CertSlotHandle slot_handle{0U};  ///< Daemon-internal slot index (for enable/disable routing).
    std::string slot_name;           ///< Stable diagnostic/configuration name.
    std::array<uint8_t, score::crypto::kSha256FingerprintSize> fingerprint{};  ///< SHA-256 fingerprint.
    std::string subject;                                                       ///< RFC 4514 Subject DN.
    std::string issuer;                                                        ///< RFC 4514 Issuer DN.
    std::string serial_number;                                                 ///< Uppercase hex serial number.
    TrustStoreMemberKind kind{TrustStoreMemberKind::kSharedStatic};  ///< Membership kind from the configuration.
    score::crypto::MemberStatus status{score::crypto::MemberStatus::kEnabled};  ///< Effective member status.
};

/// @brief One trust store: its member state, anchor and CRL cache, and member mutations.
///
/// The handler owns everything specific to a single store. It holds the configuration, the
/// runtime state of each member (enabled flag, accepted fingerprint), the cached anchors and
/// CRLs, and the persisted member state in the store's deployment descriptor. Member
/// certificates and CRLs are read and written through the slot backends, using the same
/// friend-gated access as TrustStoreManager previously held. Cached slot state is evicted in
/// CertSlotManager after every backend write made here.
///
/// TrustStoreManager is the registry in front of the handlers. It owns the name index, the
/// slot-to-store reverse index, and the per-client reference counts, and it enforces the
/// trust-store write policy before it calls a mutating method. Mutating methods here assume
/// that check has been made.
///
/// Callers of ITrustStoreHandler see only the read side: anchors, CRLs, and chain-building
/// lookups.
///
/// Cache lifecycle: the anchor and CRL cache is warm only while a client holds the store.
/// TrustStoreManager loads it when the first client binds the store (LoadCache()) and clears it when
/// the last client releases it (ClearCache()). Mutations and slot notifications update the
/// cache only while it is warm; while it is cold they change persisted member state only. A read
/// on a cold store resolves the members from the slot manager and returns the result without
/// caching it. A failure to read an existing certificate or CRL is returned, never skipped.
///
/// Thread safety: one mutex guards the state and caches of this store. Slot backend and
/// persistence calls are made with it held. The handler never calls back into
/// TrustStoreManager, so the lock order is manager mutex, then handler mutex. A reader sees a
/// complete anchor set; it may observe a member's new certificate together with its previous
/// CRL while the member is being refreshed, never a partially rebuilt anchor set.
class TrustStoreHandler final : public ITrustStoreHandler
{
  public:
    /// Alias for the member detail type returned by GetMemberSnapshot().
    using MemberSnapshot = TrustStoreMemberSnapshot;

    /// @param handle       Runtime handle of this store (its index in TrustStoreManager).
    /// @param config       Store configuration; members are resolved through @p registry.
    /// @param registry     Resolves member slot names to slot handles and configurations. May be null,
    ///                     in which case the store has no resolvable members.
    /// @param slot_manager Provides slot backends and the shared CertObject cache. May be null.
    ///
    /// Reads the persisted member state from the store's deployment descriptor. No certificate
    /// content is loaded; the cache is built by LoadCache() when a client binds the store.
    TrustStoreHandler(TrustStoreHandle handle,
                      TrustStoreConfig config,
                      CertSlotRegistry::Sptr registry,
                      CertSlotManager::Sptr slot_manager);

    // -----------------------------------------------------------------------
    // ITrustStoreHandler
    // -----------------------------------------------------------------------

    /// @copydoc ITrustStoreHandler::GetHandle
    TrustStoreHandle GetHandle() const noexcept override;

    /// @copydoc ITrustStoreHandler::GetAnchors
    score::crypto::Expected<std::vector<CertObject::Sptr>, common::DaemonErrorCode> GetAnchors() override;
    /// @copydoc ITrustStoreHandler::GetCrls
    score::crypto::Expected<std::vector<CrlData::Sptrc>, common::DaemonErrorCode> GetCrls() override;

    /// @copydoc ITrustStoreHandler::FindBySubject
    CertObject::Sptr FindBySubject(const std::string& subject) override;
    /// @copydoc ITrustStoreHandler::FindBySkid
    CertObject::Sptr FindBySkid(score::crypto::span<const uint8_t> skid) override;

    // -----------------------------------------------------------------------
    // Configuration and cache lifecycle
    // -----------------------------------------------------------------------

    /// @brief The configuration this store was created from. Fixed at construction.
    [[nodiscard]] const TrustStoreConfig& GetConfig() const noexcept;

    /// Whether the store can be used. A store is not valid when a member does not name a
    /// configured slot, a slot is listed twice, or its persisted state is unreadable or malformed.
    /// An invalid store returns kTrustStoreInvalid from every read and mutation instead of running
    /// with a subset of its members or with default state. The cause is logged once at startup.
    [[nodiscard]] bool IsValid() const noexcept
    {
        return m_valid;
    }

    /// Build the anchor and CRL cache from the enabled members, so that reads are served from it.
    /// Does nothing when the cache is already warm.
    ///
    /// An empty member slot and a missing CRL are not failures. The first failure to read an
    /// existing certificate or CRL is returned, and the cache stays cold with no partial content.
    /// A conditional member whose content no longer matches its accepted fingerprint is disabled
    /// and the state persisted, as on any other resolution.
    ///
    /// @return success, or the first failure to read a member.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> LoadCache();

    /// Drop the cached anchors and CRLs. Reads then resolve the members without caching until
    /// the next LoadCache().
    void ClearCache();

    // -----------------------------------------------------------------------
    // Slot change notification
    // -----------------------------------------------------------------------

    /// Evict the slot's cached state and refresh only that member's anchor and CRL entry.
    /// Other members are not re-read. A kConditionalExternal member is instead disabled and
    /// the state persisted, until AcknowledgeMemberUpdate() records the replacement.
    /// While the cache is cold, only the eviction and the conditional
    /// disable take place.
    /// @param slot Slot whose content changed.
    void OnSlotChanged(CertSlotHandle slot);

    /// Refresh the member's cached CRL from the slot's current CRL snapshot. Does not reload the
    /// certificate and does not change member enablement; a member that is not enabled keeps no
    /// CRL. When the cache has not been loaded yet there is nothing to refresh.
    /// @param slot Slot whose CRL changed.
    void OnSlotCrlChanged(CertSlotHandle slot);

    // -----------------------------------------------------------------------
    // Member mutations (trust-store write access is checked by the caller)
    // -----------------------------------------------------------------------

    /// @brief Add a certificate to the anchor set.
    ///
    /// A fingerprint dedup runs across all member kinds before an empty exclusive slot is
    /// consumed; a certificate that is already a member returns success. When @p crl is non-null
    /// and holds bytes, the CRL is stored with the certificate in the exclusive slot, or upserted
    /// when the certificate is already held there. Shared-static and conditional-external
    /// members are not owned by the store, so a CRL for one of them yields
    /// kUnsupportedOperation.
    ///
    /// @param cert Certificate to add. Must not be null.
    /// @param crl  CRL to store with the certificate, or null for none.
    /// @return success, kUnsupportedOperation, kTrustStoreCapacityExceeded (no empty exclusive
    ///         slot), or a slot I/O error.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> AddMember(
        const CertObject::Sptr& cert,
        CrlData::Sptrc crl);

    /// @brief Store a CRL in the exclusive member slot @p slot.
    /// @param slot Exclusive member slot to write.
    /// @param crl  CRL to store.
    /// @return success, kInvalidResourceId (not a member), kUnsupportedOperation (member is not
    ///         kExclusiveMutable), or a slot I/O error.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> StoreCrlForMember(
        CertSlotHandle slot,
        const CrlData& crl);

    /// @brief Delete the CRL of the exclusive member slot @p slot.
    /// @param slot Exclusive member slot whose CRL is removed.
    /// @return success, kInvalidResourceId, kUnsupportedOperation, or a slot I/O error.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearCrlForMember(
        CertSlotHandle slot);

    /// @brief Clear the exclusive member slot that holds the certificate with @p fingerprint.
    /// @param fingerprint SHA-256 fingerprint of the certificate to remove.
    /// @return success, kInvalidArgument (no exclusive member holds it), or a slot I/O error.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> RemoveMember(
        const std::vector<uint8_t>& fingerprint);

    /// @brief Enable a member. A conditional member is loaded fresh and must match its
    /// accepted fingerprint; enabling never advances that fingerprint.
    /// @param slot Member slot to enable.
    /// @return success, kInvalidArgument (not a member), or kInvalidOperation.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> EnableMember(CertSlotHandle slot);

    /// @brief Disable a member; it stays in the store.
    /// @param slot Member slot to disable.
    /// @return success, or kInvalidArgument (not a member).
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> DisableMember(CertSlotHandle slot);

    /// @brief Accept the current content of a conditional member and enable it, when its
    /// fingerprint equals @p expected_sha256_fingerprint.
    /// @param slot                        Conditional-external member to acknowledge.
    /// @param expected_sha256_fingerprint Fingerprint the current content must match; 32 bytes.
    /// @return success, kInvalidArgument (fingerprint not 32 bytes), kUnsupportedOperation
    ///         (member is not conditional-external), or kInvalidOperation.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> AcknowledgeMemberUpdate(
        CertSlotHandle slot,
        score::crypto::span<const uint8_t> expected_sha256_fingerprint);

    // -----------------------------------------------------------------------
    // Member inspection
    // -----------------------------------------------------------------------

    /// @brief Slot handles of the occupied members. Only checks occupancy; no parsing.
    [[nodiscard]] score::crypto::Expected<std::vector<CertSlotHandle>, common::DaemonErrorCode> GetMemberSlotHandles();

    /// @brief Detail of one member. A conditional member is loaded fresh so that its status
    /// reflects current slot content.
    /// @param slot Member slot to describe.
    /// @return the snapshot, kInvalidResourceId (not a member), or kResourceNotFound (empty slot).
    [[nodiscard]] score::crypto::Expected<MemberSnapshot, common::DaemonErrorCode> GetMemberSnapshot(
        CertSlotHandle slot);

  private:
    /// Runtime state of one member slot.
    struct MemberState
    {
        bool enabled{true};  ///< Whether the member contributes anchors.
        /// Conditional-external baseline; unset until accepted.
        std::optional<std::array<uint8_t, score::crypto::kSha256FingerprintSize>> accepted_fingerprint;
    };

    /// A member's live slot, backend handler, and configuration. Valid for the duration of
    /// the call that resolved it.
    struct ResolvedMember
    {
        CertSlotHandle slot{};               ///< Slot the member occupies.
        ICertSlotHandler* handler{nullptr};  ///< Backend handler of the slot. Owned by CertSlotManager.
        const CertSlotConfig* cfg{nullptr};  ///< Slot configuration. Owned by the slot registry.
    };

    /// The anchor and CRL a member contributes to the store. Both are empty for a member that is
    /// disabled, whose slot is empty, or whose conditional gate rejects it.
    struct MemberContent
    {
        CertObject::Sptr anchor;  ///< Certificate the member contributes, or null.
        CrlData::Sptrc crl;       ///< CRL the member contributes, or null.
    };

    // The helpers below must be called with m_mutex held.
    /// Resolve a configured member to its slot, backend handler, and configuration. Returns nullopt when
    /// the store has no registry or the member names no configured slot.
    /// @param member Configured member to resolve.
    [[nodiscard]] std::optional<ResolvedMember> ResolveMember(const TrustStoreMemberConfig& member) const;
    /// Resolve a slot to its backend handler and configuration. Returns nullopt when the store has no
    /// registry or slot manager, the slot has no configuration, or no backend handler is available.
    /// @param slot Slot to resolve.
    [[nodiscard]] std::optional<ResolvedMember> ResolveSlot(CertSlotHandle slot) const;
    /// Return the configured member that occupies @p slot, or nullptr when the slot is not a member.
    /// @param slot Slot to look up.
    [[nodiscard]] const TrustStoreMemberConfig* FindMember(CertSlotHandle slot) const;
    /// Load the slot's certificate through the slot manager's cache. Returns nullptr when the slot cannot be
    /// loaded; the failure is logged.
    /// @param slot Slot whose certificate is loaded.
    [[nodiscard]] CertObject::Sptr LoadCertificateCached(CertSlotHandle slot);
    /// Evict the slot's certificate and CRL state from the slot manager's caches. Does nothing when the
    /// store has no slot manager.
    /// @param slot Slot whose cached state is evicted.
    void InvalidateSlotCaches(CertSlotHandle slot);
    /// Drop only the slot's cached CRL state, for writes that leave the certificate unchanged.
    /// @param slot Slot whose cached CRL state is evicted.
    void InvalidateCrl(CertSlotHandle slot);

    /// Resolve one member's anchor and CRL from the slot manager and apply the enablement and
    /// conditional-member gate. An empty slot or a missing CRL is not an error; a failure to read
    /// an existing certificate or CRL is returned. Sets @p state_changed when the gate changed
    /// the member state.
    /// @param member        Configured member to resolve.
    /// @param slot          Slot the member occupies.
    /// @param state_changed Set to true when the gate changed the member state.
    /// @return The member's anchor and CRL, or the first failure to read them.
    [[nodiscard]] score::crypto::Expected<MemberContent, common::DaemonErrorCode>
    ResolveMemberContentLocked(const TrustStoreMemberConfig& member, CertSlotHandle slot, bool& state_changed);

    /// Resolve every member and persist any member-state change. Returns the first failure.
    /// @return The anchor and CRL of each resolved member, or the first failure.
    [[nodiscard]] score::crypto::Expected<std::vector<std::pair<CertSlotHandle, MemberContent>>,
                                          common::DaemonErrorCode>
    ResolveAllLocked();

    /// ResolveAllLocked() for a read on a store that is not warm; logs once per store that the result is not cached.
    [[nodiscard]] score::crypto::Expected<std::vector<std::pair<CertSlotHandle, MemberContent>>,
                                          common::DaemonErrorCode>
    ResolveUnboundLocked();

    /// Re-resolve one member into the cache. On failure the store is left cold.
    /// @param member        Configured member to re-resolve.
    /// @param slot          Slot the member occupies.
    /// @param state_changed Set to true when the gate changed the member state.
    void RefreshMemberLocked(const TrustStoreMemberConfig& member, CertSlotHandle slot, bool& state_changed);

    /// True when the slot loads and its fingerprint equals the accepted one; false when none is accepted.
    /// @param slot Conditional-external member to check.
    [[nodiscard]] bool AcceptedFingerprintMatchesLocked(CertSlotHandle slot);

    /// Re-read one member's CRL into the cache; no-op while the store is not warm. On failure the
    /// store is left cold.
    /// @param slot   Slot whose CRL is re-read.
    /// @param usable True to load the CRL from the slot; false to remove the cached CRL, for a member that
    ///               is not enabled or whose anchor is not cached.
    void RefreshMemberCrlLocked(CertSlotHandle slot, bool usable);

    /// Refresh the CRL of a member whose anchor is cached; no-op while the store is not warm.
    /// @param slot Slot whose CRL is refreshed.
    void RefreshActiveMemberCrlLocked(CertSlotHandle slot);

    /// Cache writer for the slot's anchor. A null @p cert removes the entry. No-op while the store is not warm.
    /// @param slot Slot whose anchor is set.
    /// @param cert Anchor to cache, or null to remove the entry.
    void SetAnchorLocked(CertSlotHandle slot, CertObject::Sptr cert);
    /// Cache writer for the slot's CRL. A null @p data removes the entry. No-op while the store is not warm.
    /// @param slot Slot whose CRL is set.
    /// @param data CRL to cache, or null to remove the entry.
    void SetCrlLocked(CertSlotHandle slot, CrlData::Sptrc data);

    /// Drop the cache and mark the store not warm.
    void ClearCacheLocked();

    /// The cached anchors, in no particular order. Empty while the store is not warm.
    [[nodiscard]] std::vector<CertObject::Sptr> AnchorsLocked() const;
    /// Check that every member names a configured slot, once. Returns false and logs otherwise,
    /// so a store with an unknown or repeated member is refused rather than partly loaded.
    [[nodiscard]] bool ValidateMembers() const;

    /// Read the persisted member state. An absent state file is the first run and is not an
    /// error; an unreadable or malformed one returns false and logs. Such a file is never treated
    /// as empty, because that would reset disabled members to enabled.
    [[nodiscard]] bool LoadState();

    /// Persist @p next as the state of @p slot and, only if that succeeds, make it the in-memory
    /// state. On failure the previous state is restored. Used for changes that increase trust.
    /// @param slot Member slot whose state changes.
    /// @param next Proposed state of the slot.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> CommitStateLocked(
        CertSlotHandle slot,
        const MemberState& next);
    /// Write the state of every member to the store's descriptor. Succeeds without writing when the store
    /// has no registry or no deployment path.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> PersistStateLocked() const;

    /// Handle that identifies this store in TrustStoreManager.
    TrustStoreHandle m_handle{};
    /// Configuration this store was created from. Fixed at construction.
    const TrustStoreConfig m_config;
    /// Resolves member slot names to slot handles and configurations. May be null.
    CertSlotRegistry::Sptr m_registry;
    /// Provides backend handlers and the shared certificate cache. May be null.
    CertSlotManager::Sptr m_slot_manager;

    /// Guards every member below and all calls into the slot backends made by this store.
    mutable std::mutex m_mutex;
    /// Runtime state of each member, keyed by slot index. Present once the state has been read or changed.
    std::unordered_map<uint32_t, MemberState> m_states;
    /// Cached anchors, keyed by slot index. Populated only while the store is warm.
    std::unordered_map<uint32_t, CertObject::Sptr> m_slots;
    /// Cached CRL snapshots, keyed by slot index. Populated only while the store is warm.
    std::unordered_map<uint32_t, CrlData::Sptrc> m_crls;
    /// True while the anchor and CRL cache is warm, that is, while a client holds the store.
    bool m_loaded{false};
    /// Set once the unbound-read warning has been logged for this store.
    bool m_unbound_read_logged{false};
    /// False when the configuration or the persisted state could not be used. Fixed at construction;
    /// an invalid store refuses to bind, resolve, and mutate.
    bool m_valid{true};

    /// Prefix for log messages from this store.
    static constexpr std::string_view kLogPrefix = "[TRUST_STORE] ";
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_TRUST_STORE_HANDLER_HPP
