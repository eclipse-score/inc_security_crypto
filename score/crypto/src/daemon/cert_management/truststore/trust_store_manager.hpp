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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_TRUST_STORE_MANAGER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_TRUST_STORE_MANAGER_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_trust_store_handler.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/trust_store_config.hpp"
#include "score/crypto/src/daemon/cert_management/policy/access_policy_enforcer.hpp"
#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_handler.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// @brief Manages named trust stores — collections of certificate trust anchors.
///
/// A trust store is a named, many-to-many view over typed certificate slots. A slot may back
/// multiple trust stores simultaneously; a single SaveCertificate to the slot triggers
/// NotifySlotChanged() for every referencing store.
///
/// Startup:
///   Load() populates the store list, slot-membership reverse index, and deployment-backed
///   member state. Cert content is NOT loaded at startup — it is loaded lazily on the first
///   GetAnchors() call to the handler (demand-paged, demand-freed).
///
/// Lazy loading and shared cert cache:
///   m_slot_cert_cache holds a weak_ptr<CertObject> per slot index. A TrustStoreHandler
///   holds strong refs in its internal map for the duration of active use. When the last
///   DataNode for a trust store is released (ReleaseRef drops to zero), the handler's
///   anchor cache is cleared, strong refs drop, and the weak_ptrs expire unless another
///   active store holds the same slot's cert.
///
/// Runtime:
///   AddRef()/ReleaseRef() track active DataNode count per store.
///   NotifySlotChanged(id, slot) invalidates one slot and forces reload on next GetAnchors().
///   AddMember() / RemoveMember() mutate membership and persist to the descriptor.
///
/// Thread safety: internal mutex guards all public methods.
class TrustStoreManager
{
  public:
    using Sptr = std::shared_ptr<TrustStoreManager>;

    TrustStoreManager() = default;
    ~TrustStoreManager() = default;

    TrustStoreManager(const TrustStoreManager&) = delete;
    TrustStoreManager& operator=(const TrustStoreManager&) = delete;
    TrustStoreManager(TrustStoreManager&&) = delete;
    TrustStoreManager& operator=(TrustStoreManager&&) = delete;

    // -----------------------------------------------------------------------
    // Startup loading
    // -----------------------------------------------------------------------

    /// @brief Populate the trust store list from configuration.
    ///
    /// Called once at daemon startup, after CertSlotRegistry is populated.
    /// For each TrustStoreConfig:
    ///   - Resolves typed members (slot_name → CertSlotHandle via registry)
    ///   - Populates m_slot_memberships reverse index and m_member_states from descriptor
    ///   - Does NOT load cert content — certs are loaded lazily on first GetAnchors()
    ///
    /// @param store_configs  Trust store configurations; the vector index becomes the TrustStoreId.
    /// @param slot_registry  Registry used to resolve member slot names to CertSlotHandle.
    /// @param slot_manager   Provides per-slot handlers; if null, no slot I/O is possible.
    void Load(const std::vector<TrustStoreConfig>& store_configs,
              CertSlotRegistry::Sptr slot_registry,
              CertSlotManager::Sptr slot_manager = {});

    // -----------------------------------------------------------------------
    // Store access
    // -----------------------------------------------------------------------

    /// @brief Return the shared handler of a trust store.
    /// @param handle Trust store handle.
    /// @return The handler, or nullptr if @p handle is invalid or out of range.
    [[nodiscard]] ITrustStoreHandler::Sptr GetStore(TrustStoreHandle handle) const;

    /// @brief Look up a trust store by its configured name.
    /// @param name Configured trust store name.
    /// @return The store handle, or an invalid handle if no store has that name.
    [[nodiscard]] TrustStoreHandle ResolveByName(const std::string& name) const;

    /// @brief Map an application-visible resource ID to a named trust store for one uid.
    /// @param uid             User ID the mapping applies to.
    /// @param app_resource_id Application-scoped resource identifier.
    /// @param store_name      Configured name of the trust store it resolves to.
    void RegisterAppResource(uint32_t uid, const std::string& app_resource_id, const std::string& store_name);

    /// @brief Resolve an application resource ID to a trust store for the uid of @p client_id.
    /// @param app_resource_id Application-scoped resource identifier.
    /// @param client_id       Calling client; its uid selects the mapping.
    /// @return The store handle, or kInvalidResourceId if the uid, ID or store name is unknown.
    [[nodiscard]] score::crypto::Expected<TrustStoreHandle, score::crypto::daemon::common::DaemonErrorCode>
    ResolveAppResource(const std::string& app_resource_id, data_manager::ClientId client_id) const;

    // -----------------------------------------------------------------------
    // Slot membership query
    // -----------------------------------------------------------------------

    /// @brief Return the set of trust store IDs that contain a given cert slot.
    ///
    /// Used by CertManagementService::SaveCertificate to fan out NotifyUpdate().
    ///
    /// @param slot_handle Certificate slot to look up.
    /// @return Handles of all stores referencing the slot; empty if none.
    [[nodiscard]] std::vector<TrustStoreHandle> GetMembershipsForSlot(CertSlotHandle slot_handle) const;

    // -----------------------------------------------------------------------
    // Runtime notifications and mutations
    // -----------------------------------------------------------------------

    /// @brief Increment the active-context count for a trust store on behalf of @p client_id.
    ///
    /// Called by ScoreCertVerificationHandler when SetVerificationTrustStore() binds a
    /// store to a verification context. Certs are loaded lazily on first GetAnchors().
    /// Refs are per-client so that releasing one application's contexts does not affect
    /// another application's active references to the same shared trust store.
    ///
    /// @param handle    Trust store being bound.
    /// @param client_id Client owning the verification context.
    void AddRef(TrustStoreHandle handle, data_manager::ClientId client_id);

    /// @brief Decrement the active-context count for @p client_id on @p handle.
    ///
    /// When a client's count for the store reaches zero and no other client holds refs,
    /// the anchor cache is cleared. CertObject strong-refs drop; memory is freed unless
    /// another active trust store shares the same slot's cert via the weak_ptr cache.
    ///
    /// @param handle    Trust store being released.
    /// @param client_id Client that owned the verification context.
    void ReleaseRef(TrustStoreHandle handle, data_manager::ClientId client_id);

    /// @brief Release all refs held by @p client_id across all trust stores.
    ///
    /// Called by CertManagementService::CleanupClient() on client crash or disconnect.
    /// Unconditionally removes all per-client counts for the dead client, then evicts
    /// anchor caches for any trust store that has no remaining active clients.
    ///
    /// @param client_id Client that crashed or disconnected.
    void CleanupClient(data_manager::ClientId client_id);

    /// @brief Invalidate one member slot in the given trust store.
    ///
    /// Evicts the slot from the shared cert cache and marks the handler for reload.
    /// Called by CertManagementService::NotifySlotCertChanged() after StoreCertificate.
    /// Unchanged member slots retain their cached strong-refs; only the changed slot
    /// pays a reload cost on the next GetAnchors() call.
    ///
    /// A kConditionalExternal member is additionally disabled (and the state persisted)
    /// until acknowledged via AcknowledgeMemberUpdate().
    ///
    /// @param handle       Trust store that references the slot.
    /// @param changed_slot Slot whose certificate changed.
    void NotifySlotChanged(TrustStoreHandle handle, CertSlotHandle changed_slot);

    /// @brief Add a certificate to a trust store's runtime anchor set.
    ///
    /// Performs a fingerprint dedup across ALL member types before searching for
    /// an empty exclusive slot — if the cert is already a member (shared-static,
    /// conditional-external, or exclusive), returns success without consuming a
    /// new slot.
    ///
    /// When @p crl_bytes is non-empty the CRL is written to the exclusive slot
    /// atomically with the cert (new add) or as an upsert (cert already present).
    ///
    /// Upsert semantics for existing members:
    ///   - kExclusiveMutable match: CRL is stored/updated; cert is re-enabled.
    ///   - kSharedStatic / kConditionalExternal match: trust store does not own
    ///     these slots; if crl_bytes is non-empty, kUnsupportedOperation is
    ///     returned. Callers should use ImportCrlToSlot on the slot resource.
    ///
    /// Write access to the trust store must be checked by CertManagementService
    /// before calling this method.
    ///
    /// @param handle       Target trust store.
    /// @param cert         Certificate to add; must not be null.
    /// @param client_id    Calling client, used for the write-permission check.
    /// @param crl_bytes    Optional validated CRL to store with the certificate.
    /// @param crl_format   Encoding of @p crl_bytes.
    /// @param crl_metadata Optional CRL metadata persisted with the CRL.
    /// @return success, or kInvalidArgument (bad handle or null cert), kAccessDenied,
    ///         kUnsupportedOperation (CRL given for a non-exclusive member), a slot I/O error,
    ///         or kTrustStoreCapacityExceeded (no empty exclusive slot).
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> AddMember(
        TrustStoreHandle handle,
        CertObject::Sptr cert,
        data_manager::ClientId client_id,
        score::crypto::span<const uint8_t> crl_bytes = {},
        score::crypto::FormatType crl_format = score::crypto::FormatType::kDer,
        std::optional<score::crypto::CrlMetadata> crl_metadata = std::nullopt);

    /// @brief Import a CRL to the exclusive trust store slot identified by @p slot.
    ///
    /// Only operates on kExclusiveMutable members — the trust store owns these.
    /// Shared-static and conditional-external slots are externally managed;
    /// callers use CertManagementService::ImportCrlToSlot directly for those.
    ///
    /// Returns kInvalidResourceId if @p slot is not a member of the trust store.
    /// Returns kUnsupportedOperation if the slot is not kExclusiveMutable.
    ///
    /// @param handle    Target trust store.
    /// @param slot      Member slot receiving the CRL.
    /// @param crl_data  Validated CRL bytes; must not be empty.
    /// @param format    Encoding of @p crl_data.
    /// @param client_id Calling client, used for the write-permission check.
    /// @param metadata  Optional CRL metadata persisted with the CRL.
    /// @return success, or kInvalidResourceId, kInvalidArgument (empty CRL), kAccessDenied,
    ///         kUnsupportedOperation, or a slot I/O error.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ImportCrlForMember(TrustStoreHandle handle,
                       CertSlotHandle slot,
                       score::crypto::span<const uint8_t> crl_data,
                       score::crypto::FormatType format,
                       data_manager::ClientId client_id,
                       std::optional<score::crypto::CrlMetadata> metadata = std::nullopt);

    /// @brief Delete the persistent CRL of an exclusive trust store member slot.
    ///
    /// @param handle    Target trust store.
    /// @param slot      Member slot whose CRL is cleared.
    /// @param client_id Calling client, used for the write-permission check.
    /// @return success, or kInvalidResourceId (slot not a member), kAccessDenied,
    ///         kUnsupportedOperation (slot not kExclusiveMutable), or a slot I/O error.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    DeleteCrlForMember(TrustStoreHandle handle, CertSlotHandle slot, data_manager::ClientId client_id);

    /// @brief Remove a certificate from a trust store by fingerprint.
    ///
    /// Persists the change to the trust store descriptor and calls NotifyUpdate().
    /// Write access must be checked before calling.
    ///
    /// @param handle      Target trust store.
    /// @param fingerprint SHA-256 fingerprint of the certificate to remove.
    /// @param client_id   Calling client, used for the write-permission check.
    /// @return success, or kInvalidResourceId, kAccessDenied, kInvalidArgument (no exclusive
    ///         member holds that fingerprint), or a slot I/O error.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    RemoveMember(TrustStoreHandle handle, const std::vector<uint8_t>& fingerprint, data_manager::ClientId client_id);

    /// @brief Enable a member so its certificate becomes an active anchor.
    ///
    /// For kConditionalExternal members the slot is freshly loaded and must match the
    /// accepted fingerprint; enabling never advances the accepted fingerprint.
    ///
    /// @param handle    Target trust store.
    /// @param slot      Member slot to enable.
    /// @param client_id Calling client, used for the write-permission check.
    /// @return success, or kInvalidResourceId, kAccessDenied, kInvalidArgument (slot is not a
    ///         member), or kInvalidOperation (conditional member with an empty slot, no accepted
    ///         fingerprint, or content that differs from it).
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    EnableMember(TrustStoreHandle handle, CertSlotHandle slot, data_manager::ClientId client_id);

    /// @brief Disable a member; it stays in the store and can be re-enabled.
    ///
    /// @param handle    Target trust store.
    /// @param slot      Member slot to disable.
    /// @param client_id Calling client, used for the write-permission check.
    /// @return success, or kInvalidResourceId, kAccessDenied, or kInvalidArgument (slot is not a
    ///         member).
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    DisableMember(TrustStoreHandle handle, CertSlotHandle slot, data_manager::ClientId client_id);

    /// @brief Accept the current content of a kConditionalExternal member and re-enable it.
    ///
    /// Compare-and-acknowledge: the slot is freshly loaded and its SHA-256 fingerprint must
    /// equal @p expected_sha256_fingerprint. On mismatch no state changes.
    ///
    /// @param handle                      Target trust store.
    /// @param slot                        Conditional member slot to acknowledge.
    /// @param expected_sha256_fingerprint 32-byte fingerprint of the content the caller inspected.
    /// @param client_id                   Calling client, used for the write-permission check.
    /// @return success, or kInvalidResourceId, kAccessDenied, kInvalidArgument (fingerprint not
    ///         32 bytes), kUnsupportedOperation (member is not conditional-external), or
    ///         kInvalidOperation (empty slot or content differs from the expected fingerprint).
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    AcknowledgeMemberUpdate(TrustStoreHandle handle,
                            CertSlotHandle slot,
                            score::crypto::span<const uint8_t> expected_sha256_fingerprint,
                            data_manager::ClientId client_id);

    // -----------------------------------------------------------------------
    // Snapshot for read-only typed object access (ITrustStoreObject)
    // -----------------------------------------------------------------------

    /// @brief Point-in-time snapshot of a trust store's member list.
    ///
    /// Used by the cert management executor to populate the TRUST_STORE_GET_INFO response
    /// consumed by ITrustStoreObject on the lib side. Slots with no cert present are omitted.
    struct MemberSnapshot
    {
        CertSlotHandle slot_handle{0U};          ///< Daemon-internal slot index (for enable/disable routing).
        std::string slot_name;                   ///< Stable diagnostic/configuration name.
        std::array<uint8_t, 32U> fingerprint{};  ///< SHA-256 fingerprint of the member certificate.
        std::string subject;                     ///< RFC 4514 Subject DN.
        std::string issuer;                      ///< RFC 4514 Issuer DN.
        std::string serial_number;               ///< Uppercase hex serial number.
        TrustStoreMemberKind kind{TrustStoreMemberKind::kSharedStatic};
        score::crypto::MemberStatus status{score::crypto::MemberStatus::kEnabled};  ///< Effective member status.
    };

    /// @brief Load and return a snapshot of all occupied member slots for trust store @p id.
    ///
    /// Certs are loaded via the shared cache where possible; fresh loads are taken for
    /// uncached slots. Non-const because it may populate handler and cert caches.
    ///
    /// kConditionalExternal members are always loaded fresh so that `status` reflects current
    /// slot content: kFingerprintMismatch when it differs from the accepted fingerprint,
    /// kAwaitingAcknowledgement when none was accepted and the store requires acceptance.
    ///
    /// @param handle Trust store to snapshot.
    /// @return One entry per occupied, resolvable member; empty if @p handle is invalid.
    [[nodiscard]] std::vector<MemberSnapshot> GetMembersSnapshot(TrustStoreHandle handle);

    // -----------------------------------------------------------------------
    // Configuration access
    // -----------------------------------------------------------------------

    /// @brief Return the TrustStoreConfig for a given store handle.
    /// @param handle Trust store handle.
    /// @return Pointer to the config, or nullptr if @p handle is out of range.
    [[nodiscard]] const TrustStoreConfig* GetStoreConfig(TrustStoreHandle handle) const;

  private:
    /// Runtime state of one member slot within one trust store.
    struct MemberState
    {
        bool enabled{true};  ///< Whether the member contributes anchors.
        /// Conditional-external baseline; unset until accepted.
        std::optional<std::array<uint8_t, 32U>> accepted_fingerprint;
    };

    /// Result of resolving a TrustStoreMemberConfig to its live slot, handler, and config.
    /// All pointers are non-null. Valid only while m_mutex is held.
    struct ResolvedMember
    {
        CertSlotHandle slot{};
        ICertSlotHandler* handler{nullptr};
        const CertSlotConfig* cfg{nullptr};
    };
    /// Returns nullopt if the member's slot name cannot be resolved or has no registered handler.
    [[nodiscard]] std::optional<ResolvedMember> ResolveMember(const TrustStoreMemberConfig& member);

    /// Result of looking up a CertSlotHandle's config and handler.
    /// All pointers are non-null. Valid only while m_mutex is held.
    struct ResolvedBackend
    {
        const CertSlotConfig* cfg;
        ICertSlotHandler* handler;
    };
    /// Returns kInvalidResourceId if the slot is not registered or has no handler.
    [[nodiscard]] score::crypto::Expected<ResolvedBackend, common::DaemonErrorCode> ResolveSlotBackend(
        CertSlotHandle slot);

    /// Returns the handler for @p slot from CertSlotManager (friend-gated, no auth check).
    /// Returns nullptr if CertSlotManager is absent or has no config for the slot.
    /// Must be called with m_mutex held.
    ICertSlotHandler* GetHandler(CertSlotHandle slot);

    /// Read member states for store @p id from its deployment descriptor. No cert I/O.
    void LoadState(TrustStoreId id);

    /// Write member states for store @p id to its deployment descriptor, keeping other sections.
    /// Must be called with m_mutex held.
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> PersistState(TrustStoreId id) const;

    /// Populate handler's anchor cache for one trust store. Called by the AnchorLoader
    /// lambda captured inside each TrustStoreHandler. Acquires m_mutex.
    /// Disables conditional members whose content no longer matches the accepted fingerprint.
    void LoadAnchorsIntoHandler(TrustStoreId id, TrustStoreHandler& handler);

    /// Evict the anchor cache for @p handle if no client currently holds a ref to it.
    /// Must be called with m_mutex held.
    void MaybeEvictAnchorCache(TrustStoreHandle handle);

    /// Promote the weak_ptr for slot from m_slot_cert_cache, or load fresh and cache it.
    /// Returns nullptr if the slot is empty or the backend returns an error.
    /// Must be called with m_mutex held.
    CertObject::Sptr LoadOrGetCached(CertSlotHandle slot);

    struct TrustStoreEntry
    {
        TrustStoreConfig config;
        ITrustStoreHandler::Sptr handler;
        TrustStoreId id{0U};
    };

    mutable std::mutex m_mutex;

    std::vector<TrustStoreEntry> m_stores;
    std::unordered_map<std::string, TrustStoreId> m_name_index;
    std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>> m_app_resource_map;

    /// Reverse index: slot handle index → list of trust store IDs that reference it.
    std::unordered_map<uint32_t, std::vector<TrustStoreId>> m_slot_memberships;
    /// Runtime state loaded from/persisted to each trust-store deployment descriptor.
    std::unordered_map<TrustStoreId, std::unordered_map<uint32_t, MemberState>> m_member_states;

    /// Cross-trust-store cert cache. Holds a weak_ptr so the cert is freed automatically
    /// when no TrustStoreHandler (or other holder) keeps a strong ref alive.
    std::unordered_map<uint32_t, std::weak_ptr<CertObject>> m_slot_cert_cache;

    /// Per-client, per-store active context reference counts.
    /// Outer key: ClientId (one entry per connected application).
    /// Inner key: TrustStoreId index. Value: count of verification contexts currently
    /// bound to that store for that client.
    /// An entry is removed when the count drops to zero.
    /// The anchor cache for a store is evicted only when ALL clients' counts drop to zero.
    std::unordered_map<data_manager::ClientId, std::unordered_map<TrustStoreId, uint32_t>> m_client_ref_counts;

    CertSlotRegistry::Sptr m_slot_registry;
    CertSlotManager::Sptr m_slot_manager;

    static constexpr std::string_view kLogPrefix = "[TRUST_STORE_MANAGER] ";
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_TRUST_STORE_MANAGER_HPP
