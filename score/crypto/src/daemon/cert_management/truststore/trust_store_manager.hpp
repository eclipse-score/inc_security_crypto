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

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_trust_store_handler.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/trust_store_config.hpp"
#include "score/crypto/src/daemon/cert_management/policy/access_policy_enforcer.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_handler.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
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
    void Load(const std::vector<TrustStoreConfig>& store_configs,
              CertSlotRegistry::Sptr slot_registry,
              CertSlotHandlerFactory slot_handler_factory = {});

    // -----------------------------------------------------------------------
    // Store access
    // -----------------------------------------------------------------------

    [[nodiscard]] ITrustStoreHandler::Sptr GetStore(TrustStoreId id) const;
    [[nodiscard]] TrustStoreId ResolveByName(const std::string& name) const;

    void RegisterAppResource(uint32_t uid, const std::string& app_resource_id, const std::string& store_name);
    [[nodiscard]] score::crypto::Expected<TrustStoreHandle, score::crypto::daemon::common::DaemonErrorCode>
    ResolveAppResource(const std::string& app_resource_id, data_manager::ClientId client_id) const;

    // -----------------------------------------------------------------------
    // Slot membership query
    // -----------------------------------------------------------------------

    /// @brief Return the set of trust store IDs that contain a given cert slot.
    ///
    /// Used by CertManagementService::SaveCertificate to fan out NotifyUpdate().
    [[nodiscard]] std::vector<TrustStoreId> GetMembershipsForSlot(CertSlotHandle slot_handle) const;

    // -----------------------------------------------------------------------
    // Runtime notifications and mutations
    // -----------------------------------------------------------------------

    /// @brief Increment the active-context count for a trust store on behalf of @p client_id.
    ///
    /// Called by ScoreCertVerificationHandler when SetVerificationTrustStore() binds a
    /// store to a verification context. Certs are loaded lazily on first GetAnchors().
    /// Refs are per-client so that releasing one application's contexts does not affect
    /// another application's active references to the same shared trust store.
    void AddRef(TrustStoreHandle handle, data_manager::ClientId client_id);

    /// @brief Decrement the active-context count for @p client_id on @p handle.
    ///
    /// When a client's count for the store reaches zero and no other client holds refs,
    /// the anchor cache is cleared. CertObject strong-refs drop; memory is freed unless
    /// another active trust store shares the same slot's cert via the weak_ptr cache.
    void ReleaseRef(TrustStoreHandle handle, data_manager::ClientId client_id);

    /// @brief Release all refs held by @p client_id across all trust stores.
    ///
    /// Called by CertManagementService::CleanupClient() on client crash or disconnect.
    /// Unconditionally removes all per-client counts for the dead client, then evicts
    /// anchor caches for any trust store that has no remaining active clients.
    void CleanupClient(data_manager::ClientId client_id);

    /// @brief Invalidate one member slot in the given trust store.
    ///
    /// Evicts the slot from the shared cert cache and marks the handler for reload.
    /// Called by CertManagementService::NotifySlotCertChanged() after StoreCertificate.
    /// Unchanged member slots retain their cached strong-refs; only the changed slot
    /// pays a reload cost on the next GetAnchors() call.
    void NotifySlotChanged(TrustStoreId id, CertSlotHandle changed_slot);

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
    ///     returned. Callers should use ImportCrl directly on the slot resource.
    ///
    /// Write access to the trust store must be checked by CertManagementService
    /// before calling this method.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> AddMember(
        TrustStoreId id,
        CertObject::Sptr cert,
        data_manager::ClientId client_id,
        score::crypto::span<const uint8_t> crl_bytes = {},
        score::crypto::FormatType crl_format = score::crypto::FormatType::kDer);

    /// @brief Import a CRL to the exclusive trust store slot identified by @p slot.
    ///
    /// Only operates on kExclusiveMutable members — the trust store owns these.
    /// Shared-static and conditional-external slots are externally managed;
    /// callers use CertManagementService::ImportCrlToSlot directly for those.
    ///
    /// Returns kInvalidResourceId if @p slot is not a member of the trust store.
    /// Returns kUnsupportedOperation if the slot is not kExclusiveMutable.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ImportCrlForMember(TrustStoreId id,
                       CertSlotHandle slot,
                       score::crypto::span<const uint8_t> crl_data,
                       score::crypto::FormatType format);

    /// @brief Remove a certificate from a trust store by fingerprint.
    ///
    /// Persists the change to the trust store descriptor and calls NotifyUpdate().
    /// Write access must be checked before calling.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    RemoveMember(TrustStoreId id, const std::vector<uint8_t>& fingerprint, data_manager::ClientId client_id);

    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    EnableMember(TrustStoreId id, CertSlotHandle slot, data_manager::ClientId client_id);
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    DisableMember(TrustStoreId id, CertSlotHandle slot, data_manager::ClientId client_id);
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    AcknowledgeMemberUpdate(TrustStoreId id, CertSlotHandle slot, data_manager::ClientId client_id);

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
        std::string slot_name;                   ///< Slot name (used by executor to call ResolveCertSlot).
        std::array<uint8_t, 32U> fingerprint{};  ///< SHA-256 fingerprint of the member certificate.
        std::string subject;                     ///< RFC 4514 Subject DN.
        std::string issuer;                      ///< RFC 4514 Issuer DN.
        std::string serial_number;               ///< Uppercase hex serial number.
        TrustStoreMemberKind kind{TrustStoreMemberKind::kSharedStatic};
        bool is_enabled{true};
    };

    /// @brief Load and return a snapshot of all occupied member slots for trust store @p id.
    ///
    /// Certs are loaded via the shared cache where possible; fresh loads are taken for
    /// uncached slots. Non-const because it may populate handler and cert caches.
    [[nodiscard]] std::vector<MemberSnapshot> GetMembersSnapshot(TrustStoreId id);

    // -----------------------------------------------------------------------
    // Configuration access
    // -----------------------------------------------------------------------

    /// @brief Return the TrustStoreConfig for a given store ID.
    [[nodiscard]] const TrustStoreConfig* GetStoreConfig(TrustStoreId id) const;

  private:
    struct MemberState
    {
        bool enabled{true};
        std::optional<std::array<uint8_t, 32U>> accepted_fingerprint;
    };

    /// Result of resolving a TrustStoreMemberConfig to its live slot, handler, and config.
    /// All pointers are non-null. Valid only while m_mutex is held.
    struct ResolvedMember
    {
        CertSlotHandle slot;
        ICertSlotHandler* handler;
        const CertSlotConfig* cfg;
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

    /// Returns the handler for @p slot, creating it via m_slot_handler_factory on first access.
    /// Returns nullptr if the factory is absent, the slot has no config, or factory returns nullptr.
    /// Must be called with m_mutex held.
    ICertSlotHandler* GetOrCreateHandler(CertSlotHandle slot);

    void LoadState(TrustStoreId id);
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> PersistState(TrustStoreId id) const;

    /// Populate handler's anchor cache for one trust store. Called by the AnchorLoader
    /// lambda captured inside each TrustStoreHandler. Acquires m_mutex.
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
    std::unordered_map<uint32_t, ICertSlotHandler::Sptr> m_slot_handlers;
    CertSlotHandlerFactory m_slot_handler_factory;

    static constexpr std::string_view kLogPrefix = "[TRUST_STORE_MANAGER] ";
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_TRUST_STORE_MANAGER_HPP
