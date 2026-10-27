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

/// @brief Registry of named trust stores.
///
/// A trust store is a named, many-to-many view over typed certificate slots. A slot may back
/// multiple trust stores simultaneously; NotifySlotChanged() updates every store that references
/// the slot.
///
/// Each store is a TrustStoreHandler, which owns the store's member state, anchor and CRL
/// cache, member mutations, and persisted state. This class owns what spans stores: the name
/// index, the application-resource mapping, the slot-to-store reverse index, and the
/// per-client reference counts that decide when a store's cache is evicted. It enforces the
/// trust-store write policy and then forwards each operation to the store's handler.
///
/// Startup:
///   Load() creates one handler per configured store and builds the reverse index. Cert
///   content is NOT loaded at startup.
///
/// Cache lifecycle:
///   A handler's anchor and CRL cache is warm only while a client holds the store. AddRef()
///   warms it when a client binds the store, and ReleaseRef() clears it when the last client
///   releases (or CleanupClient() removes the last one). Parsed certificates are shared with
///   CertSlotManager, which holds them weakly, so clearing the handler's cache lets them be
///   freed unless another holder keeps the same slot's cert. A read on a store nobody holds
///   resolves the members without caching.
///
/// Runtime:
///   AddRef()/ReleaseRef() track active context count per client and store.
///   NotifySlotChanged(slot) refreshes the changed member in every warm store that references it.
///   AddMember() / RemoveMember() mutate membership and persist to the descriptor.
///
/// Thread safety: the stores, the name and application-resource indices, and the slot membership
/// index are built by Load() and RegisterAppResource() before concurrent use begins, and are read
/// without locking afterwards. Only the per-client reference counts change at runtime, and one mutex
/// guards them. Cache eviction takes the handler's own mutex while that mutex is held. Handlers never
/// call back into this class, so the lock order is registry mutex, then handler mutex.
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
    /// The configuration is checked before anything is changed: every store needs a non-empty name
    /// and the names must be unique, otherwise nothing is loaded and kInvalidArgument is returned.
    /// For each TrustStoreConfig:
    ///   - Resolves typed members (slot_name → CertSlotHandle via registry)
    ///   - Creates one TrustStoreHandler per store, which reads its member state from the descriptor
    ///   - Populates the m_slot_memberships reverse index
    ///   - Does NOT load cert content — a store is warmed when a client binds it (AddRef)
    ///
    /// A store whose members or persisted state cannot be used is still created but is not valid
    /// (TrustStoreHandler::IsValid()); it refuses to bind, resolve, and mutate, so a client gets an
    /// error instead of a store with fewer members or default state.
    ///
    /// @param store_configs  Trust store configurations; the vector index becomes the TrustStoreId.
    /// @param slot_registry  Registry used to resolve member slot names to CertSlotHandle.
    /// @param slot_manager   Provides per-slot handlers; if null, no slot I/O is possible.
    /// @return Success, or kInvalidArgument for an empty or duplicate store name.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Load(
        const std::vector<TrustStoreConfig>& store_configs,
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
    /// @return The store handle, or kInvalidResourceId if no store has that name. The handle of an
    ///         invalid store is returned; its operations report kTrustStoreInvalid.
    [[nodiscard]] score::crypto::Expected<TrustStoreHandle, score::crypto::daemon::common::DaemonErrorCode>
    ResolveByName(const std::string& name) const;

    /// @brief Map an application-visible resource ID to a named trust store for one uid.
    /// @param uid             User ID the mapping applies to.
    /// @param app_resource_id Application-scoped resource identifier.
    /// @param store_name      Configured name of the trust store it resolves to.
    void RegisterAppResource(uint32_t uid, const std::string& app_resource_id, const std::string& store_name);

    /// @brief Resolve an application resource ID to a trust store for the uid of @p client_id.
    /// @param app_resource_id Application-scoped resource identifier.
    /// @param client_id       Calling client; its uid selects the mapping.
    /// @return The store handle; kInvalidResourceId if the uid, ID or store name is unknown; or
    ///         kTrustStoreInvalid if the store cannot be used (see TrustStoreHandler::IsValid()).
    [[nodiscard]] score::crypto::Expected<TrustStoreHandle, score::crypto::daemon::common::DaemonErrorCode>
    ResolveAppResource(const std::string& app_resource_id, data_manager::ClientId client_id) const;

    // -----------------------------------------------------------------------
    // Slot membership query
    // -----------------------------------------------------------------------

    /// @brief Return the set of trust store IDs that contain a given cert slot.
    ///
    /// @param slot_handle Certificate slot to look up.
    /// @return Handles of all stores referencing the slot; empty if none.
    [[nodiscard]] std::vector<TrustStoreHandle> GetMembershipsForSlot(CertSlotHandle slot_handle) const;

    // -----------------------------------------------------------------------
    // Runtime notifications and mutations
    // -----------------------------------------------------------------------

    /// @brief Bind a client to a trust store and warm the store's cache.
    ///
    /// Called when a verification context binds a store. Increments the client's reference count,
    /// then asks the handler to build its anchor and CRL cache (a no-op when it is already warm).
    /// The cache stays warm while any client holds a reference, and ReleaseRef() clears it when
    /// the last one is gone. Refs are per client so that releasing one application's contexts
    /// does not affect another application's references to the same shared trust store.
    ///
    /// @param handle    Trust store being bound.
    /// @param client_id Client owning the verification context.
    /// @return Success, kInvalidArgument for an unknown store, or the first failure to read an
    ///         existing member certificate or CRL. On failure the reference is not kept.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> AddRef(
        TrustStoreHandle handle,
        data_manager::ClientId client_id);

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
    /// Evicts the slot's cached state and reloads only that member's anchor and CRL entry from
    /// the slot's current content. Other members are not re-read. A store whose anchors have
    /// not been loaded yet only has the slot's cached state evicted.
    /// Called by CertManagementService after StoreCertificate and ClearSlot. Every trust store
    /// that references the slot is updated.
    ///
    /// A kConditionalExternal member is instead disabled (and the state persisted) until
    /// acknowledged via AcknowledgeMemberUpdate().
    ///
    /// @param changed_slot Slot whose certificate changed.
    void NotifySlotChanged(CertSlotHandle changed_slot);

    /// @brief Refresh one member slot's CRL in the trust store's handler cache.
    ///
    /// The handler re-reads the slot's current CRL snapshot from CertSlotManager. Unlike
    /// NotifySlotChanged(), this does not invalidate or reload the slot's certificate and does
    /// not affect conditional-external member enable/disable state — a CRL update is a
    /// revocation-data refresh, not a change to the anchor's identity.
    /// Called by CertManagementService after the CRL overload of UpdateSlot or ClearSlotCrl. Every
    /// trust store that references the slot is updated.
    ///
    /// @param changed_slot Slot whose CRL changed.
    void NotifySlotCrlChanged(CertSlotHandle changed_slot);

    /// @brief Add a certificate to a trust store's runtime anchor set.
    ///
    /// Performs a fingerprint dedup across ALL member types before searching for
    /// an empty exclusive slot — if the cert is already a member (shared-static,
    /// conditional-external, or exclusive), returns success without consuming a
    /// new slot.
    ///
    /// When @p crl holds bytes the CRL is written to the exclusive slot
    /// atomically with the cert (new add) or as an upsert (cert already present).
    ///
    /// Upsert semantics for existing members:
    ///   - kExclusiveMutable match: CRL is stored/updated; cert is re-enabled.
    ///   - kSharedStatic / kConditionalExternal match: trust store does not own
    ///     these slots; if @p crl holds bytes, kUnsupportedOperation is
    ///     returned. Callers should use ImportCrlToSlot on the slot resource.
    ///
    /// Write access to the trust store must be checked by CertManagementService
    /// before calling this method.
    ///
    /// @param handle       Target trust store.
    /// @param cert        Certificate to add; must not be null.
    /// @param client_id   Calling client, used for the write-permission check.
    /// @param crl         Optional validated CRL to store with the certificate; null means no CRL.
    /// @return success, or kInvalidArgument (bad handle or null cert), kAccessDenied,
    ///         kUnsupportedOperation (CRL given for a non-exclusive member), a slot I/O error,
    ///         or kTrustStoreCapacityExceeded (no empty exclusive slot).
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> AddMember(
        TrustStoreHandle handle,
        CertObject::Sptr cert,
        data_manager::ClientId client_id,
        CrlData::Sptrc crl = nullptr);

    /// @brief Store a CRL in the exclusive trust store slot identified by @p slot.
    ///
    /// Only operates on kExclusiveMutable members — the trust store owns these.
    /// Shared-static and conditional-external slots are externally managed;
    /// callers use the CertManagementService::UpdateSlot CRL overload for those.
    ///
    /// Returns kInvalidResourceId if @p slot is not a member of the trust store.
    /// Returns kUnsupportedOperation if the slot is not kExclusiveMutable.
    ///
    /// @param handle    Target trust store.
    /// @param slot      Member slot receiving the CRL.
    /// @param crl       Validated CRL; its bytes must not be empty.
    /// @param client_id Calling client, used for the write-permission check.
    /// @return success, or kInvalidResourceId, kInvalidArgument (empty CRL), kAccessDenied,
    ///         kUnsupportedOperation, or a slot I/O error.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    StoreCrlForMember(TrustStoreHandle handle,
                      CertSlotHandle slot,
                      const CrlData& crl,
                      data_manager::ClientId client_id);

    /// @brief Delete the persistent CRL of an exclusive trust store member slot.
    ///
    /// @param handle    Target trust store.
    /// @param slot      Member slot whose CRL is cleared.
    /// @param client_id Calling client, used for the write-permission check.
    /// @return success, or kInvalidResourceId (slot not a member), kAccessDenied,
    ///         kUnsupportedOperation (slot not kExclusiveMutable), or a slot I/O error.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ClearCrlForMember(TrustStoreHandle handle, CertSlotHandle slot, data_manager::ClientId client_id);

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

    /// @brief Resolved, point-in-time detail of one trust store member.
    using MemberSnapshot = TrustStoreMemberSnapshot;

    /// @brief List the occupied member slot handles of a trust store, without resolving
    /// certificate content.
    ///
    /// Only checks slot occupancy — no certificate parsing. Combined with GetMemberSnapshot(),
    /// lets a caller resolve one trust store member's detail at a time rather than requiring a
    /// single response sized by the full, configuration-driven member count.
    ///
    /// @param handle Trust store to list.
    /// @return Occupied member slot handles, or kInvalidResourceId if @p handle is invalid.
    [[nodiscard]] score::crypto::Expected<std::vector<CertSlotHandle>, common::DaemonErrorCode> GetMemberSlotHandles(
        TrustStoreHandle handle);

    /// @brief Load and return the snapshot of a single member slot of a trust store.
    ///
    /// Certs are loaded via the shared cache where possible; a fresh load is taken for an
    /// uncached slot. Non-const because it may populate handler and cert caches.
    ///
    /// A kConditionalExternal member is always loaded fresh so that `status` reflects current
    /// slot content: kFingerprintMismatch when it differs from the accepted fingerprint,
    /// kAwaitingAcknowledgement when none was accepted and the store requires acceptance.
    ///
    /// @param handle Trust store the member belongs to.
    /// @param slot   Member slot to snapshot; must be a member of @p handle.
    /// @return The member's snapshot, or kInvalidResourceId if @p handle is invalid or @p slot is
    ///         not a member of it, or kResourceNotFound if the slot is a member but currently
    ///         empty.
    [[nodiscard]] score::crypto::Expected<MemberSnapshot, common::DaemonErrorCode> GetMemberSnapshot(
        TrustStoreHandle handle,
        CertSlotHandle slot);

    // -----------------------------------------------------------------------
    // Configuration access
    // -----------------------------------------------------------------------

    /// @brief Return the TrustStoreConfig for a given store handle.
    /// @param handle Trust store handle.
    /// @return Pointer to the config, or nullptr if @p handle is out of range.
    [[nodiscard]] const TrustStoreConfig* GetStoreConfig(TrustStoreHandle handle) const;

  private:
    /// Returns the handler of @p handle, or nullptr if the handle is invalid or out of range.
    /// The store list is read without locking; it is fixed after Load().
    [[nodiscard]] std::shared_ptr<TrustStoreHandler> FindStore(TrustStoreHandle handle) const;

    /// Evict the anchor cache for @p handle if no client currently holds a ref to it.
    /// Must be called with m_mutex held.
    void MaybeEvictAnchorCache(TrustStoreHandle handle);

    /// Guards m_client_ref_counts. The other members are not locked: they are written only during startup.
    std::mutex m_mutex;

    std::vector<std::shared_ptr<TrustStoreHandler>> m_stores;
    std::unordered_map<std::string, TrustStoreId> m_name_index;
    std::unordered_map<uint32_t, std::unordered_map<std::string, std::string>> m_app_resource_map;

    /// Reverse index: slot handle index → list of trust store IDs that reference it.
    std::unordered_map<uint32_t, std::vector<TrustStoreId>> m_slot_memberships;

    /// Per-client, per-store active context reference counts.
    /// Outer key: ClientId (one entry per connected application).
    /// Inner key: TrustStoreId index. Value: count of verification contexts currently
    /// bound to that store for that client.
    /// An entry is removed when the count drops to zero.
    /// The anchor cache for a store is evicted only when ALL clients' counts drop to zero.
    std::unordered_map<data_manager::ClientId, std::unordered_map<TrustStoreId, uint32_t>> m_client_ref_counts;

    static constexpr std::string_view kLogPrefix = "[TRUST_STORE_MANAGER] ";
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_TRUST_STORE_MANAGER_HPP
