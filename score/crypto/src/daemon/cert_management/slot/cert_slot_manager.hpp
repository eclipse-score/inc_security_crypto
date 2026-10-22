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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_CERT_SLOT_MANAGER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_CERT_SLOT_MANAGER_HPP

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/policy/access_policy_enforcer.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace score::crypto::daemon::cert_management
{

class TrustStoreManager;

/// @brief Central owner of certificate slot handler instances and the sole
///        enforcement point for slot-level access policy.
///
/// All backend operations on a certificate slot must pass through this manager.
/// No caller outside CertSlotManager may hold or call a raw ICertSlotHandler, except through the Tier 2
/// accessor below and under the constraints stated there.
///
/// The API is divided into three tiers:
///
///   Tier 1 — operation-oriented (executor / IPC handler path).
///             Authorization is unconditional inside each method.
///             Read ops call CheckSlotAccess; write ops also call CheckWritePermission.
///
///   Tier 2 — GetProviderCertSlotHandler (public).
///             For provider extension dispatch that needs functionality beyond
///             ICertSlotHandler (e.g. custom PKCS#11 attributes). CertSlotManager
///             runs the same slot policy before returning the handler; the caller
///             dynamic_casts to its extended type. Only provider code calls this
///             accessor. Mutations go through the Tier 1 write methods, which run the
///             trust-store notification and cache invalidation.
///
///   Tier 3 — GetTrustStoreCertSlotHandler (private, friend-gated).
///             For TrustStoreManager only, which has already enforced trust-store
///             write policy + membership/kind check before calling this method.
///
/// Handler instances are created lazily on first access and cached per slot
/// (keyed by CertSlotHandle::index). This eliminates the per-call PKCS#11 session
/// overhead that existed when CertManagementService created a fresh handler on
/// every ResolveSlotForOperation call.
///
/// Thread safety: m_handlers and m_slot_cache are guarded by m_mutex. Backend calls
/// are made without holding that mutex and may be invoked concurrently for the
/// same handler. Each ICertSlotHandler implementation must serialize operations
/// on its slot, including reads that must be consistent with writes; independent
/// slot handlers can proceed concurrently. A load records the generation of the
/// part it reads (certificate or CRL) before its backend read and caches the result
/// only if that generation is unchanged afterwards, so a read that overlaps a write
/// or invalidation is returned to its caller but never cached.
class CertSlotManager final
{
    friend class TrustStoreManager;
    friend class TrustStoreHandler;

  public:
    using Sptr = std::shared_ptr<CertSlotManager>;

    /// @brief Construct a manager over the configured slots.
    /// @param registry Resolves slot handles to their configuration. Without it every operation fails with
    ///                 kInternalError.
    /// @param factory  Creates the backend handler for a slot on first access. Without it no handler can be created.
    CertSlotManager(CertSlotRegistry::Sptr registry, CertSlotHandlerFactory factory);
    ~CertSlotManager() = default;

    CertSlotManager(const CertSlotManager&) = delete;
    CertSlotManager& operator=(const CertSlotManager&) = delete;
    CertSlotManager(CertSlotManager&&) = delete;
    CertSlotManager& operator=(CertSlotManager&&) = delete;

    // -----------------------------------------------------------------------
    // Tier 1 — read operations (CheckSlotAccess inside)
    // -----------------------------------------------------------------------

    /// @brief Load the certificate stored in a slot.
    /// @details Served from the certificate cache while any holder keeps the object alive; otherwise read through the
    /// slot's handler and cached.
    /// @param slot      Slot to read.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return The parsed certificate, an access-policy or registry error, kInternalError when no handler is
    ///         available, or the handler's error (e.g. for an empty slot).
    [[nodiscard]] score::crypto::Expected<CertObject::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    LoadCertificate(CertSlotHandle slot, data_manager::ClientId client_id);

    /// @brief Return the state and descriptive information of a slot.
    /// @param slot      Slot to inspect.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return The slot information, an access-policy or registry error, kInternalError when no handler is
    ///         available, or the handler's error.
    [[nodiscard]] score::crypto::Expected<score::crypto::CertificateSlotInfo,
                                          score::crypto::daemon::common::DaemonErrorCode>
    GetSlotInfo(CertSlotHandle slot, data_manager::ClientId client_id);

    /// @brief Report whether a slot has a stored CRL.
    /// @details Answered from the slot's cached CRL state (see m_slot_cache); populated from the backend on first
    /// access and after any write that can change CRL state.
    /// @param slot      Slot to inspect.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return True when a CRL is stored, an access-policy or registry error, kInternalError when no handler is
    ///         available, or the handler's error.
    [[nodiscard]] score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode> HasCrl(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    /// @brief Load the slot's CRL as an immutable snapshot.
    /// @details Bytes, format, and metadata are read from the backend together. The snapshot is immutable: a holder
    /// keeps the bytes it read, even after a CRL update. Loads that start after an update return a new snapshot.
    /// @param slot      Slot to read.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return The snapshot, or a null pointer when the slot has no CRL; an access-policy or registry error,
    ///         kInternalError when no handler is available, or the handler's error.
    [[nodiscard]] score::crypto::Expected<CrlData::Sptrc, score::crypto::daemon::common::DaemonErrorCode> LoadCrlData(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    /// @brief Return the metadata of the slot's CRL from the cached entry, without reading the CRL itself.
    /// @param slot      Slot to inspect.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return The metadata, an empty optional when the slot has no CRL or the CRL has no usable metadata
    ///         (HasCrl() tells the two apart), an access-policy or registry error, kInternalError when no
    ///         handler is available, or the handler's error.
    [[nodiscard]] score::crypto::Expected<std::optional<score::crypto::CrlMetadata>,
                                          score::crypto::daemon::common::DaemonErrorCode>
    GetCrlMetadata(CertSlotHandle slot, data_manager::ClientId client_id);

    /// @brief Return the next-update time of the slot's CRL.
    /// @details Answered from the cached CRL entry.
    /// @param slot      Slot to inspect.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return The next-update time as Unix epoch seconds; kResourceNotAllocated both when no CRL is stored and when
    ///         a stored CRL has no usable next-update value (including a malformed one), since either way no value
    ///         is available; or an access-policy, registry, or handler error.
    [[nodiscard]] score::crypto::Expected<int64_t, score::crypto::daemon::common::DaemonErrorCode> GetCrlNextUpdate(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    // -----------------------------------------------------------------------
    // Tier 1 — write operations (CheckSlotAccess + CheckWritePermission inside)
    // -----------------------------------------------------------------------

    /// @brief Store a certificate in a slot.
    /// @details The slot's certificate and CRL caches are invalidated after the write, whether or not it
    /// succeeded. Any CRL previously stored with the slot is discarded by the handler.
    /// @param slot      Slot to write.
    /// @param client_id Client requesting the write; needs slot access and write permission.
    /// @param cert      Certificate to store.
    /// @param content_may_have_changed Optional. Set to true when the write reaches the backend, even if it fails.
    ///        The caller uses it to decide whether dependent trust stores must be refreshed.
    ///        Not modified when the write is refused or no handler is available.
    /// @return Success, an access-policy or registry error, kInternalError when no handler is available, or the
    ///         handler's error.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    StoreCertificate(CertSlotHandle slot,
                     data_manager::ClientId client_id,
                     const CertObject& cert,
                     bool* content_may_have_changed = nullptr);

    /// @brief Erase the certificate and any CRL stored in a slot.
    /// @details The slot's certificate and CRL caches are invalidated after the write, whether or not it succeeded.
    /// @param slot      Slot to clear.
    /// @param client_id Client requesting the write; needs slot access and write permission.
    /// @param content_may_have_changed Optional. Set to true when the write reaches the backend, even if it fails.
    ///        The caller uses it to decide whether dependent trust stores must be refreshed.
    ///        Not modified when the write is refused or no handler is available.
    /// @return Success, an access-policy or registry error, kInternalError when no handler is available, or the
    ///         handler's error.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ClearSlot(CertSlotHandle slot, data_manager::ClientId client_id, bool* content_may_have_changed = nullptr);

    /// @brief Store a CRL in a slot.
    /// @details The slot's CRL cache is invalidated after the write, whether or not it succeeded. The CRL is stored as
    /// given; validation is the caller's responsibility.
    /// @param slot      Slot to write.
    /// @param client_id Client requesting the write; needs slot access and write permission.
    /// @param crl       Encoded CRL bytes, encoding, and optional validated metadata; copied by the handler.
    /// @param content_may_have_changed Optional. Set to true when the write reaches the backend, even if it fails.
    ///        The caller uses it to decide whether dependent trust stores must be refreshed.
    ///        Not modified when the write is refused or no handler is available.
    /// @return Success, an access-policy or registry error, kInternalError when no handler is available, or the
    ///         handler's error.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> StoreCrl(
        CertSlotHandle slot,
        data_manager::ClientId client_id,
        const CrlData& crl,
        bool* content_may_have_changed = nullptr);

    /// @brief Remove the CRL stored in a slot.
    /// @details The slot's CRL cache is invalidated after the write, whether or not it succeeded.
    /// @param slot      Slot whose CRL is removed.
    /// @param client_id Client requesting the write; needs slot access and write permission.
    /// @param content_may_have_changed Optional. Set to true when the write reaches the backend, even if it fails.
    ///        The caller uses it to decide whether dependent trust stores must be refreshed.
    ///        Not modified when the write is refused or no handler is available.
    /// @return Success, an access-policy or registry error, kInternalError when no handler is available, or the
    ///         handler's error.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ClearCrl(CertSlotHandle slot, data_manager::ClientId client_id, bool* content_may_have_changed = nullptr);

    // -----------------------------------------------------------------------
    // Tier 2 — provider extension escape hatch
    //
    // CertSlotManager runs CheckSlotAccess (always) and optionally
    // CheckWritePermission (when require_write=true) before returning the handler.
    // The caller dynamic_casts to its extended provider type for custom operations.
    // Must only be called from a provider extension dispatch, not from general
    // executor handler code.
    // -----------------------------------------------------------------------

    /// @brief Return the slot's backend handler for provider-specific operations.
    /// @param slot          Slot whose handler is returned.
    /// @param client_id     Client requesting the handler; checked against the slot's access policy.
    /// @param require_write When true the client also needs write permission on the slot.
    /// @return The handler, an access-policy or registry error, or kInternalError when no handler is available.
    [[nodiscard]] score::crypto::Expected<ICertSlotHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    GetProviderCertSlotHandler(CertSlotHandle slot, data_manager::ClientId client_id, bool require_write = false);

  private:
    // -----------------------------------------------------------------------
    // Tier 3 — trust-store backend seam (friend-gated)
    //
    // TrustStoreManager has already enforced trust-store write policy +
    // membership/kind check before calling this method. No client_id — the
    // trust store is the authority for exclusive-slot mutations.
    // -----------------------------------------------------------------------

    /// @brief Return the slot's backend handler for the trust-store seam.
    /// @param slot Slot whose handler is returned.
    /// @return The handler, or nullptr if the slot is not found or the factory returns null.
    [[nodiscard]] ICertSlotHandler::Sptr GetTrustStoreCertSlotHandler(CertSlotHandle slot);

    /// @brief Load the slot's certificate without a client access check.
    /// @details Goes through the same certificate cache as LoadCertificate(), so one cache serves every reader of a
    /// slot. Trust-store anchor loading uses this method.
    /// @param slot Slot to read.
    /// @return The parsed certificate, a registry error, kInternalError when no handler is available, or the
    ///         handler's error.
    [[nodiscard]] score::crypto::Expected<CertObject::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    LoadCertificateForTrustStore(CertSlotHandle slot);

    /// @brief Load the slot's CRL snapshot without a client access check.
    /// @param slot Slot to read.
    /// @return As LoadCrlData(), without the access-policy error.
    [[nodiscard]] score::crypto::Expected<CrlData::Sptrc, score::crypto::daemon::common::DaemonErrorCode>
    LoadCrlDataForTrustStore(CertSlotHandle slot);

    /// @brief Evict the cached certificate and CRL state for a slot.
    /// @details Called after a write that changes the certificate (StoreCertificate, ClearSlot), and by
    /// TrustStoreManager before it re-reads a slot whose content may have changed outside this manager.
    /// @param slot Slot whose cached state is evicted.
    void InvalidateSlotCaches(CertSlotHandle slot);

    // Internal helpers

    /// @brief Look up a slot's configuration in the registry.
    /// @param slot Slot to resolve.
    /// @return The configuration, which the registry owns; the registry's error when the slot is unknown; or
    ///         kInternalError when there is no registry.
    [[nodiscard]] score::crypto::Expected<std::reference_wrapper<const CertSlotConfig>,
                                          score::crypto::daemon::common::DaemonErrorCode>
    GetConfig(CertSlotHandle slot) const;

    /// @brief Check that a client may write a slot.
    /// @param cfg       Configuration of the slot to write.
    /// @param client_id Client requesting the write.
    /// @return Success, or the access-policy error when the client has no write permission.
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ApplyWriteChecks(const CertSlotConfig& cfg, data_manager::ClientId client_id);

    /// @brief Return the cached handler for a slot, creating it via the factory on first use.
    /// @details Must be called with m_mutex held.
    /// @param slot Slot whose handler is returned.
    /// @return The handler, or nullptr when there is no factory or registry, the slot is unknown, or the factory
    ///         returns null.
    [[nodiscard]] ICertSlotHandler::Sptr GetOrCreate(CertSlotHandle slot);

    /// @brief Load a slot's certificate through the certificate cache.
    /// @details Shared body of LoadCertificate() and LoadCertificateForTrustStore(): serves the cache and otherwise
    /// reads through the slot's handler. Manages its own locking; the backend call is made without holding m_mutex.
    /// @param slot Slot to read.
    /// @param cfg  Configuration of @p slot.
    /// @return The parsed certificate, kInternalError when no handler is available, or the handler's error.
    [[nodiscard]] score::crypto::Expected<CertObject::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    LoadCertificateCached(CertSlotHandle slot, const CertSlotConfig& cfg);

    /// Presence and metadata of one slot's CRL, as cached without the CRL bytes.
    struct CrlState
    {
        bool has_crl{false};
        std::optional<score::crypto::CrlMetadata> metadata;
    };

    /// Everything cached for one slot. The certificate and the CRL are invalidated independently,
    /// and each has a generation that its invalidation advances. A load that overlapped an
    /// invalidation of its own part is returned to its caller but not cached. The certificate and the
    /// CRL snapshot are held weakly, so they are freed when no holder remains; the CRL state is a small
    /// value held strongly.
    struct SlotCache
    {
        std::weak_ptr<CertObject> certificate;
        uint64_t certificate_generation{0};

        /// Unset until the CRL state has been loaded for the first time.
        std::optional<CrlState> crl_state;
        std::weak_ptr<const CrlData> crl_snapshot;
        uint64_t crl_generation{0};

        void ResetCertificate()
        {
            certificate.reset();
            ++certificate_generation;
        }

        void ResetCrl()
        {
            crl_state.reset();
            crl_snapshot.reset();
            ++crl_generation;
        }
    };

    /// @brief Check access to a slot and return its cached CRL state.
    /// @param slot      Slot to inspect.
    /// @param client_id Client requesting the read; checked against the slot's access policy.
    /// @return The CRL state, an access-policy or registry error, kInternalError when no handler is available, or
    ///         the handler's error.
    [[nodiscard]] score::crypto::Expected<CrlState, score::crypto::daemon::common::DaemonErrorCode> GetCrlStateChecked(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    /// @brief Return the slot's cached CRL state, populating it on a cache miss.
    /// @details Manages its own locking; the backend calls on a miss are made without holding m_mutex, consistent
    /// with LoadCertificate().
    /// @param slot    Slot to inspect.
    /// @param handler Handler used to read the state on a miss.
    /// @param cfg     Configuration of @p slot.
    /// @return The CRL state, or the handler's error.
    [[nodiscard]] score::crypto::Expected<CrlState, score::crypto::daemon::common::DaemonErrorCode>
    GetOrLoadCrlState(CertSlotHandle slot, const ICertSlotHandler::Sptr& handler, const CertSlotConfig& cfg);

    /// @brief Return the slot's CRL snapshot, serving a live cached snapshot or reading one from the handler.
    /// @details Manages its own locking, as GetOrLoadCrlState() does.
    /// @param slot Slot to read.
    /// @param cfg  Configuration of @p slot.
    /// @return The snapshot, or a null pointer when the slot has no CRL; kInternalError when no handler is
    ///         available, or the handler's error.
    [[nodiscard]] score::crypto::Expected<CrlData::Sptrc, score::crypto::daemon::common::DaemonErrorCode>
    GetOrLoadCrlData(CertSlotHandle slot, const CertSlotConfig& cfg);

    /// @brief Evict the cached CRL state and snapshot for a slot.
    /// @details Called after a write that changes only the CRL (StoreCrl, ClearCrl).
    /// @param slot Slot whose CRL state is evicted.
    void InvalidateCrl(CertSlotHandle slot);

    CertSlotRegistry::Sptr m_registry;
    CertSlotHandlerFactory m_factory;
    std::unordered_map<uint32_t, ICertSlotHandler::Sptr> m_handlers;
    /// Certificate and CRL caches keyed by slot index. See SlotCache.
    std::unordered_map<uint32_t, SlotCache> m_slot_cache;
    mutable std::mutex m_mutex;

    static constexpr std::string_view kLogPrefix{"[CERT_SLOT_MANAGER] "};
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_CERT_SLOT_MANAGER_HPP
