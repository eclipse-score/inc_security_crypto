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

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/policy/access_policy_enforcer.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <cstdint>
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
/// No caller outside CertSlotManager may hold or call a raw ICertSlotHandler.
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
///             dynamic_casts to its extended type.
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
/// Thread safety: m_handlers is guarded by m_mutex. Handlers themselves are not
/// thread-safe; serialization for concurrent backend calls is provided by the
/// DataNode locks in the data manager.
class CertSlotManager final
{
    friend class TrustStoreManager;

  public:
    using Sptr = std::shared_ptr<CertSlotManager>;

    CertSlotManager(CertSlotRegistry::Sptr registry, CertSlotHandlerFactory factory);
    ~CertSlotManager() = default;

    CertSlotManager(const CertSlotManager&) = delete;
    CertSlotManager& operator=(const CertSlotManager&) = delete;
    CertSlotManager(CertSlotManager&&) = delete;
    CertSlotManager& operator=(CertSlotManager&&) = delete;

    // -----------------------------------------------------------------------
    // Tier 1 — read operations (CheckSlotAccess inside)
    // -----------------------------------------------------------------------

    [[nodiscard]] score::crypto::Expected<CertObject::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    LoadCertificate(CertSlotHandle slot, data_manager::ClientId client_id);

    [[nodiscard]] score::crypto::Expected<score::crypto::CertificateSlotInfo,
                                          score::crypto::daemon::common::DaemonErrorCode>
    GetSlotInfo(CertSlotHandle slot, data_manager::ClientId client_id);

    /// Returns false when the slot has no handler or no CRL; never fails.
    [[nodiscard]] bool HasCrl(CertSlotHandle slot);

    [[nodiscard]] score::crypto::Expected<std::vector<uint8_t>, score::crypto::daemon::common::DaemonErrorCode> LoadCrl(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    /// Returns kDer when the slot has no handler or no [crl] section; never fails.
    [[nodiscard]] score::crypto::FormatType GetCrlFormat(CertSlotHandle slot);

    [[nodiscard]] score::crypto::Expected<int64_t, score::crypto::daemon::common::DaemonErrorCode> GetCrlNextUpdate(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    // -----------------------------------------------------------------------
    // Tier 1 — write operations (CheckSlotAccess + CheckWritePermission inside)
    // -----------------------------------------------------------------------

    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    StoreCertificate(CertSlotHandle slot, data_manager::ClientId client_id, const CertObject& cert);

    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ClearSlot(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ImportCrl(
        CertSlotHandle slot,
        data_manager::ClientId client_id,
        score::crypto::span<const uint8_t> crl_data,
        score::crypto::FormatType format,
        std::int64_t next_update_epoch_s);

    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> DeleteCrl(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    // -----------------------------------------------------------------------
    // Tier 2 — provider extension escape hatch
    //
    // CertSlotManager runs CheckSlotAccess (always) and optionally
    // CheckWritePermission (when require_write=true) before returning the handler.
    // The caller dynamic_casts to its extended provider type for custom operations.
    // Must only be called from a provider extension dispatch, not from general
    // executor handler code.
    // -----------------------------------------------------------------------

    [[nodiscard]] score::crypto::Expected<ICertSlotHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    GetProviderCertSlotHandler(CertSlotHandle slot, data_manager::ClientId client_id, bool require_write = false);

  private:
    // -----------------------------------------------------------------------
    // Tier 3 — trust-store backend seam (friend-gated)
    //
    // TrustStoreManager has already enforced trust-store write policy +
    // membership/kind check before calling this method. No client_id — the
    // trust store is the authority for exclusive-slot mutations.
    // Returns nullptr if the slot is not found or the factory returns null.
    // -----------------------------------------------------------------------
    [[nodiscard]] ICertSlotHandler::Sptr GetTrustStoreCertSlotHandler(CertSlotHandle slot);

    // Internal helpers
    [[nodiscard]] score::crypto::Expected<const CertSlotConfig*, score::crypto::daemon::common::DaemonErrorCode>
    GetConfig(CertSlotHandle slot) const;

    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ApplyWriteChecks(const CertSlotConfig& cfg, data_manager::ClientId client_id);

    /// Returns the cached handler or creates it via the factory. Must be called with m_mutex held.
    [[nodiscard]] ICertSlotHandler::Sptr GetOrCreate(CertSlotHandle slot);

    /// Evict the CertObject cache entry for @p slot. Must be called after any
    /// write that replaces the slot's certificate content (StoreCertificate, ClearSlot).
    void InvalidateCertObjectCache(CertSlotHandle slot);

    CertSlotRegistry::Sptr m_registry;
    CertSlotHandlerFactory m_factory;
    std::unordered_map<uint32_t, ICertSlotHandler::Sptr> m_handlers;
    /// Weak-pointer cache of parsed CertObjects keyed by slot index.
    /// Avoids repeated disk reads when multiple clients open the same slot cert.
    /// Entries are evicted automatically when no CertEntry holds a strong ref,
    /// and explicitly invalidated on StoreCertificate / ClearSlot.
    std::unordered_map<uint32_t, std::weak_ptr<CertObject>> m_cert_object_cache;
    mutable std::mutex m_mutex;

    static constexpr std::string_view kLogPrefix{"[CERT_SLOT_MANAGER] "};
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_CERT_SLOT_MANAGER_HPP
