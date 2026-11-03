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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_REGISTRY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_REGISTRY_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace score::crypto::daemon::cert_management
{

class CertEntry;

/// Registry of live certificates, owned by the single CertManagementService
/// for the daemon.
///
/// CertRegistry is constructed once, by CertManagementService, and reached by
/// every CERT:* context handler through that one service instance. It holds
/// shared ownership of every CertEntry registered through it (both
/// slot-loaded and ephemeral). CertDataNode instances in the client tree hold
/// an additional shared_ptr to the same CertEntry, keeping it alive as long
/// as any client references it.
///
/// Thread safety: registry operations are serialized by an internal mutex.
/// Object construction and destruction must not race with registry operations.
class CertRegistry final
{
  public:
    using Sptr = std::shared_ptr<CertRegistry>;

    CertRegistry() = default;
    ~CertRegistry() = default;

    CertRegistry(const CertRegistry&) = delete;
    CertRegistry& operator=(const CertRegistry&) = delete;
    CertRegistry(CertRegistry&&) = delete;
    CertRegistry& operator=(CertRegistry&&) = delete;

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    /// Register a certificate that was loaded from a persistent slot.
    ///
    /// Every call creates a new registry entry regardless of the slot; callers
    /// that load the same slot for different clients each receive an independent
    /// CertEntry so that per-client state (e.g. session CRL) cannot bleed.
    /// @param slot_handle Slot associated with the loaded certificate.
    /// @param cert_entry Non-null certificate entry to register.
    /// @return Non-zero registry ID, or 0U if @p cert_entry is null.
    /// @note Thread safety: insertion is serialized with other registry operations.
    [[nodiscard]] CertRegistryId RegisterSlotCert(CertSlotHandle slot_handle, std::shared_ptr<CertEntry> cert_entry);

    /// Register an ephemeral (non-slot) certificate.
    /// @param cert_entry Non-null certificate entry to register.
    /// @return Non-zero registry ID, or 0U if @p cert_entry is null.
    /// @note Thread safety: insertion is serialized with other registry operations.
    [[nodiscard]] CertRegistryId RegisterEphemeralCert(std::shared_ptr<CertEntry> cert_entry);

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    /// Find a registered certificate entry by its registry ID.
    /// @param id Registry ID returned by a successful registration call.
    /// @return Shared pointer to the entry, or nullptr if the ID is not registered.
    /// @note Thread safety: lookup is serialized; the returned shared pointer keeps the entry alive after return.
    [[nodiscard]] std::shared_ptr<CertEntry> FindById(CertRegistryId id) const;

    // ------------------------------------------------------------------
    // Removal
    // ------------------------------------------------------------------

    /// Remove a registered certificate entry.
    /// @param id Registry ID of the entry to remove.
    /// @return true if the entry was found and removed; false if the ID was not registered.
    /// @note Thread safety: removal is serialized with other registry operations.
    bool Unregister(CertRegistryId id);

    // ------------------------------------------------------------------
    // Crash cleanup
    // ------------------------------------------------------------------

    /// Remove entries owned by a client. Invalid null entries are also removed defensively.
    /// @param client_id Client whose certificate entries are to be removed.
    /// @note Thread safety: cleanup is serialized with other registry operations.
    void CleanupClient(data_manager::ClientId client_id);

    // ------------------------------------------------------------------
    // Query
    // ------------------------------------------------------------------

    /// Return the number of entries currently held by the registry.
    /// @return Number of registered entries.
    /// @note Thread safety: the count is read while holding the registry mutex.
    [[nodiscard]] std::size_t Size() const;

  private:
    mutable std::mutex m_mutex;
    std::unordered_map<CertRegistryId, std::shared_ptr<CertEntry>> m_certs;
    CertRegistryId m_next_id{1U};
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_REGISTRY_HPP
