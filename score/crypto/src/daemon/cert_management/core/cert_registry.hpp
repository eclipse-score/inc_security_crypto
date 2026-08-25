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
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace score::crypto::daemon::cert_management
{

class CertEntry;

/// Per-provider registry of live certificates.
///
/// Holds shared ownership of every CertEntry produced by a single provider
/// (both slot-loaded and ephemeral). CertDataNode instances in the client
/// tree hold an additional shared_ptr to the same CertEntry, keeping it alive
/// as long as any client references it.
///
/// Thread safety: all public methods serialise on an internal mutex.
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
    /// Returns 0 if the slot is already registered (caller should call
    /// FindBySlot() first to check).
    [[nodiscard]] CertRegistryId RegisterSlotCert(CertSlotHandle slot_handle, std::shared_ptr<CertEntry> cert_entry);

    /// Register an ephemeral (non-slot) certificate.
    [[nodiscard]] CertRegistryId RegisterEphemeralCert(std::shared_ptr<CertEntry> cert_entry);

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    [[nodiscard]] std::shared_ptr<CertEntry> FindBySlot(CertSlotHandle slot_handle) const;
    [[nodiscard]] CertRegistryId FindSlotRegistryId(CertSlotHandle slot_handle) const;
    [[nodiscard]] std::shared_ptr<CertEntry> FindById(CertRegistryId id) const;

    // ------------------------------------------------------------------
    // Removal
    // ------------------------------------------------------------------

    /// @return true if the cert was found and removed.
    bool Unregister(CertRegistryId id);

    // ------------------------------------------------------------------
    // Crash cleanup
    // ------------------------------------------------------------------

    void CleanupClient(data_manager::ClientId client_id);

    // ------------------------------------------------------------------
    // Query
    // ------------------------------------------------------------------

    [[nodiscard]] std::size_t Size() const;

  private:
    mutable std::mutex m_mutex;
    std::unordered_map<CertRegistryId, std::shared_ptr<CertEntry>> m_certs;
    std::unordered_map<uint32_t, CertRegistryId> m_slot_to_id;
    CertRegistryId m_next_id{1U};
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_REGISTRY_HPP
