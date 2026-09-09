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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_ENTRY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_ENTRY_HPP

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

namespace score::crypto::daemon::cert_management
{

/// Registry entry for a single live certificate (ephemeral or slot-loaded).
///
/// Holds shared ownership of a provider-neutral CertObject. The bytes and
/// metadata are freed automatically when the last shared_ptr is destroyed.
///
/// Client-visible references are CertDataNode instances in the DataManager
/// client tree.
class CertEntry final : public std::enable_shared_from_this<CertEntry>
{
  public:
    /// @param object       Owning cert object (must not be nullptr).
    /// @param slot_handle  Non-default only when cert was loaded from a slot.
    /// @param owner        The client that owns this entry.
    CertEntry(CertObject::Sptr object, CertSlotHandle slot_handle = CertSlotHandle{}, data_manager::ClientId owner = 0U)
        : m_object{std::move(object)}, m_slot_handle{slot_handle}, m_owner_client_id{owner}
    {
    }

    ~CertEntry() = default;

    CertEntry(const CertEntry&) = delete;
    CertEntry& operator=(const CertEntry&) = delete;
    CertEntry(CertEntry&&) = delete;
    CertEntry& operator=(CertEntry&&) = delete;

    [[nodiscard]] CertObject::Sptr GetCertObject() const noexcept
    {
        return m_object;
    }

    [[nodiscard]] CertSlotHandle GetSlotHandle() const noexcept
    {
        return m_slot_handle;
    }

    // -----------------------------------------------------------------------
    // Session-scoped CRL association
    //
    // A session CRL is validated externally (signature, issuer match, validity)
    // before being attached. CertEntry stores the bytes verbatim; no re-validation
    // occurs. The association is session-lifetime — it does not survive a daemon
    // restart and is never written to disk. This allows ImportCrl(persist=false)
    // to associate a CRL with either an ephemeral kCertificate or a persistent
    // kCertSlot without requiring write access to the slot's deployment descriptor.
    // -----------------------------------------------------------------------

    /// Attach a previously-validated CRL to this entry for the current session.
    void AttachSessionCrl(std::vector<uint8_t> crl_bytes, score::crypto::FormatType format)
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        m_session_crl = std::move(crl_bytes);
        m_session_crl_format = format;
    }

    /// True when a session-scoped CRL has been attached via AttachSessionCrl().
    [[nodiscard]] bool HasSessionCrl() const
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        return m_session_crl.has_value();
    }

    /// Return a copy of the session CRL bytes, or an empty optional if none.
    [[nodiscard]] std::optional<std::vector<uint8_t>> GetSessionCrl() const
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        return m_session_crl;
    }

    [[nodiscard]] score::crypto::FormatType GetSessionCrlFormat() const
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        return m_session_crl_format;
    }

    /// Remove the session CRL association (e.g. after persisting to a slot).
    void ClearSessionCrl()
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        m_session_crl.reset();
        m_session_crl_format = score::crypto::FormatType::kDer;
    }

    // -----------------------------------------------------------------------
    // Ownership
    // -----------------------------------------------------------------------

    [[nodiscard]] data_manager::ClientId GetOwner() const noexcept
    {
        return m_owner_client_id;
    }

    [[nodiscard]] bool IsOwnedBy(data_manager::ClientId client_id) const noexcept
    {
        return m_owner_client_id == client_id;
    }

  private:
    CertObject::Sptr m_object;
    CertSlotHandle m_slot_handle;
    data_manager::ClientId m_owner_client_id{0U};

    mutable std::mutex m_ref_mutex;
    std::optional<std::vector<uint8_t>> m_session_crl;
    score::crypto::FormatType m_session_crl_format{score::crypto::FormatType::kDer};
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_ENTRY_HPP
