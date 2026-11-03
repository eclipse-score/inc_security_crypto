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

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

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
    /// Construct a registry entry around a provider-neutral certificate object.
    ///
    /// @param owner        The client that owns this entry.
    /// @param object       Owning cert object (must not be nullptr).
    /// @param slot_handle  Non-default only when cert was loaded from a slot.
    CertEntry(data_manager::ClientId owner, CertObject::Sptr object, CertSlotHandle slot_handle = CertSlotHandle{});

    /// Releases this entry's shared ownership of the underlying CertObject and any session CRL.
    ~CertEntry();

    CertEntry(const CertEntry&) = delete;
    CertEntry& operator=(const CertEntry&) = delete;
    CertEntry(CertEntry&&) = delete;
    CertEntry& operator=(CertEntry&&) = delete;

    /// Return the provider-neutral certificate object held by this entry.
    ///
    /// @return Shared pointer to the certificate object; never nullptr.
    /// @note Thread-safe. The underlying value is fixed at construction and
    ///       never modified afterward, so concurrent calls from any thread
    ///       require no external synchronization.
    [[nodiscard]] CertObject::Sptr GetCertObject() const noexcept;

    /// Return the slot this certificate was loaded from, if any.
    ///
    /// @return The originating slot handle, or a default-constructed handle
    ///         when the entry is ephemeral and has no backing slot.
    /// @note Thread-safe. The underlying value is fixed at construction and
    ///       never modified afterward, so concurrent calls from any thread
    ///       require no external synchronization.
    [[nodiscard]] CertSlotHandle GetSlotHandle() const noexcept;

    // -----------------------------------------------------------------------
    // Session-scoped CRL association
    //
    // A session CRL is validated by the caller (signature, issuer match, validity)
    // before it is attached. CertEntry stores the bytes verbatim and does not
    // validate them again. The association lasts for the session only: it is not
    // kept across a daemon restart and is never written to disk. An ephemeral
    // kCertificate can therefore carry a CRL without write access to a slot.
    // -----------------------------------------------------------------------

    /// Attach a validated CRL to this entry for the current session.
    ///
    /// @param crl  Encoded CRL bytes, encoding, and optional metadata; stored verbatim without re-validation.
    /// @note Thread-safe. Access to the session CRL state is serialized
    ///       internally via a dedicated mutex.
    void AttachSessionCrl(CrlData crl);

    /// Check whether a session-scoped CRL has been attached.
    ///
    /// @return True when a CRL was attached via AttachSessionCrl() and has not
    ///         since been cleared.
    /// @note Thread-safe. Access to the session CRL state is serialized
    ///       internally via a dedicated mutex.
    [[nodiscard]] bool HasSessionCrl() const;

    /// Remove the session CRL association.
    ///
    /// @note Thread-safe. Access to the session CRL state is serialized
    ///       internally via a dedicated mutex.
    void ClearSessionCrl();

    /// Return the bytes, format, and metadata of the attached session CRL as one snapshot.
    ///
    /// The fields come from one immutable object, so they always belong to the same attachment.
    ///
    /// @return The attached CRL snapshot, or a null pointer when no CRL is
    ///         currently attached. The snapshot is immutable: a later attach or
    ///         clear does not modify it.
    /// @note Thread-safe. Access to the session CRL state is serialized
    ///       internally via a dedicated mutex; only the pointer is copied
    ///       under the lock.
    [[nodiscard]] CrlData::Sptrc GetSessionCrlSnapshot() const;

    // -----------------------------------------------------------------------
    // Ownership
    // -----------------------------------------------------------------------

    /// Return the identifier of the client that owns this entry.
    ///
    /// @return The owning client's identifier.
    /// @note Thread-safe. The underlying value is fixed at construction and
    ///       never modified afterward, so concurrent calls from any thread
    ///       require no external synchronization.
    [[nodiscard]] data_manager::ClientId GetOwner() const noexcept;

    /// Check whether the given client owns this entry.
    ///
    /// @param client_id  Client identifier to compare against the owner.
    /// @return True when @p client_id matches the owning client.
    /// @note Thread-safe. The underlying value is fixed at construction and
    ///       never modified afterward, so concurrent calls from any thread
    ///       require no external synchronization.
    [[nodiscard]] bool IsOwnedBy(data_manager::ClientId client_id) const noexcept;

  private:
    /// Provider-neutral certificate held by this entry.
    CertObject::Sptr m_object;
    /// Originating slot, or a default handle when the certificate is ephemeral.
    CertSlotHandle m_slot_handle;
    /// Client that owns this entry.
    data_manager::ClientId m_owner_client_id;
    /// Protects access to the mutable session-CRL association.
    mutable std::mutex m_ref_mutex;
    /// Optional session-scoped CRL associated with the certificate.
    CrlData::Sptrc m_session_crl;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_ENTRY_HPP
