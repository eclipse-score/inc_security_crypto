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
    CertEntry(data_manager::ClientId owner, CertObject::Sptr object, CertSlotHandle slot_handle = CertSlotHandle{})
        : m_object{std::move(object)}, m_slot_handle{slot_handle}, m_owner_client_id{owner}
    {
    }

    /// Default destructor; shared ownership of the underlying CertObject is
    /// released automatically.
    ~CertEntry() = default;

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
    [[nodiscard]] CertObject::Sptr GetCertObject() const noexcept
    {
        return m_object;
    }

    /// Return the slot this certificate was loaded from, if any.
    ///
    /// @return The originating slot handle, or a default-constructed handle
    ///         when the entry is ephemeral and has no backing slot.
    /// @note Thread-safe. The underlying value is fixed at construction and
    ///       never modified afterward, so concurrent calls from any thread
    ///       require no external synchronization.
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
    // restart and is never written to disk. This allows ImportCrl() to associate
    // a CRL with an ephemeral kCertificate without requiring slot write access.
    // -----------------------------------------------------------------------

    /// Attach a previously-validated CRL to this entry for the current session.
    ///
    /// @param crl_bytes  Raw CRL bytes, stored verbatim without re-validation.
    /// @param format     Encoding of @p crl_bytes.
    /// @param metadata   Optional parsed CRL metadata associated with the bytes.
    /// @note Thread-safe. Access to the session CRL state is serialized
    ///       internally via a dedicated mutex.
    void AttachSessionCrl(std::vector<uint8_t> crl_bytes,
                          score::crypto::FormatType format,
                          std::optional<score::crypto::CrlMetadata> metadata = std::nullopt)
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        m_session_crl = CrlData{std::move(crl_bytes), format, std::move(metadata)};
    }

    /// Check whether a session-scoped CRL has been attached.
    ///
    /// @return True when a CRL was attached via AttachSessionCrl() and has not
    ///         since been cleared.
    /// @note Thread-safe. Access to the session CRL state is serialized
    ///       internally via a dedicated mutex.
    [[nodiscard]] bool HasSessionCrl() const
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        return m_session_crl.has_value();
    }

    /// Retrieve the attached session CRL bytes, if any.
    ///
    /// @return A copy of the session CRL bytes, or an empty optional when no
    ///         CRL is currently attached.
    /// @note Thread-safe. Access to the session CRL state is serialized
    ///       internally via a dedicated mutex.
    [[nodiscard]] std::optional<std::vector<uint8_t>> GetSessionCrl() const
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        if (!m_session_crl.has_value())
            return std::nullopt;
        return m_session_crl->bytes;
    }

    /// Return the encoding format of the attached session CRL.
    ///
    /// @return The attached CRL's format, or an empty optional when no CRL
    ///         is attached.
    /// @note Thread-safe. Access to the session CRL state is serialized
    ///       internally via a dedicated mutex.
    [[nodiscard]] std::optional<score::crypto::FormatType> GetSessionCrlFormat() const
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        if (!m_session_crl.has_value())
            return std::nullopt;
        return m_session_crl->format;
    }

    /// Return the parsed metadata of the attached session CRL, if any.
    ///
    /// @return The metadata passed to the most recent AttachSessionCrl() call,
    ///         or an empty optional when none was supplied or no CRL is attached.
    /// @note Thread-safe. Access to the session CRL state is serialized
    ///       internally via a dedicated mutex.
    [[nodiscard]] std::optional<score::crypto::CrlMetadata> GetSessionCrlMetadata() const
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        if (!m_session_crl.has_value())
            return std::nullopt;
        return m_session_crl->metadata;
    }

    /// Remove the session CRL association (e.g. after persisting to a slot).
    ///
    /// @note Thread-safe. Access to the session CRL state is serialized
    ///       internally via a dedicated mutex.
    void ClearSessionCrl()
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        m_session_crl.reset();
    }

    /// Retrieve the session CRL bytes, format, and metadata together as a
    /// single consistent snapshot.
    ///
    /// Prefer this over calling GetSessionCrl(), GetSessionCrlFormat(), and
    /// GetSessionCrlMetadata() separately when more than one of these fields
    /// is needed: those calls each acquire and release the internal mutex
    /// independently, so an AttachSessionCrl() or ClearSessionCrl() call
    /// interleaved between them could otherwise produce a combination of
    /// fields that never existed together (e.g. new bytes paired with the
    /// previous format).
    ///
    /// @return The attached CRL snapshot, or an empty optional when no CRL is
    ///         currently attached.
    /// @note Thread-safe. Access to the session CRL state is serialized
    ///       internally via a dedicated mutex.
    [[nodiscard]] std::optional<CrlData> GetSessionCrlSnapshot() const
    {
        const std::lock_guard<std::mutex> lock(m_ref_mutex);
        return m_session_crl;
    }

    // -----------------------------------------------------------------------
    // Ownership
    // -----------------------------------------------------------------------

    /// Return the identifier of the client that owns this entry.
    ///
    /// @return The owning client's identifier.
    /// @note Thread-safe. The underlying value is fixed at construction and
    ///       never modified afterward, so concurrent calls from any thread
    ///       require no external synchronization.
    [[nodiscard]] data_manager::ClientId GetOwner() const noexcept
    {
        return m_owner_client_id;
    }

    /// Check whether the given client owns this entry.
    ///
    /// @param client_id  Client identifier to compare against the owner.
    /// @return True when @p client_id matches the owning client.
    /// @note Thread-safe. The underlying value is fixed at construction and
    ///       never modified afterward, so concurrent calls from any thread
    ///       require no external synchronization.
    [[nodiscard]] bool IsOwnedBy(data_manager::ClientId client_id) const noexcept
    {
        return m_owner_client_id == client_id;
    }

  private:
    CertObject::Sptr m_object;
    CertSlotHandle m_slot_handle;
    data_manager::ClientId m_owner_client_id;

    mutable std::mutex m_ref_mutex;
    std::optional<CrlData> m_session_crl;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_ENTRY_HPP
