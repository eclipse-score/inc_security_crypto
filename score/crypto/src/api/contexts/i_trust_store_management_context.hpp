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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_I_TRUST_STORE_MANAGEMENT_CONTEXT_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_I_TRUST_STORE_MANAGEMENT_CONTEXT_HPP

#include "score/crypto/src/api/contexts/i_context.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstdint>
#include <memory>
#include <variant>

namespace score
{

namespace crypto
{

/// @brief Interface for trust-store membership curation.
///
/// A trust store remains a collection of certificate slots owned by
/// `ICertificateManagementContext`; this context owns only the membership
/// and enablement policy on top of it — a distinct client-facing capability
/// under the same certificate-management provider scope (`CERT:TRUST_STORE`).
///
/// Certificate lifecycle operations (parse, save, export, slot CRL import)
/// remain on `ICertificateManagementContext`. Read-only trust-store
/// inspection remains on `ITrustStoreObject`, obtained via
/// `ICryptoContext::GetTrustStoreObject()`.
class ITrustStoreManagementContext : public IContext
{
  public:
    using Uptr = std::unique_ptr<ITrustStoreManagementContext>;

    ~ITrustStoreManagementContext() override = default;

    ITrustStoreManagementContext(const ITrustStoreManagementContext&) = delete;
    ITrustStoreManagementContext& operator=(const ITrustStoreManagementContext&) = delete;
    ITrustStoreManagementContext(ITrustStoreManagementContext&&) = default;
    ITrustStoreManagementContext& operator=(ITrustStoreManagementContext&&) = default;

    /// @brief Adds a certificate to a persistent trust store.
    ///
    /// The certificate is assigned to a trust-store-managed exclusive slot. This is a
    /// write operation and requires trust-store write access. Idempotent: if the cert
    /// is already a member of any type, returns success without allocating a new slot.
    ///
    /// @param trust_store Handle to the trust store (type = kCertificateTrustStore)
    /// @param cert        Handle to the certificate to add (type = kCertificate or kCertSlot)
    /// @return std::monostate on success, error if the trust store cannot be updated
    virtual score::Result<std::monostate> AddCertificateToTrustStore(const CryptoResourceId& trust_store,
                                                                     const CryptoResourceId& cert) = 0;

    /// @brief Adds a certificate and propagates its associated CRL.
    /// @param trust_store Handle to the trust store (type = kCertificateTrustStore)
    /// @param cert        Handle to the certificate to add (type = kCertificate or kCertSlot)
    /// The CRL is resolved daemon-side from the certificate resource's
    ///                    session-scoped CRL association (see
    ///                    `ICertificateManagementContext::ImportCrl`) or, failing that,
    ///                    from the source slot's persistent CRL — no raw bytes are passed here.
    virtual score::Result<std::monostate> AddCertificateToTrustStoreWithCrl(const CryptoResourceId& trust_store,
                                                                            const CryptoResourceId& cert) = 0;

    /// @brief Removes a certificate from a persistent trust store by cert handle.
    ///
    /// The certificate must be loaded in the daemon (ephemeral or slot-loaded).
    /// The daemon resolves the SHA-256 fingerprint internally from the handle.
    ///
    /// @param trust_store Handle to the trust store (type = kCertificateTrustStore)
    /// @param cert        Handle to the certificate to remove (type = kCertificate or kCertSlot)
    virtual score::Result<std::monostate> RemoveCertificateFromTrustStore(const CryptoResourceId& trust_store,
                                                                          const CryptoResourceId& cert) = 0;

    /// @brief Removes a certificate from a persistent trust store by SHA-256 fingerprint.
    ///
    /// The certificate does not need to be loaded in the daemon. Use this when
    /// the fingerprint is known from an external source without the cert bytes being available.
    ///
    /// @param trust_store        Handle to the trust store (type = kCertificateTrustStore)
    /// @param sha256_fingerprint 32-byte SHA-256 fingerprint of the certificate to remove
    virtual score::Result<std::monostate> RemoveCertificateFromTrustStore(
        const CryptoResourceId& trust_store,
        score::cpp::span<const uint8_t> sha256_fingerprint) = 0;

    /// @brief Enables a disabled trust store member identified by its slot resource.
    ///
    /// Use the slot_id from ITrustStoreObject::MemberInfo to obtain the slot handle.
    ///
    /// @param trust_store Handle to the trust store (type = kCertificateTrustStore)
    /// @param slot        Handle to the member slot (type = kCertSlot)
    virtual score::Result<std::monostate> EnableTrustStoreMember(const CryptoResourceId& trust_store,
                                                                 const CryptoResourceId& slot) = 0;

    /// @brief Disables a trust store member identified by its slot resource.
    ///
    /// A disabled member is excluded from anchor resolution; it remains in the store
    /// and can be re-enabled. Use RemoveCertificateFromTrustStore to permanently remove.
    ///
    /// Use the slot_id from ITrustStoreObject::MemberInfo to obtain the slot handle.
    ///
    /// @param trust_store Handle to the trust store (type = kCertificateTrustStore)
    /// @param slot        Handle to the member slot (type = kCertSlot)
    virtual score::Result<std::monostate> DisableTrustStoreMember(const CryptoResourceId& trust_store,
                                                                  const CryptoResourceId& slot) = 0;

    /// @brief Acknowledges an unexpected content change on a conditional-external member.
    ///
    /// A kConditionalExternal member is automatically disabled when its slot content
    /// changes without acknowledgement (see ITrustStoreObject::MemberInfo state). This
    /// re-baselines the accepted fingerprint to the slot's current content and
    /// re-enables the member. Not equivalent to EnableTrustStoreMember: enabling alone
    /// does not update the accepted fingerprint, so the member would be disabled again
    /// on the next anchor reload if the content is still unacknowledged.
    ///
    /// Use the slot_id from ITrustStoreObject::MemberInfo to obtain the slot handle.
    ///
    /// @param trust_store Handle to the trust store (type = kCertificateTrustStore)
    /// @param slot        Handle to the conditional-external member slot (type = kCertSlot)
    virtual score::Result<std::monostate> AcknowledgeTrustStoreMemberUpdate(const CryptoResourceId& trust_store,
                                                                            const CryptoResourceId& slot) = 0;

    /// @brief Imports a CRL for a trust store exclusive member identified by its slot resource.
    ///
    /// Only kExclusiveMutable trust store slots are writable through this path.
    /// For shared-static or conditional-external members, use
    /// `ICertificateManagementContext::ImportCrlToSlot` directly on the slot.
    ///
    /// Use the slot_id from ITrustStoreObject::MemberInfo to obtain the slot handle.
    ///
    /// @param trust_store Handle to the trust store (type = kCertificateTrustStore)
    /// @param slot        Handle to the exclusive member slot (type = kCertSlot)
    /// @param crl_data    Encoded CRL bytes
    /// @param format      Encoding format of the CRL
    virtual score::Result<std::monostate> ImportCrlForTrustStoreMember(const CryptoResourceId& trust_store,
                                                                       const CryptoResourceId& slot,
                                                                       score::cpp::span<const uint8_t> crl_data,
                                                                       FormatType format) = 0;

    /// @brief Deletes the CRL from a trust-store-owned exclusive member.
    ///
    /// Only kExclusiveMutable members are writable through this path. The
    /// trust store's write permission is required.
    ///
    /// @param trust_store Handle to the trust store (type = kCertificateTrustStore)
    /// @param slot        Handle to the exclusive member slot (type = kCertSlot)
    virtual score::Result<std::monostate> DeleteCrlForTrustStoreMember(const CryptoResourceId& trust_store,
                                                                       const CryptoResourceId& slot) = 0;

  protected:
    ITrustStoreManagementContext() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_I_TRUST_STORE_MANAGEMENT_CONTEXT_HPP
