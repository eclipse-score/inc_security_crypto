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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_I_CERTIFICATE_MANAGEMENT_CONTEXT_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_I_CERTIFICATE_MANAGEMENT_CONTEXT_HPP

#include "score/crypto/src/api/common/crypto_resource_guard.hpp"
#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/api/contexts/i_context.hpp"
#include "score/crypto/src/api/objects/i_certificate_object.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <variant>
#include <vector>

namespace score
{

namespace crypto
{

/// @brief Interface for certificate lifecycle management operations.
///
/// - **Parse** raw bytes into a daemon-backed ICertificateObject with an
///   ephemeral resource ID.
/// - **SaveCertificate** copies an ephemeral certificate to a persistent slot
///   (copy semantics — the ephemeral cert remains valid until the
///   ICertificateObject goes out of scope).
/// - **Export / convert** using a two-call pattern: query the required buffer
///   size first, then fill the caller-supplied span.
/// - **Slot management** and **trust store management** are co-located here.
///
/// **ParseCertificate lifecycle**:
/// @code
///   auto cert = cert_mgmt->ParseCertificate(der_bytes, FormatType::kDer).value();
///   // cert->GetId() is valid — daemon assigned an ephemeral kCertificate ID.
///   // Inspect before committing:
///   if (cert->GetNotAfter() < current_time) { return Error; }
///   cert_mgmt->SaveCertificate(cert->GetId(), target_slot).value();
///   // cert goes out of scope → destructor → daemon releases ephemeral copy.
/// @endcode
class ICertificateManagementContext : public IContext
{
  public:
    using Uptr = std::unique_ptr<ICertificateManagementContext>;

    ~ICertificateManagementContext() override = default;

    ICertificateManagementContext(const ICertificateManagementContext&) = delete;
    ICertificateManagementContext& operator=(const ICertificateManagementContext&) = delete;
    ICertificateManagementContext(ICertificateManagementContext&&) = default;
    ICertificateManagementContext& operator=(ICertificateManagementContext&&) = default;

    // ---- Parsing ----

    /// @brief Parses a single X.509 certificate from encoded data.
    ///
    /// Sends the raw bytes to the daemon, which validates the certificate
    /// structure and assigns an ephemeral kCertificate resource ID.
    /// The returned ICertificateObject::GetId() is immediately valid.
    ///
    /// @param cert_data DER or PEM encoded certificate bytes
    /// @param format Encoding format of the input data
    /// @return ICertificateObject with a daemon-assigned ephemeral ID.
    ///         Destroying the object releases the ephemeral ID.
    virtual score::Result<ICertificateObject::Uptr> ParseCertificate(score::cpp::span<const uint8_t> cert_data,
                                                                     FormatType format) = 0;

    /// @brief Parses multiple certificates from a PEM bundle or DER chain.
    ///
    /// @param cert_data PEM bundle or concatenated certificate data
    /// @param format Encoding format of the data
    /// @return Ordered vector of ICertificateObject (first = leaf/first in bundle).
    ///         Each object has a daemon-assigned ephemeral ID.
    virtual score::Result<std::vector<ICertificateObject::Uptr>> ParseCertificates(
        score::cpp::span<const uint8_t> cert_data,
        FormatType format) = 0;

    // ---- Persistence ----

    /// @brief Copies an ephemeral certificate to a persistent certificate slot.
    ///
    /// Copy semantics: the ephemeral certificate (and its ICertificateObject)
    /// remains valid after this call. The object releases the ephemeral copy
    /// independently when it is destroyed.
    ///
    /// Typical usage: parse → inspect fields → save to slot.
    ///
    /// @param cert        CryptoResourceId of the certificate to save (type = kCertificate or kCertSlot)
    /// @param target_slot Handle to the target slot (type = kCertSlot)
    /// @return std::monostate on success, error if slot is occupied or access is denied
    virtual score::Result<std::monostate> SaveCertificate(const CryptoResourceId& cert,
                                                          const CryptoResourceId& target_slot) = 0;

    // ---- Export ----

    /// @brief Returns the encoded size of a certificate in the requested format.
    ///
    /// Call this before ExportCertificate() to allocate a correctly-sized buffer.
    ///
    /// @param cert Handle to the certificate (type = kCertificate)
    /// @param format Desired output encoding (DER or PEM)
    /// @return Required buffer size in bytes, or error on failure
    virtual score::Result<std::size_t> GetCertificateExportSize(const CryptoResourceId& cert, FormatType format) = 0;

    /// @brief Exports a certificate in the requested encoding format.
    ///
    /// Call GetCertificateExportSize() first to determine the buffer size.
    ///
    /// @param cert Handle to the certificate (type = kCertificate or kCertSlot)
    /// @param format Desired output encoding (DER or PEM)
    /// @param output Caller-supplied buffer; must be at least GetCertificateExportSize() bytes
    /// @return Number of bytes written, or error if handle is invalid or buffer too small
    virtual score::Result<std::size_t> ExportCertificate(const CryptoResourceId& cert,
                                                         FormatType format,
                                                         score::cpp::span<uint8_t> output) = 0;

    // ---- Format conversion ----

    /// @brief Returns the size of the certificate data after format conversion.
    ///
    /// Call this before ConvertCertificateFormat() to allocate a correctly-sized buffer.
    ///
    /// @param input Certificate data in the source format
    /// @param input_format Format of the input data
    /// @param output_format Desired output format
    /// @return Required buffer size in bytes
    virtual score::Result<std::size_t> GetConvertedCertificateSize(score::cpp::span<const uint8_t> input,
                                                                   FormatType input_format,
                                                                   FormatType output_format) = 0;

    /// @brief Converts certificate data between DER and PEM formats.
    ///
    /// Call GetConvertedCertificateSize() first to allocate the output buffer.
    ///
    /// @param input Certificate data in the source format
    /// @param input_format Format of the input data
    /// @param output_format Desired output format
    /// @param output Caller-supplied buffer; must be at least GetConvertedCertificateSize() bytes
    /// @return Number of bytes written
    virtual score::Result<std::size_t> ConvertCertificateFormat(score::cpp::span<const uint8_t> input,
                                                                FormatType input_format,
                                                                FormatType output_format,
                                                                score::cpp::span<uint8_t> output) = 0;

    // ---- Slot management ----

    /// @brief Clears a persistent certificate slot, erasing its contents.
    /// @param slot Handle to the slot to clear (type = kCertSlot)
    /// @return std::monostate on success, error if the slot is not found or access is denied
    virtual score::Result<std::monostate> ClearCertificate(const CryptoResourceId& slot) = 0;

    /// @brief Queries the occupancy and metadata of a certificate slot.
    /// @param slot Handle to the slot (type = kCertSlot)
    /// @return CertificateSlotInfo with certificate-slot state and CRL presence
    virtual score::Result<CertificateSlotInfo> GetCertificateSlotInfo(const CryptoResourceId& slot) = 0;

    // ---- Key extraction ----

    /// @brief Extracts the public key from a certificate as an ephemeral key resource.
    ///
    /// The returned CryptoResourceGuard owns an ephemeral kKey resource. It can
    /// be passed directly to any API accepting `const CryptoResourceId&` via
    /// implicit conversion. The daemon releases the key when the guard is destroyed.
    ///
    /// @param cert Handle to the certificate (type = kCertificate or kCertSlot)
    /// @return Pair of CryptoResourceGuard (ephemeral key) and its AlgorithmId
    ///         (e.g., "RSA-2048", "ECDSA-P256", "ML-DSA-65")
    virtual score::Result<std::pair<CryptoResourceGuard, AlgorithmId>> LoadCertificatePublicKey(
        const CryptoResourceId& cert) = 0;

    /// @brief Bulk-deletes expired certificates from persistent slots.
    /// @return Number of certificates deleted
    virtual score::Result<std::size_t> DeleteExpiredCertificates() = 0;

    // ---- Persistence — with optional CRL propagation ----

    /// @brief Copies an ephemeral certificate to a persistent slot, optionally propagating its CRL.
    ///
    /// When @p with_crl is true the daemon propagates the CRL already held for @p cert:
    /// - If a session-scoped CRL was previously associated via ImportCrl() (persist=false),
    ///   that CRL is used (works for both kCertificate and kCertSlot sources).
    /// - Otherwise the CRL is read from @p cert's slot's persistent [crl] section
    ///   (only applicable when cert is a kCertSlot source).
    ///
    /// No CRL re-validation occurs — the daemon reuses the CRL it already accepted.
    ///
    /// @param cert        CryptoResourceId of the certificate to save (type = kCertificate or kCertSlot)
    /// @param target_slot Handle to the target slot (type = kCertSlot)
    /// @param with_crl    When true, propagate the associated CRL to the destination slot
    virtual score::Result<std::monostate> SaveCertificate(const CryptoResourceId& cert,
                                                          const CryptoResourceId& target_slot,
                                                          bool with_crl) = 0;

    // ---- CRL management ----

    /// @brief Imports a Certificate Revocation List and associates it with its issuer certificate.
    ///
    /// The CRL lifecycle follows the lifecycle of @p issuer_cert:
    /// - kCertSlot + persist=true: CRL written to the slot's [crl] section; write access required.
    /// - kCertSlot or kCertificate + persist=false: session-scoped in-memory; no write access needed.
    ///   Session CRL is consumed by SaveCertificate(with_crl=true) and
    ///   AddCertificateToTrustStore(with_crl=true) without re-passing raw bytes.
    ///
    /// @param crl_data    Encoded CRL data
    /// @param format      Encoding format of the CRL
    /// @param issuer_cert Handle to the issuer certificate (type = kCertSlot or kCertificate)
    /// @param persist     When true, store permanently to the issuer slot (kCertSlot only)
    /// @return std::monostate on success, error if validation fails or access is denied
    virtual score::Result<std::monostate> ImportCrl(score::cpp::span<const uint8_t> crl_data,
                                                    FormatType format,
                                                    const CryptoResourceId& issuer_cert,
                                                    bool persist = false) = 0;

    /// @brief Removes the CRL stored in a certificate slot.
    /// @param cert_slot Handle to the slot whose CRL should be removed (type = kCertSlot)
    /// @return std::monostate on success, error if no CRL is present or access is denied
    virtual score::Result<std::monostate> DeleteCrl(const CryptoResourceId& cert_slot) = 0;

    // ---- OCSP (reserved for future support) ----
    // /// @brief Constructs an OCSP request for a certificate's revocation status.
    // ///
    // /// @param cert Handle to the certificate to check (type = kCertificate or kCertSlot)
    // /// @param issuer_cert Handle to the issuer certificate
    // /// @return Export object providing the DER-encoded request and responder URL
    // virtual score::Result<IOcspRequestExport::Uptr> GetOcspRequestData(
    //     const CryptoResourceId& cert,
    //     const CryptoResourceId& issuer_cert) = 0;

    // ---- Trust-store membership management ----

    /// @brief Adds a certificate to a persistent trust store.
    ///
    /// The certificate is assigned to a trust-store-managed exclusive slot. This is a
    /// write operation and requires trust-store write access. Idempotent: if the cert
    /// is already a member of any type, returns success without allocating a new slot.
    ///
    /// @param trust_store Handle to the trust store (type = kCertificateTrustStore)
    /// @param cert        Handle to the certificate to add (type = kCertificate or kCertSlot)
    /// @param with_crl    When true, propagate the associated CRL to the exclusive slot
    virtual score::Result<std::monostate> AddCertificateToTrustStore(const CryptoResourceId& trust_store,
                                                                     const CryptoResourceId& cert,
                                                                     bool with_crl = false) = 0;

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

    /// @brief Enables a previously disabled trust store member identified by its slot resource.
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

    /// @brief Imports a CRL for a trust store exclusive member identified by its slot resource.
    ///
    /// Only kExclusiveMutable trust store slots are writable through this path.
    /// For shared-static or conditional-external members, use ImportCrl directly on the slot.
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

  protected:
    ICertificateManagementContext() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_I_CERTIFICATE_MANAGEMENT_CONTEXT_HPP
