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

#ifndef SCORE_MW_CRYPTO_API_FUTURE_CONTEXTS_I_CERTIFICATE_MANAGEMENT_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_FUTURE_CONTEXTS_I_CERTIFICATE_MANAGEMENT_CONTEXT_HPP

#include "score/mw/crypto/api/certificate/i_ocsp_request_export.hpp"
#include "score/mw/crypto/api/common/crypto_resource_guard.hpp"
#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/contexts/i_context.hpp"
#include "score/mw/crypto/api/future/objects/i_certificate_object.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Interface for certificate lifecycle management operations.
///
/// Mirrors the structure of IKeyManagementContext for certificates:
/// - **Parse** raw bytes into a daemon-backed ICertificateObject with an
///   ephemeral resource ID.
/// - **SaveCertificate** copies an ephemeral certificate to a persistent slot
///   (copy semantics — the ephemeral cert remains valid until the
///   ICertificateObject goes out of scope).
/// - **Export / convert** using a two-call pattern: query the required buffer
///   size first, then fill the caller-supplied span.
/// - **Slot management**, **CRL management**, and **trust store management**
///   are all co-located here.
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
    /// @param cert CryptoResourceId of the certificate to save (type = kCertificate).
    ///        Pass the result of ICertificateObject::GetId() directly.
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
    /// @return CertificateSlotInfo with occupancy, algorithm, and provider binding
    virtual score::Result<CertificateSlotInfo> GetCertificateSlotInfo(const CryptoResourceId& slot) = 0;

    // ---- CRL management ----

    /// @brief Imports a Certificate Revocation List and associates it with its issuer.
    ///
    /// The returned CryptoResourceId uses ResourceType::kCrl and carries the
    /// same numeric id as the resolved issuer certificate — callers can look up
    /// the applicable CRL for any issuer by re-resolving with ResourceType::kCrl.
    ///
    /// @param crl_data Encoded CRL data
    /// @param format Encoding format of the CRL
    /// @param issuer_cert Handle to the issuer certificate
    ///        (type = kCertificate or kCertSlot). The daemon validates that the
    ///        CRL issuer DN matches and that the CRL signature is correct.
    /// @param persist When true, the CRL survives the guard's destructor
    ///        (kPersistent — daemon retains the CRL when the client releases its
    ///        reference). When false, the CRL is deleted when the guard is destroyed.
    /// @return Guard wrapping a handle with type = kCrl. Pass guard.GetId() to
    ///         SetCrl() or re-resolve via ResourceType::kCrl on the issuer id.
    virtual score::Result<CryptoResourceGuard> ImportCrl(score::cpp::span<const uint8_t> crl_data,
                                                         FormatType format,
                                                         const CryptoResourceId& issuer_cert,
                                                         bool persist) = 0;

    /// @brief Removes a specific CRL from the store.
    /// @param crl Handle to the CRL to delete (type = kCrl)
    /// @return std::monostate on success, error if the CRL is not found
    virtual score::Result<std::monostate> DeleteCrl(const CryptoResourceId& crl) = 0;

    /// @brief Bulk-deletes expired CRLs from the store.
    /// @return Number of CRLs deleted
    virtual score::Result<std::size_t> DeleteExpiredCrls() = 0;

    /// @brief Bulk-deletes expired certificates from persistent slots.
    /// @return Number of certificates deleted
    virtual score::Result<std::size_t> DeleteExpiredCertificates() = 0;

    // ---- Key extraction and OCSP ----

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

    /// @brief Constructs an OCSP request for a certificate's revocation status.
    ///
    /// The returned object exposes the DER-encoded OCSP request and the responder URL.
    /// Send the request to the URL via HTTP POST, then feed the response to
    /// ICertificateVerificationContext::SetOcspResponse().
    ///
    /// @param cert Handle to the certificate to check (type = kCertificate or kCertSlot)
    /// @param issuer_cert Handle to the issuer certificate (required for OCSP request construction)
    /// @return Export object providing the encoded request and responder URL
    virtual score::Result<IOcspRequestExport::Uptr> GetOcspRequestData(const CryptoResourceId& cert,
                                                                       const CryptoResourceId& issuer_cert) = 0;

  protected:
    ICertificateManagementContext() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_FUTURE_CONTEXTS_I_CERTIFICATE_MANAGEMENT_CONTEXT_HPP
