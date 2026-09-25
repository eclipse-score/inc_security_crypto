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
#include "score/crypto/src/api/contexts/i_context.hpp"
#include "score/crypto/src/api/objects/i_certificate_object.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"
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
/// - **Parse** raw bytes into a guarded ephemeral certificate resource.
/// - **SaveCertificate** copies an ephemeral certificate to a persistent slot.
/// - **Export / convert** using a two-call pattern: query the required buffer
///   size first, then fill the caller-supplied span.
/// - **Certificate-slot and slot-CRL lifecycle** including loading, saving,
///   clearing, and persistent CRL import.
///
/// **ParseCertificate lifecycle**:
/// @code
///   auto cert = cert_mgmt->ParseCertificate(der_bytes, FormatType::kDer).value();
///   auto view = crypto_context->GetCertificateObject(cert).value();
///   // Inspect the certificate while cert owns the daemon resource.
///   if (view->GetNotAfter() < current_time) { return Error; }
///   cert_mgmt->SaveCertificate(cert, target_slot).value();
///   // cert goes out of scope → guard releases the ephemeral certificate.
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
    /// The returned guard owns the ephemeral kCertificate resource.
    ///
    /// @param cert_data DER or PEM encoded certificate bytes
    /// @param format Encoding format of the input data
    /// @return CryptoResourceGuard owning the daemon-assigned ephemeral resource.
    virtual score::Result<CryptoResourceGuard> ParseCertificate(score::cpp::span<const uint8_t> cert_data,
                                                                FormatType format) = 0;

    /// @brief Parses a sequence of X.509 certificates from PEM or DER data.
    ///
    /// For FormatType::kPem, cert_data contains consecutive PEM-encoded
    /// certificate blocks. For FormatType::kDer, cert_data contains
    /// consecutive complete DER-encoded X.509 objects. Protocol-specific
    /// framing or certificate-container formats are not part of this input.
    /// This operation parses the objects and does not validate their chain
    /// relationships or trust.
    ///
    /// @param cert_data PEM bundle or concatenated DER certificate data
    /// @param format Encoding format of the data
    /// @return Ordered vector of guards (first = first certificate in the data).
    ///         Each guard owns one daemon-assigned ephemeral resource.
    virtual score::Result<std::vector<CryptoResourceGuard>> ParseCertificates(score::cpp::span<const uint8_t> cert_data,
                                                                              FormatType format) = 0;

    // ---- Persistence ----

    /// @brief Copies an ephemeral certificate to a persistent certificate slot.
    ///
    /// Copy semantics: the source guard continues to own the ephemeral
    /// certificate after this call.
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

    /// @brief Loads a certificate from a persistent slot into an ephemeral resource.
    /// The returned guard may be reused with multiple certificate contexts.
    virtual score::Result<CryptoResourceGuard> LoadCertificate(const CryptoResourceId& slot) = 0;

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

    // ---- Persistence with CRL propagation ----

    /// @brief Copies a certificate to a persistent slot and propagates its CRL.
    ///
    /// The daemon propagates the CRL already held for @p cert:
    /// - If a session-scoped CRL is associated via ImportCrl() with a
    ///   kCertificate source, that CRL is used.
    /// - Otherwise the CRL is read from @p cert's slot's persistent [crl] section
    ///   (only applicable when cert is a kCertSlot source).
    ///
    /// No CRL re-validation occurs — the daemon reuses the CRL it already accepted.
    ///
    /// @param cert        CryptoResourceId of the certificate to save (type = kCertificate or kCertSlot)
    /// @param target_slot Handle to the target slot (type = kCertSlot)
    virtual score::Result<std::monostate> SaveCertificateWithCrl(const CryptoResourceId& cert,
                                                                 const CryptoResourceId& target_slot) = 0;

    // ---- CRL management ----

    /// @brief Imports a session-scoped CRL for a `kCertificate` resource.
    ///
    /// The association follows the lifetime of @p issuer_cert. No slot write
    /// access is required. The session CRL is consumed by
    /// SaveCertificateWithCrl and AddCertificateToTrustStoreWithCrl
    /// without re-passing raw bytes.
    ///
    /// @param crl_data    Encoded CRL data
    /// @param format      Encoding format of the CRL
    /// @param issuer_cert Handle to a `kCertificate` resource. Obtain one by
    ///                    parsing a certificate or loading it from a slot.
    /// @return std::monostate on success, error if validation fails or access is denied
    virtual score::Result<std::monostate> ImportCrl(score::cpp::span<const uint8_t> crl_data,
                                                    FormatType format,
                                                    const CryptoResourceId& issuer_cert) = 0;

    /// @brief Imports a CRL to a persistent certificate slot.
    /// @param crl_data    Encoded CRL data
    /// @param format      Encoding format of the CRL
    /// @param cert_slot   Handle to the certificate slot (type = kCertSlot)
    /// @return std::monostate on success, error if validation fails or access is denied
    virtual score::Result<std::monostate> ImportCrlToSlot(score::cpp::span<const uint8_t> crl_data,
                                                          FormatType format,
                                                          const CryptoResourceId& cert_slot) = 0;

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

  protected:
    ICertificateManagementContext() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_I_CERTIFICATE_MANAGEMENT_CONTEXT_HPP
