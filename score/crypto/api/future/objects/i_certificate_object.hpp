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

#ifndef SCORE_MW_CRYPTO_API_OBJECTS_I_CERTIFICATE_OBJECT_HPP
#define SCORE_MW_CRYPTO_API_OBJECTS_I_CERTIFICATE_OBJECT_HPP

#include "score/mw/crypto/api/objects/i_crypto_object.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Typed view of a certificate resource.
///
/// The single certificate abstraction used for both ephemeral (parsed from bytes)
/// and persistent (loaded from a slot) certificates. All instances are
/// daemon-backed and carry a valid `GetId()` from the moment they are obtained.
///
/// **Lifecycle**: destroying this object releases the daemon-side resource.
/// For ephemeral certificates created by ParseCertificate(), the daemon frees
/// the resource when the last ICertificateObject referring to it is destroyed.
/// For persistent certificates loaded from a slot, the slot and its content
/// are unaffected — only the in-memory view object is released.
///
/// **Persistence**: use ICertificateManagementContext::SaveCertificate() to
/// copy an ephemeral certificate to a persistent slot. The ephemeral copy
/// remains valid and is released independently when this object is destroyed.
///
/// Provides field access, serial number, public key metadata, and public key
/// export. Certificates with PQC keys (ML-DSA, SLH-DSA, XMSS, LMS) may
/// produce larger export payloads — call GetPublicKeyExportSize() first.
class ICertificateObject : public ICryptoObject
{
  public:
    using Uptr = std::unique_ptr<ICertificateObject>;

    ~ICertificateObject() override = default;

    ICertificateObject(const ICertificateObject&) = delete;
    ICertificateObject& operator=(const ICertificateObject&) = delete;
    ICertificateObject(ICertificateObject&&) = default;
    ICertificateObject& operator=(ICertificateObject&&) = default;

    /// @brief Returns the certificate subject distinguished name.
    virtual std::string_view GetSubject() const noexcept = 0;

    /// @brief Returns the certificate issuer distinguished name.
    virtual std::string_view GetIssuer() const noexcept = 0;

    /// @brief Returns the notBefore validity timestamp (seconds since Unix epoch).
    virtual int64_t GetNotBefore() const noexcept = 0;

    /// @brief Returns the notAfter validity timestamp (seconds since Unix epoch).
    virtual int64_t GetNotAfter() const noexcept = 0;

    /// @brief Returns the public key algorithm identifier.
    /// @return Algorithm string (e.g., "RSA-2048", "ECDSA-P256", "ML-DSA-65")
    virtual AlgorithmId GetPublicKeyAlgorithm() const noexcept = 0;

    /// @brief Returns the certificate serial number as a hex-encoded string.
    virtual std::string GetSerialNumber() const = 0;

    /// @brief Returns the byte size of the DER-encoded SubjectPublicKeyInfo.
    ///
    /// Call this before ExportPublicKey() to determine the required buffer size.
    /// PQC algorithms (e.g., ML-DSA-65) may have public keys in the kilobyte
    /// range; always query rather than assuming a fixed upper bound.
    ///
    /// @return Required buffer size in bytes, or error on failure.
    virtual score::Result<std::size_t> GetPublicKeyExportSize() const noexcept = 0;

    /// @brief Exports the certificate's public key in DER (SubjectPublicKeyInfo) format.
    ///
    /// Call GetPublicKeyExportSize() first to allocate a correctly-sized buffer.
    ///
    /// @param output Buffer to receive the exported public key. Must be at least
    ///        GetPublicKeyExportSize() bytes.
    /// @return Number of bytes written, or error if the buffer is too small.
    virtual score::Result<std::size_t> ExportPublicKey(score::cpp::span<uint8_t> output) const = 0;

  protected:
    ICertificateObject() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_OBJECTS_I_CERTIFICATE_OBJECT_HPP
