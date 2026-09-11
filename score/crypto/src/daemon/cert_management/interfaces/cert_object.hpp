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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CERT_OBJECT_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CERT_OBJECT_HPP

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"

#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// Provider-neutral value type for a single parsed certificate.
///
/// A certificate is public, fully serializable data — unlike a private key, it
/// has no opaque provider-internal secret that must stay bound to the provider
/// that created it. `CertObject` therefore replaces the previous polymorphic
/// `ICertHandler`: it is a plain, immutable value holding the raw DER/PEM bytes,
/// their format, and the metadata extracted at parse time (`CertChainMetadata`).
///
/// Parsing remains a provider capability (`ICertParser`), but
/// its product is neutral: any provider — or none — can consume a CertObject,
/// which is what lets a certificate stored via one backend (e.g. PKCS#11) be
/// parsed/verified by the software provider. Operations that transform bytes
/// (format conversion, public-key extraction) live on the provider, not here.
///
/// Shared via CertObject::Sptr because the same certificate is commonly
/// referenced by the CertRegistry and one or more trust stores at once.
///
/// Thread safety: instances are immutable after construction and safe to read
/// concurrently through a shared_ptr.
class CertObject final
{
  public:
    using Sptr = std::shared_ptr<CertObject>;

    CertObject(CertChainMetadata metadata, std::vector<uint8_t> bytes, score::crypto::FormatType format)
        : m_metadata{std::move(metadata)}, m_bytes{std::move(bytes)}, m_format{format}
    {
    }

    ~CertObject() = default;

    CertObject(const CertObject&) = delete;
    CertObject& operator=(const CertObject&) = delete;
    CertObject(CertObject&&) = delete;
    CertObject& operator=(CertObject&&) = delete;

    // -----------------------------------------------------------------------
    // Metadata accessors (read from the cached CertChainMetadata)
    // -----------------------------------------------------------------------

    /// RFC 4514 canonical string representation of the Subject Distinguished Name.
    [[nodiscard]] std::string_view GetSubject() const noexcept
    {
        return m_metadata.subject_canonical;
    }

    /// RFC 4514 canonical string representation of the Issuer Distinguished Name.
    [[nodiscard]] std::string_view GetIssuer() const noexcept
    {
        return m_metadata.issuer_canonical;
    }

    /// Unix epoch seconds of the certificate's notBefore validity field.
    [[nodiscard]] int64_t GetNotBefore() const noexcept
    {
        return m_metadata.not_before_epoch_s;
    }

    /// Unix epoch seconds of the certificate's notAfter validity field.
    [[nodiscard]] int64_t GetNotAfter() const noexcept
    {
        return m_metadata.not_after_epoch_s;
    }

    /// Raw bytes of the Subject Key Identifier extension value (empty if absent).
    [[nodiscard]] score::crypto::span<const uint8_t> GetSkid() const noexcept
    {
        return {m_metadata.skid.data(), m_metadata.skid.size()};
    }

    /// Raw bytes of the Authority Key Identifier extension value (empty if absent).
    [[nodiscard]] score::crypto::span<const uint8_t> GetAkid() const noexcept
    {
        return {m_metadata.akid.data(), m_metadata.akid.size()};
    }

    /// True when the BasicConstraints extension marks this as a CA certificate.
    [[nodiscard]] bool IsCA() const noexcept
    {
        return m_metadata.is_ca;
    }

    /// SHA-256 fingerprint of the certificate's DER encoding (32 bytes).
    [[nodiscard]] score::crypto::span<const uint8_t> GetFingerprint() const noexcept
    {
        return {m_metadata.fingerprint.data(), m_metadata.fingerprint.size()};
    }

    /// The full precomputed chain metadata struct.
    [[nodiscard]] const CertChainMetadata& GetChainMetadata() const noexcept
    {
        return m_metadata;
    }

    // -----------------------------------------------------------------------
    // Raw bytes access — the neutral payload for re-parse / verification
    // -----------------------------------------------------------------------

    /// Raw certificate bytes as parsed. Pass to any ICertParser to re-parse,
    /// or to a cert context handler for verification — no per-provider binding required.
    [[nodiscard]] score::crypto::span<const uint8_t> GetRawBytes() const noexcept
    {
        return {m_bytes.data(), m_bytes.size()};
    }

    /// Format of the bytes returned by GetRawBytes() (kPem or kDer).
    [[nodiscard]] score::crypto::FormatType GetFormat() const noexcept
    {
        return m_format;
    }

  private:
    CertChainMetadata m_metadata;
    std::vector<uint8_t> m_bytes;
    score::crypto::FormatType m_format;
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_INTERFACES_CERT_OBJECT_HPP
