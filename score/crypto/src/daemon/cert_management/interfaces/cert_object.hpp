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

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"

#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace score::crypto::daemon::cert_management
{

/// Immutable, provider-neutral value holding one parsed certificate.
///
/// Contains the raw DER/PEM bytes, their format, and the metadata extracted at
/// parse time (`CertChainMetadata`). Parsing is performed by `ICertParser`; any
/// provider can consume a `CertObject`. Byte-transforming operations (format
/// conversion, public-key extraction) belong to the provider, not to this type.
///
/// Shared via `CertObject::Sptr` across the certificate registry and trust stores.
/// Thread safety: instances are immutable after construction and safe to read
/// concurrently through a shared_ptr.
class CertObject final
{
  public:
    using Sptr = std::shared_ptr<CertObject>;

    /// @param metadata Precomputed chain metadata for the certificate.
    /// @param bytes Raw certificate bytes in the format given by @p format.
    /// @param format Format of @p bytes (kPem or kDer).
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
    /// @return Canonical Subject DN string; valid while this object lives (copy to outlive the owner).
    [[nodiscard]] std::string_view GetSubject() const noexcept
    {
        return m_metadata.subject_canonical;
    }

    /// RFC 4514 canonical string representation of the Issuer Distinguished Name.
    /// @return Canonical Issuer DN string; valid while this object lives (copy to outlive the owner).
    [[nodiscard]] std::string_view GetIssuer() const noexcept
    {
        return m_metadata.issuer_canonical;
    }

    /// Unix epoch seconds of the certificate's notBefore validity field.
    /// @return notBefore time as Unix epoch seconds.
    [[nodiscard]] int64_t GetNotBefore() const noexcept
    {
        return m_metadata.not_before_epoch_s;
    }

    /// Unix epoch seconds of the certificate's notAfter validity field.
    /// @return notAfter time as Unix epoch seconds.
    [[nodiscard]] int64_t GetNotAfter() const noexcept
    {
        return m_metadata.not_after_epoch_s;
    }

    /// Raw bytes of the Subject Key Identifier extension value (empty if absent).
    /// @return View of the SKID bytes; empty if absent. Valid while this object lives.
    [[nodiscard]] score::crypto::span<const uint8_t> GetSkid() const noexcept
    {
        return {m_metadata.skid.data(), m_metadata.skid.size()};
    }

    /// Raw bytes of the Authority Key Identifier extension value (empty if absent).
    /// @return View of the AKID bytes; empty if absent. Valid while this object lives.
    [[nodiscard]] score::crypto::span<const uint8_t> GetAkid() const noexcept
    {
        return {m_metadata.akid.data(), m_metadata.akid.size()};
    }

    /// True when the BasicConstraints extension marks this as a CA certificate.
    /// @return true if BasicConstraints marks the certificate as a CA.
    [[nodiscard]] bool IsCA() const noexcept
    {
        return m_metadata.is_ca;
    }

    /// SHA-256 fingerprint of the certificate's DER encoding (32 bytes).
    /// @return View of the 32-byte SHA-256 DER fingerprint; valid while this object lives.
    [[nodiscard]] score::crypto::span<const uint8_t> GetFingerprint() const noexcept
    {
        return {m_metadata.fingerprint.data(), m_metadata.fingerprint.size()};
    }

    /// The full precomputed chain metadata struct.
    /// @return Reference to the chain metadata owned by this object.
    [[nodiscard]] const CertChainMetadata& GetChainMetadata() const noexcept
    {
        return m_metadata;
    }

    // -----------------------------------------------------------------------
    // Raw bytes access — the neutral payload for re-parse / verification
    // -----------------------------------------------------------------------

    /// Raw certificate bytes as parsed. Pass to any ICertParser to re-parse,
    /// or to a cert context handler for verification — no per-provider binding required.
    /// @return View of the raw certificate bytes; valid while this object lives.
    [[nodiscard]] score::crypto::span<const uint8_t> GetRawBytes() const noexcept
    {
        return {m_bytes.data(), m_bytes.size()};
    }

    /// Format of the bytes returned by GetRawBytes() (kPem or kDer).
    /// @return Format of the bytes returned by GetRawBytes().
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
