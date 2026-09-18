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

#include "score/crypto/src/api/objects/src/certificate_object_impl.hpp"
#include "score/crypto/src/api/common/error_domain.hpp"

#include <cstdint>
#include <string>
#include <utility>

namespace score
{

namespace crypto
{

CertificateObjectImpl::CertificateObjectImpl(CryptoResourceId id,
                                             std::string subject,
                                             std::string issuer,
                                             std::string serial_number,
                                             std::array<uint8_t, kSha256FingerprintSize> fingerprint,
                                             int64_t not_before,
                                             int64_t not_after,
                                             bool is_ca,
                                             std::optional<CrlMetadata> crl_metadata)
    : m_id(id),
      m_subject(std::move(subject)),
      m_issuer(std::move(issuer)),
      m_serial_number(std::move(serial_number)),
      m_fingerprint(fingerprint),
      m_not_before(not_before),
      m_not_after(not_after),
      m_is_ca(is_ca),
      m_crl_metadata(std::move(crl_metadata))
{
}

CryptoResourceId CertificateObjectImpl::GetId() const noexcept
{
    return m_id;
}

ResourceType CertificateObjectImpl::GetType() const noexcept
{
    return ResourceType::kCertificate;
}

std::string_view CertificateObjectImpl::GetSubject() const noexcept
{
    return m_subject;
}

std::string_view CertificateObjectImpl::GetIssuer() const noexcept
{
    return m_issuer;
}

int64_t CertificateObjectImpl::GetNotBefore() const noexcept
{
    return m_not_before;
}

int64_t CertificateObjectImpl::GetNotAfter() const noexcept
{
    return m_not_after;
}

AlgorithmId CertificateObjectImpl::GetPublicKeyAlgorithm() const noexcept
{
    // TODO: Store and return algorithm from CERT_GET_METADATA once CertChainMetadata includes it.
    return AlgorithmId{};
}

std::string CertificateObjectImpl::GetSerialNumber() const
{
    return m_serial_number;
}

std::array<uint8_t, kSha256FingerprintSize> CertificateObjectImpl::GetFingerprint() const noexcept
{
    return m_fingerprint;
}

std::optional<CrlMetadata> CertificateObjectImpl::GetCrlMetadata() const noexcept
{
    return m_crl_metadata;
}

score::Result<std::size_t> CertificateObjectImpl::GetPublicKeyExportSize() const noexcept
{
    // Public-key metadata is not available through the certificate view.
    return score::Result<std::size_t>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "Public key export is unavailable")};
}

score::Result<std::size_t> CertificateObjectImpl::ExportPublicKey(score::cpp::span<uint8_t> /*output*/) const
{
    // Public-key export is not available through the certificate view.
    return score::Result<std::size_t>{
        score::unexpect, MakeError(CryptoErrorCode::kUnsupportedOperation, "Public key export is unavailable")};
}

}  // namespace crypto

}  // namespace score
