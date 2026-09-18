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

#ifndef SCORE_CRYPTO_SRC_API_OBJECTS_SRC_CERTIFICATE_OBJECT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_OBJECTS_SRC_CERTIFICATE_OBJECT_IMPL_HPP

#include "score/crypto/src/api/objects/i_certificate_object.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"

#include "score/result/result.h"
#include "score/span.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace score
{

namespace crypto
{

/// @brief Concrete non-owning ICertificateObject backed by daemon-cached metadata.
///
/// The resource owner is a CryptoResourceGuard. This object only provides a
/// typed inspection view and never releases the underlying resource.
class CertificateObjectImpl final : public ICertificateObject
{
  public:
    /// @brief Construct a read-only view for an existing resource.
    CertificateObjectImpl(CryptoResourceId id,
                          std::string subject,
                          std::string issuer,
                          std::string serial_number,
                          std::array<uint8_t, kSha256FingerprintSize> fingerprint,
                          int64_t not_before,
                          int64_t not_after,
                          bool is_ca,
                          std::optional<CrlMetadata> crl_metadata);

    ~CertificateObjectImpl() override = default;

    CertificateObjectImpl(const CertificateObjectImpl&) = delete;
    CertificateObjectImpl& operator=(const CertificateObjectImpl&) = delete;
    CertificateObjectImpl(CertificateObjectImpl&&) = delete;
    CertificateObjectImpl& operator=(CertificateObjectImpl&&) = delete;

    // ICryptoObject
    CryptoResourceId GetId() const noexcept override;
    ResourceType GetType() const noexcept override;

    // ICertificateObject
    std::string_view GetSubject() const noexcept override;
    std::string_view GetIssuer() const noexcept override;
    int64_t GetNotBefore() const noexcept override;
    int64_t GetNotAfter() const noexcept override;
    AlgorithmId GetPublicKeyAlgorithm() const noexcept override;
    std::string GetSerialNumber() const override;
    std::array<uint8_t, kSha256FingerprintSize> GetFingerprint() const noexcept override;
    std::optional<CrlMetadata> GetCrlMetadata() const noexcept override;
    score::Result<std::size_t> GetPublicKeyExportSize() const noexcept override;
    score::Result<std::size_t> ExportPublicKey(score::cpp::span<uint8_t> output) const override;

  private:
    CryptoResourceId m_id;
    std::string m_subject;
    std::string m_issuer;
    std::string m_serial_number;
    std::array<uint8_t, kSha256FingerprintSize> m_fingerprint{};
    int64_t m_not_before;
    int64_t m_not_after;
    bool m_is_ca;
    std::optional<CrlMetadata> m_crl_metadata;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_OBJECTS_SRC_CERTIFICATE_OBJECT_IMPL_HPP
