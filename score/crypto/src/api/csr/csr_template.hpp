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

#ifndef SCORE_CRYPTO_SRC_API_CSR_CSR_TEMPLATE_HPP
#define SCORE_CRYPTO_SRC_API_CSR_CSR_TEMPLATE_HPP

#include "score/crypto/src/api/certificate/i_csr_export.hpp"
#include "score/crypto/src/api/config/csr_generation_context_config.hpp"
#include "score/crypto/src/api/csr/csr_request.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace score::crypto
{
class ICryptoContext;
/// Provider-neutral enrollment input. No persisted handles or private key data.
/// Values in subject/issuer may contain ${name} placeholders. Extension config
/// is static: use typed helpers for dynamic SANs, never interpolate config text.
struct CsrTemplate
{
    std::string id;
    ResourceId key_resource;
    AlgorithmId algorithm;
    CsrSubject subject;
    CsrSubject issuer;  ///< Enrollment metadata only; never placed in PKCS#10.
    std::vector<CsrExtension> extensions;
    std::string submission_url;
};

struct CsrAttributeRequirements
{
    std::vector<std::string> subject_oids;
    std::vector<std::string> issuer_oids;
};

using CsrRuntimeValues = std::map<std::string, std::string>;

struct PreparedCsrTemplate
{
    std::string id;
    ResourceId key_resource;
    AlgorithmId algorithm;
    CsrRequest request;
    CsrSubject issuer;
    std::string submission_url;
};

struct CsrTemplateOutput
{
    std::string id;
    CsrSubject issuer;
    ICsrExport::Uptr csr;
};

/// Application maps a stable ResourceId to an authorized live key/slot handle.
/// The application retains any key guard for the complete synchronous Generate call.
/// This library never loads, exports, deletes, or takes ownership of a private key.
class ICsrKeyResolver
{
  public:
    virtual ~ICsrKeyResolver() = default;
    virtual score::Result<CryptoResourceId> ResolveSigningKey(const ResourceId& resource) = 0;
};

/// Persistence seam; storage/path/access policy belongs to the application.
class ICsrTemplateStorage
{
  public:
    virtual ~ICsrTemplateStorage() = default;
    virtual score::Result<CsrTemplate> Load(std::string_view id) const = 0;
};

/// Bounded, versioned ASN.1 DER storage using the shared template codec.
/// Each document contains one template, retaining ordered subject/issuer
/// placeholders and static extension configuration. No public keys or live
/// key handles are persisted. File IO, atomic persistence and access control
/// remain application responsibilities.
class DerCsrTemplateStorage final : public ICsrTemplateStorage
{
  public:
    DerCsrTemplateStorage(ICsrProcessingService& processing, std::vector<std::uint8_t> document)
        : processing_{processing}, document_{std::move(document)}
    {
    }
    score::Result<CsrTemplate> Load(std::string_view id) const override;
    static score::Result<std::vector<std::uint8_t>> Save(ICsrProcessingService& processing, const CsrTemplate& value);

  private:
    ICsrProcessingService& processing_;
    std::vector<std::uint8_t> document_;
};

class CsrTemplateProcessor
{
  public:
    static score::Result<PreparedCsrTemplate> Prepare(ICsrProcessingService& processing,
                                                      const CsrTemplate& value,
                                                      const CsrRuntimeValues& runtime,
                                                      const CsrAttributeRequirements& requirements);
    static score::Result<CsrTemplateOutput> Generate(ICsrProcessingService& processing,
                                                     const PreparedCsrTemplate& value,
                                                     ICryptoContext& crypto,
                                                     ICsrKeyResolver& keys);
    /// Ordered, best-effort batch with an independent Result per item. No automatic
    /// retry, deduplication, lifecycle transition or installation of certificates.
    static std::vector<score::Result<CsrTemplateOutput>> GenerateBatch(ICsrProcessingService& processing,
                                                                       const std::vector<PreparedCsrTemplate>& values,
                                                                       ICryptoContext& crypto,
                                                                       ICsrKeyResolver& keys);
};
}  // namespace score::crypto

#endif  // SCORE_CRYPTO_SRC_API_CSR_CSR_TEMPLATE_HPP
