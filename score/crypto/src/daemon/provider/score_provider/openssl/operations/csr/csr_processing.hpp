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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CSR_CSR_PROCESSING_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CSR_CSR_PROCESSING_HPP

#include "score/crypto/src/api/csr/csr_processing_client.hpp"

namespace score::crypto
{
/// Daemon-only implementation of the existing tested helper bodies. No
/// connection, resolver, key factory or signing access exists in this service.
class NativeCsrProcessing final : public ICsrProcessingService
{
  public:
    score::Result<csr::wire::Document> Process(const csr::wire::Document& input) override;
    static score::Result<CsrRequest> GenerationRequest(const csr::wire::Document& input);
    static score::Result<std::monostate> Add(CsrSubject& subject, CsrOid oid, std::string_view value);
    static score::Result<std::monostate> Add(CsrSubject& subject, std::string_view oid, std::string_view value);
    static score::Result<CsrSubject> FromDn(std::string_view dn);
    static score::Result<CsrExtension> SubjectAltNames(const std::vector<CsrSubjectAltName>& names, bool critical);
    static score::Result<CsrExtension> KeyUsage(const std::vector<CsrKeyUsage>& usages, bool critical);
    static score::Result<CsrExtension> ExtendedKeyUsage(const std::vector<std::string>& oids, bool critical);
    static score::Result<CsrExtension> BasicConstraints(bool ca, int path_length, bool critical);
    static score::Result<CsrExtension> CustomDer(std::string_view oid,
                                                 score::cpp::span<const uint8_t> der,
                                                 bool critical);
    static score::Result<std::monostate> Validate(const CsrRequest& request);
    static score::Result<std::vector<uint8_t>> ToDer(const CsrRequest& request,
                                                     score::cpp::span<const uint8_t> public_key_info = {});
    static score::Result<CsrTemplate> Load(score::cpp::span<const uint8_t> document, std::string_view id);
    static score::Result<std::vector<uint8_t>> Save(const CsrTemplate& value);
    static score::Result<PreparedCsrTemplate> Prepare(const CsrTemplate& value,
                                                      const CsrRuntimeValues& runtime,
                                                      const CsrAttributeRequirements& requirements);
    static score::Result<std::monostate> ValidatePrepared(const PreparedCsrTemplate& value);
};
}  // namespace score::crypto
#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CSR_CSR_PROCESSING_HPP
