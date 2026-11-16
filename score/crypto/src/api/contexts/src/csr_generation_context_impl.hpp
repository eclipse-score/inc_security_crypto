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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CSR_GENERATION_CONTEXT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CSR_GENERATION_CONTEXT_IMPL_HPP

#include "score/crypto/src/api/config/csr_generation_context_config.hpp"
#include "score/crypto/src/api/contexts/i_csr_generation_context.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/csr/csr_processing_client.hpp"
#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"

namespace score::crypto
{
class CsrGenerationContextImpl final : public ICsrGenerationContext
{
  public:
    CsrGenerationContextImpl(std::shared_ptr<api::control_plane::IConnection> connection,
                             uint64_t context_id,
                             const CsrGenerationContextConfig& config,
                             std::shared_ptr<IBufferTranscoder> transcoder);
    ~CsrGenerationContextImpl() override;
    CsrGenerationContextImpl(const CsrGenerationContextImpl&) = delete;
    CsrGenerationContextImpl& operator=(const CsrGenerationContextImpl&) = delete;
    CsrGenerationContextImpl(CsrGenerationContextImpl&&) = delete;
    CsrGenerationContextImpl& operator=(CsrGenerationContextImpl&&) = delete;

    score::Result<std::monostate> SetSubject(const CsrSubject& subject) override;
    score::Result<std::monostate> SetSubjectDn(std::string_view dn) override;
    score::Result<std::monostate> AddExtension(const CsrExtension& extension) override;
    score::Result<std::monostate> AddSubjectAltName(std::string_view san) override;
    score::Result<std::monostate> SetChallengePassword(std::string_view password) override;
    score::Result<std::monostate> SetSubjectKey(const CryptoResourceId& key) override;
    score::Result<std::monostate> SetSignatureAlgorithm(const AlgorithmId& algorithm) override;
    score::Result<ICsrExport::Uptr> Generate() override;

  private:
    score::Result<std::monostate> Commit(CsrRequest candidate);
    std::shared_ptr<api::control_plane::IConnection> connection_;
    uint64_t context_id_;
    CsrGenerationContextConfig config_;
    std::shared_ptr<IBufferTranscoder> transcoder_;
    CsrProcessingClient processing_;
    CsrRequest request_;
    std::vector<std::string> sans_;
};
}  // namespace score::crypto
#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_CSR_GENERATION_CONTEXT_IMPL_HPP
