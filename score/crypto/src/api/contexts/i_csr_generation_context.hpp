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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_I_CSR_GENERATION_CONTEXT_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_I_CSR_GENERATION_CONTEXT_HPP

#include "score/crypto/src/api/certificate/i_csr_export.hpp"
#include "score/crypto/src/api/contexts/i_context.hpp"
#include "score/crypto/src/api/csr/csr_request.hpp"
#include "score/crypto/src/api/types/common.hpp"

namespace score::crypto
{
/// Stateful client-side request builder; not thread-safe. Key and algorithm
/// are bound at creation. Repeated Generate() calls are independent requests,
/// not idempotency guarantees. A failed setter leaves the previous value intact.
class ICsrGenerationContext : public IContext
{
  public:
    using Uptr = std::unique_ptr<ICsrGenerationContext>;
    virtual score::Result<std::monostate> SetSubject(const CsrSubject& subject) = 0;
    virtual score::Result<std::monostate> SetSubjectDn(std::string_view dn) = 0;
    virtual score::Result<std::monostate> AddExtension(const CsrExtension& extension) = 0;
    virtual score::Result<std::monostate> AddSubjectAltName(std::string_view san) = 0;
    virtual score::Result<std::monostate> SetChallengePassword(std::string_view password) = 0;
    /// Compatibility setters only accept the already-bound value; changing a
    /// key or algorithm requires a new context, never a silent local override.
    virtual score::Result<std::monostate> SetSubjectKey(const CryptoResourceId& key) = 0;
    virtual score::Result<std::monostate> SetSignatureAlgorithm(const AlgorithmId& algorithm) = 0;
    virtual score::Result<ICsrExport::Uptr> Generate() = 0;
};
}  // namespace score::crypto
#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_I_CSR_GENERATION_CONTEXT_HPP
