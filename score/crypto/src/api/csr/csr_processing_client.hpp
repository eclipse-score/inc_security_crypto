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

#ifndef SCORE_CRYPTO_SRC_API_CSR_CSR_PROCESSING_CLIENT_HPP
#define SCORE_CRYPTO_SRC_API_CSR_CSR_PROCESSING_CLIENT_HPP

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"
#include "score/crypto/src/common/csr_wire.hpp"

#include <memory>
#include <utility>

namespace score::crypto
{
/// Explicit processing seam. Production uses the caller's existing SCORE
/// connection and transcoder; no endpoint selection or local codec fallback.
class ICsrProcessingService
{
  public:
    virtual ~ICsrProcessingService() = default;
    virtual score::Result<csr::wire::Document> Process(const csr::wire::Document& input) = 0;
};

class CsrProcessingClient final : public ICsrProcessingService
{
  public:
    CsrProcessingClient(std::shared_ptr<api::control_plane::IConnection> connection,
                        std::shared_ptr<IBufferTranscoder> transcoder)
        : connection_{std::move(connection)}, transcoder_{std::move(transcoder)}
    {
    }
    score::Result<csr::wire::Document> Process(const csr::wire::Document& input) override;

  private:
    std::shared_ptr<api::control_plane::IConnection> connection_;
    std::shared_ptr<IBufferTranscoder> transcoder_;
};
}  // namespace score::crypto

#endif  // SCORE_CRYPTO_SRC_API_CSR_CSR_PROCESSING_CLIENT_HPP
