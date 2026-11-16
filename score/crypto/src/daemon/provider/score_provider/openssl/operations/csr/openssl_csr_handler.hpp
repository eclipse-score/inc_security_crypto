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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CSR_OPENSSL_CSR_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CSR_OPENSSL_CSR_HANDLER_HPP

#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/signature_common.hpp"

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{
class OpenSslCsrHandler final : public ::score::crypto::daemon::provider::handler::Handler
{
  public:
    explicit OpenSslCsrHandler(const AlgorithmDescriptor& algorithm);
    static bool IsAlgorithmSupported(const AlgorithmDescriptor& algorithm) noexcept;
    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams& params) override;
    Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(const common::OperationIdentifier& operation,
                                                                          common::RequestParameters& request) override;
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;

  private:
    AlgorithmDescriptor m_algorithm{};
    signature::Stream m_stream;
    bool m_initialized{false};
};
}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CSR_OPENSSL_CSR_HANDLER_HPP
