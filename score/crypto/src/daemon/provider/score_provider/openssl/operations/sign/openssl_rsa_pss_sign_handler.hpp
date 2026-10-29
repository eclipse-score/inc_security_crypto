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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_RSA_PSS_SIGN_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_RSA_PSS_SIGN_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/signature_common.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <variant>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// @brief RSA-PSS signing, streaming or prehashed.
class OpenSslRsaPssSignHandler final : public operations::sign::ScoreSignHandler
{
  public:
    explicit OpenSslRsaPssSignHandler(std::unique_ptr<operations::sign::SignExecutor> executor,
                                      const common::AlgorithmId& algorithm);
    ~OpenSslRsaPssSignHandler() override;
    OpenSslRsaPssSignHandler(const OpenSslRsaPssSignHandler&) = delete;
    OpenSslRsaPssSignHandler& operator=(const OpenSslRsaPssSignHandler&) = delete;

    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams&) override;
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;
    std::size_t GetSignatureSize() const noexcept override;
    Expected<std::monostate, common::DaemonErrorCode> InitSign() override;
    Expected<std::monostate, common::DaemonErrorCode> UpdateSign(score::cpp::span<const std::uint8_t>) override;
    Expected<std::size_t, common::DaemonErrorCode> FinalizeSign(score::cpp::span<std::uint8_t>) override;
    Expected<std::size_t, common::DaemonErrorCode> SingleShotSign(score::cpp::span<const std::uint8_t>,
                                                                  score::cpp::span<std::uint8_t>) override;
    static bool IsAlgorithmSupported(const common::AlgorithmId&) noexcept;

  private:
    Expected<std::monostate, common::DaemonErrorCode> InitializeSignContext();
    Expected<std::size_t, common::DaemonErrorCode> ResolveBuffer(score::cpp::span<std::uint8_t>) const;

    signature::Stream m_stream;
    std::vector<std::uint8_t> m_buffer;
    bool m_prehashed{false};
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_RSA_PSS_SIGN_HANDLER_HPP
