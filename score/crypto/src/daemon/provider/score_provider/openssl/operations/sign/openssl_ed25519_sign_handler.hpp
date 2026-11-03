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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_ED25519_SIGN_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_ED25519_SIGN_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/signature_common.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <variant>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// @brief Ed25519 signing (RFC 8032, pure mode).
///
/// Ed25519 hashes internally and signs the whole message at once, so only the
/// single-shot operation is supported; the streaming entry points and the
/// prehashed input mode are refused.
class OpenSslEd25519SignHandler final : public operations::sign::ScoreSignHandler
{
  public:
    explicit OpenSslEd25519SignHandler(std::unique_ptr<operations::sign::SignExecutor> executor,
                                       const common::AlgorithmId& algorithm);
    ~OpenSslEd25519SignHandler() override;
    OpenSslEd25519SignHandler(const OpenSslEd25519SignHandler&) = delete;
    OpenSslEd25519SignHandler& operator=(const OpenSslEd25519SignHandler&) = delete;

    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams&) override;
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;
    std::size_t GetSignatureSize() const noexcept override;
    /// @copydoc ScoreSignHandler::InitSign
    /// @note Streaming is not supported for Ed25519.
    Expected<std::monostate, common::DaemonErrorCode> InitSign() override;
    /// @copydoc ScoreSignHandler::UpdateSign
    /// @note Streaming is not supported for Ed25519.
    Expected<std::monostate, common::DaemonErrorCode> UpdateSign(score::cpp::span<const std::uint8_t>) override;
    /// @copydoc ScoreSignHandler::FinalizeSign
    /// @note Streaming is not supported for Ed25519.
    Expected<std::size_t, common::DaemonErrorCode> FinalizeSign(score::cpp::span<std::uint8_t>) override;
    /// @brief Signs the complete message in one call using Ed25519.
    /// @param data Message to sign.
    /// @param signature Caller-provided buffer with room for at least 64 bytes.
    /// @return Number of bytes written, or an error if signing cannot be completed.
    Expected<std::size_t, common::DaemonErrorCode> SingleShotSign(score::cpp::span<const std::uint8_t> data,
                                                                  score::cpp::span<std::uint8_t> signature) override;
    static bool IsAlgorithmSupported(const common::AlgorithmId&) noexcept;

  private:
    signature::Stream m_stream;
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_ED25519_SIGN_HANDLER_HPP
