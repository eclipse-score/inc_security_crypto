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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_VERIFY_OPENSSL_ED25519_VERIFY_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_VERIFY_OPENSSL_ED25519_VERIFY_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/signature_common.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <variant>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// @brief Ed25519 verification (RFC 8032, pure mode).
///
/// Ed25519 hashes internally and verifies the whole message at once, so only
/// the single-shot operation is supported; the streaming entry points and the
/// prehashed input mode are refused.
class OpenSslEd25519VerifyHandler final : public operations::verify::ScoreVerifyHandler
{
  public:
    explicit OpenSslEd25519VerifyHandler(std::unique_ptr<operations::verify::VerifyExecutor> executor,
                                         const common::AlgorithmId& algorithm);
    ~OpenSslEd25519VerifyHandler() override;
    OpenSslEd25519VerifyHandler(const OpenSslEd25519VerifyHandler&) = delete;
    OpenSslEd25519VerifyHandler& operator=(const OpenSslEd25519VerifyHandler&) = delete;

    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams&) override;
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;
    std::size_t GetSignatureSize() const noexcept override;
    /// @copydoc ScoreVerifyHandler::InitVerify
    /// @note Streaming is not supported for Ed25519.
    Expected<std::monostate, common::DaemonErrorCode> InitVerify() override;
    /// @copydoc ScoreVerifyHandler::UpdateVerify
    /// @note Streaming is not supported for Ed25519.
    Expected<std::monostate, common::DaemonErrorCode> UpdateVerify(score::cpp::span<const std::uint8_t>) override;
    /// @copydoc ScoreVerifyHandler::FinalizeVerify
    /// @note Streaming is not supported for Ed25519.
    Expected<bool, common::DaemonErrorCode> FinalizeVerify(score::cpp::span<const std::uint8_t>) override;
    /// @brief Verifies an Ed25519 signature in one call.
    /// @param data Message to verify.
    /// @param signature Exactly 64 bytes containing the Ed25519 signature.
    /// @return true for a valid signature, false for an invalid signature, or an error
    ///         if verification cannot be completed.
    Expected<bool, common::DaemonErrorCode> SingleShotVerify(score::cpp::span<const std::uint8_t> data,
                                                             score::cpp::span<const std::uint8_t> signature) override;
    static bool IsAlgorithmSupported(const common::AlgorithmId&) noexcept;

  private:
    signature::Stream m_stream;
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_VERIFY_OPENSSL_ED25519_VERIFY_HANDLER_HPP
