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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGNATURE_SCORE_SIGNATURE_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGNATURE_SCORE_SIGNATURE_HANDLER_HPP

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"

#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace score::crypto::daemon::provider::score_provider::operations::signature
{

class SignatureExecutor;

/// @brief Abstract base handler for digital signature generation and verification
///        under the score interface family.
///
/// Signing and verification share one handler class because they differ only in
/// which half of the key pair is used and in the final provider call
/// (EVP_DigestSignFinal vs EVP_DigestVerifyFinal). Which of the two a context
/// performs is fixed at CTX_CREATE time via the OperationMode byte in param[4]
/// and is exposed through GetOperationMode().
///
/// The daemon's Handler::Execute() is delegated to the injected SignatureExecutor,
/// which validates the stream state machine and routes to the typed methods below.
///
/// Signature encoding: this stack uses the fixed-length IEEE P1363 form r‖s for
/// ECDSA on every provider, so a signature produced by one provider verifies
/// under another. Providers whose native output is DER convert at this boundary.
class ScoreSignatureHandler : public handler::Handler
{
  public:
    using Sptr = std::shared_ptr<ScoreSignatureHandler>;

    ScoreSignatureHandler() = delete;

    /// @param executor   Signature executor injected by the handler factory.
    /// @param algorithm  Algorithm identifier (e.g. "ECDSA-P256-SHA256").
    explicit ScoreSignatureHandler(std::unique_ptr<SignatureExecutor> executor, const common::AlgorithmId& algorithm);

    ~ScoreSignatureHandler() override = default;

    // -----------------------------------------------------------------------
    // Handler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request) override;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;

    // -----------------------------------------------------------------------
    // Stream state management
    // -----------------------------------------------------------------------

    [[nodiscard]] common::StreamOperationState GetOperationState() const noexcept
    {
        return m_state;
    }

    void SetOperationState(common::StreamOperationState state) noexcept
    {
        m_state = state;
    }

    [[nodiscard]] const common::AlgorithmId& GetAlgorithm() const noexcept
    {
        return m_algorithm;
    }

    [[nodiscard]] score::crypto::OperationMode GetOperationMode() const noexcept
    {
        return m_operation_mode;
    }

    // -----------------------------------------------------------------------
    // Typed signature operations — override in concrete provider handlers
    // -----------------------------------------------------------------------

    /// @brief Signature length in bytes for the configured algorithm.
    [[nodiscard]] virtual std::size_t GetSignatureSize() const noexcept;

    /// @brief Start a signing or verification stream using the bound key.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> InitSignature();

    /// @brief Feed a message chunk into the active stream.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> UpdateSignature(
        const common::RequestParameter& data);

    /// @brief Produce the signature over the accumulated message.
    /// @param signature Caller-provided buffer, already resolved from shared memory.
    /// @return Bytes written.
    /// @note Only valid when GetOperationMode() == kGenerate.
    [[nodiscard]] virtual Expected<std::size_t, common::DaemonErrorCode> FinalizeSign(
        score::cpp::span<std::uint8_t> signature);

    /// @brief Check @p signature against the accumulated message.
    /// @return false for a well-formed but incorrect signature; an error only for
    ///         malformed input or a provider failure.
    /// @note Only valid when GetOperationMode() == kVerify.
    [[nodiscard]] virtual Expected<bool, common::DaemonErrorCode> FinalizeVerify(
        const common::RequestParameter& signature);

  protected:
    common::AlgorithmId m_algorithm;
    common::StreamOperationState m_state{common::StreamOperationState::IDLE};
    score::crypto::OperationMode m_operation_mode{score::crypto::OperationMode::kGenerate};

    /// @brief Reads the OperationMode from CTX_CREATE param[4].
    ///
    /// Leaves m_operation_mode untouched when the parameter is absent or has the
    /// wrong type, so the kGenerate default applies.
    void ExtractOperationMode(const handler::InitializationParams& init_params) noexcept;

  private:
    std::unique_ptr<SignatureExecutor> m_executor;
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::signature

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGNATURE_SCORE_SIGNATURE_HANDLER_HPP
