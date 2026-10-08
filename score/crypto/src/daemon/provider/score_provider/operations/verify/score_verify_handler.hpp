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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_SCORE_VERIFY_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_SCORE_VERIFY_HANDLER_HPP

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"

#include "score/span.hpp"

#include <cstddef>
#include <memory>

namespace score::crypto::daemon::provider::score_provider::operations::verify
{

class VerifyExecutor;

/// @brief Abstract base handler for signature verification under the score
///        interface family.
///
/// A VERIFY context uses the public half of the bound key pair for its whole
/// life. Generation is a separate context type served by ScoreSignHandler.
///
/// The daemon's Handler::Execute() is delegated to the injected VerifyExecutor,
/// which validates the stream state machine and routes to the typed methods
/// below.
///
/// Signature encoding: signatures arrive in the fixed-length IEEE P1363 form
/// r‖s, the stack's wire format on every provider. Providers whose native input
/// is DER convert at this boundary.
class ScoreVerifyHandler : public handler::Handler
{
  public:
    using Sptr = std::shared_ptr<ScoreVerifyHandler>;

    ScoreVerifyHandler() = delete;

    /// @param executor   Verify executor injected by the handler factory.
    /// @param algorithm  Algorithm identifier (e.g. "ECDSA-P256-SHA256").
    explicit ScoreVerifyHandler(std::unique_ptr<VerifyExecutor> executor, const common::AlgorithmId& algorithm);

    ~ScoreVerifyHandler() override;

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

    // -----------------------------------------------------------------------
    // Typed verify operations — override in concrete provider handlers
    // -----------------------------------------------------------------------

    /// @brief Signature length in bytes for the configured algorithm.
    ///
    /// Reported so that a caller can size the signature it submits; a
    /// verification produces no output of its own.
    [[nodiscard]] virtual std::size_t GetSignatureSize() const noexcept;

    /// @brief Start a verification stream using the bound public key.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> InitVerify();

    /// @brief Feed a message chunk into the active stream.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> UpdateVerify(
        score::cpp::span<const std::uint8_t> data);

    /// @brief Check @p signature against the accumulated message.
    /// @return false for a well-formed but incorrect signature; an error only for
    ///         malformed input or a provider failure.
    [[nodiscard]] virtual Expected<bool, common::DaemonErrorCode> FinalizeVerify(
        score::cpp::span<const std::uint8_t> signature);

    /// @brief Check @p signature over @p data in one call, without a streaming
    ///        sequence.
    ///
    /// @note Not implemented here: the base returns kUnsupportedOperation. A
    ///       provider serves a one-shot from a dedicated single-call API where
    ///       one exists, or from its own streaming sequence.
    [[nodiscard]] virtual Expected<bool, common::DaemonErrorCode> SingleShotVerify(
        score::cpp::span<const std::uint8_t> data,
        score::cpp::span<const std::uint8_t> signature);

  protected:
    common::AlgorithmId m_algorithm;
    common::StreamOperationState m_state{common::StreamOperationState::IDLE};

  private:
    std::unique_ptr<VerifyExecutor> m_executor;
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::verify

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_SCORE_VERIFY_HANDLER_HPP
