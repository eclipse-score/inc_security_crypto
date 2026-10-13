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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SCORE_SIGN_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SCORE_SIGN_HANDLER_HPP

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"

#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace score::crypto::daemon::provider::score_provider::operations::sign
{

class SignExecutor;

/// @brief Abstract base handler for digital signature generation under the score
///        interface family.
///
/// A SIGN context uses the private half of the bound key pair for its whole
/// life. Verification is a separate context type, so nothing here branches on a
/// direction.
///
/// The daemon's Handler::Execute() is delegated to the injected SignExecutor,
/// which validates the stream state machine and routes to the typed methods
/// below.
///
/// Signature encoding: this stack uses the fixed-length IEEE P1363 form r‖s for
/// ECDSA on every provider, so a signature produced by one provider verifies
/// under another. Providers whose native output is DER convert at this boundary.
class ScoreSignHandler : public handler::Handler
{
  public:
    using Sptr = std::shared_ptr<ScoreSignHandler>;

    ScoreSignHandler() = delete;

    /// @param executor   Sign executor injected by the handler factory.
    /// @param algorithm  Algorithm identifier (e.g. "ECDSA-P256-SHA256").
    explicit ScoreSignHandler(std::unique_ptr<SignExecutor> executor, const common::AlgorithmId& algorithm);

    ~ScoreSignHandler() override;

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
    // Typed sign operations — override in concrete provider handlers
    // -----------------------------------------------------------------------

    /// @brief Signature length in bytes for the configured algorithm.
    [[nodiscard]] virtual std::size_t GetSignatureSize() const noexcept;

    /// @brief Start a signing stream using the bound private key.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> InitSign();

    /// @brief Feed a message chunk into the active stream.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> UpdateSign(
        score::cpp::span<const std::uint8_t> data);

    /// @brief Produce the signature over the accumulated message.
    /// @param signature Caller-provided output buffer, already resolved by the executor.
    /// @return Bytes written.
    [[nodiscard]] virtual Expected<std::size_t, common::DaemonErrorCode> FinalizeSign(
        score::cpp::span<std::uint8_t> signature);

    /// @brief Sign @p data in one call, without a streaming sequence.
    ///
    /// @param data      Message to sign.
    /// @param signature Caller-provided output buffer.
    /// @return Bytes written.
    ///
    /// @note Not implemented here: the base returns kUnsupportedOperation. A
    ///       provider serves a one-shot from a dedicated single-call API where
    ///       one exists, or from its own streaming sequence.
    [[nodiscard]] virtual Expected<std::size_t, common::DaemonErrorCode> SingleShotSign(
        score::cpp::span<const std::uint8_t> data,
        score::cpp::span<std::uint8_t> signature);

  protected:
    common::AlgorithmId m_algorithm;
    common::StreamOperationState m_state{common::StreamOperationState::IDLE};

  private:
    std::unique_ptr<SignExecutor> m_executor;
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::sign

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SCORE_SIGN_HANDLER_HPP
