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

/// @file score_sign_handler.hpp
/// @brief Provider-neutral base handler for signature operations.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SCORE_SIGN_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SCORE_SIGN_HANDLER_HPP

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"
#include <memory>
#include <optional>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::operations::sign
{

/// @brief Forward declaration of the signature-operation executor (m_executor).
class SignExecutor;

/// @brief Abstract base handler for signature operations under the score interface family.
///
/// Implements the daemon's Handler interface by delegating Execute() to the
/// injected SignExecutor. Concrete score-interface providers (e.g. OpenSSL, IAV-Primula)
/// inherit from this class and override the typed signature methods.
///
/// Typed methods default to kUnsupportedOperation so that a partially-implemented
/// provider compiles and returns a clear error at runtime.
///
/// State management (algorithm, stream operation state) is centralised here.
class ScoreSignHandler : public handler::Handler
{
  public:
    using Sptr = std::shared_ptr<ScoreSignHandler>;

    ScoreSignHandler() = delete;

    /// @brief Create a provider-neutral signature handler.
    ///
    /// Takes ownership of the operation executor and stores the selected
    /// signature algorithm.
    ///
    /// @param executor Executor used to dispatch signature operations.
    /// @param algorithm Algorithm identifier handled by this instance.
    ScoreSignHandler(std::unique_ptr<SignExecutor> executor, const common::AlgorithmId algorithm);
    ~ScoreSignHandler() override;

    /// @brief Delegates to the injected executor.
    ///
    /// @param operation Operation identifier containing the signature action.
    /// @param request Operation parameters.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operation,
        common::RequestParameters& request) override;

    /// @brief Initialize the handler context and reset the stream state to IDLE.
    ///
    /// @param init_params Context initialization parameters.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

    /// @brief Reset the intermediate stream state back to IDLE.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;

    // -----------------------------------------------------------------------
    // Stream state management
    // -----------------------------------------------------------------------

    /// @brief Return the current signature stream state.
    [[nodiscard]] common::StreamOperationState GetOperationState() const noexcept
    {
        return m_state;
    }

    /// @brief Set the current signature stream state.
    void SetOperationState(common::StreamOperationState state) noexcept
    {
        m_state = state;
    }

    /// @brief Return the configured signature algorithm.
    [[nodiscard]] const common::AlgorithmId& GetAlgorithm() const noexcept
    {
        return m_algorithm;
    }

    // -----------------------------------------------------------------------
    // Typed signature operations — override in concrete provider handlers
    // -----------------------------------------------------------------------

    /// @brief Initialize a signature operation on an existing context.
    ///
    /// @param initial_data Optional data to include during initialization.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> InitSign(
        std::optional<common::RequestParameter> initial_data);

    /// @brief Add data to the active signature stream.
    ///
    /// @param data Message data to add to the signature.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> UpdateSign(
        const common::RequestParameter& data);

    /// @brief Finalize the signature and produce the output.
    ///
    /// @param final_data Optional final data to add before signing.
    /// @param output Optional caller-provided output buffer.
    [[nodiscard]] virtual Expected<common::ResponseParameters, common::DaemonErrorCode> FinalizeSign(
        std::optional<common::RequestParameter> final_data,
        std::optional<common::RequestParameter> output);

    /// @brief Perform a single-shot signature without streaming.
    ///
    /// @param data Message data to sign.
    /// @param output Optional caller-provided output buffer.
    [[nodiscard]] virtual Expected<common::ResponseParameters, common::DaemonErrorCode> SingleShotSign(
        const common::RequestParameter& data,
        std::optional<common::RequestParameter> output);

    /// @brief Get the signature size for the current algorithm.
    [[nodiscard]] virtual Expected<common::ResponseParameters, common::DaemonErrorCode> GetSignatureSize() const;

  protected:
    common::AlgorithmId m_algorithm;                                           ///< Algorithm handled by this instance.
    common::StreamOperationState m_state{common::StreamOperationState::IDLE};  ///< Current streaming state.

  private:
    std::unique_ptr<SignExecutor> m_executor;  ///< Owns the operation dispatcher.
};
}  // namespace score::crypto::daemon::provider::score_provider::operations::sign

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SCORE_SIGN_HANDLER_HPP
