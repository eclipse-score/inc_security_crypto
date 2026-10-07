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

/// @file score_verify_handler.hpp
/// @brief Provider-neutral base handler for verification operations.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_SCORE_VERIFY_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_SCORE_VERIFY_HANDLER_HPP

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"
#include <memory>
#include <optional>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::operations::verify
{
/// @brief Forward declaration of the verification-operation executor.
class VerifyExecutor;

/// @brief Abstract base handler for verification operations under the score interface family.
///
/// Implements the daemon's Handler interface by delegating Execute() to the
/// injected VerifyExecutor. Concrete score-interface providers (e.g. OpenSSL, IAV_Primula)
/// inherit from this class and override the typed verification methods.
///
/// Typed methods default to kUnsupportedOperation so that a partially-implemented
/// provider compiles and returns a clear error at runtime.
///
/// The handler owns the operation executor and stores the configured algorithm
/// and streaming state.
class ScoreVerifyHandler : public handler::Handler
{
  public:
    using Sptr = std::shared_ptr<ScoreVerifyHandler>;

    ScoreVerifyHandler() = delete;

    /// @brief Create a provider-neutral verification handler.
    ///
    /// Takes ownership of the operation executor and stores the selected
    /// verification algorithm.
    ///
    /// @param executor Executor used to dispatch verification operations.
    /// @param algorithm Algorithm identifier handled by this instance.
    ScoreVerifyHandler(std::unique_ptr<VerifyExecutor> executor, const common::AlgorithmId algorithm);
    ~ScoreVerifyHandler() override;

    /// @brief Delegates to the injected executor.
    ///
    /// @param operation Operation identifier containing the verification action.
    /// @param request Operation parameters.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operation,
        common::RequestParameters& request) override;

    /// @brief Initialize the handler context and reset the stream state to IDLE.
    ///
    /// @param init_params Context initialization parameters.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

    /// @brief Reset the intermediate verification stream state back to IDLE.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;

    // -----------------------------------------------------------------------
    // Stream state management
    // -----------------------------------------------------------------------

    /// @brief Return the current verification stream state.
    [[nodiscard]] common::StreamOperationState GetOperationState() const noexcept
    {
        return m_state;
    }

    /// @brief Set the current verification stream state.
    void SetOperationState(common::StreamOperationState state) noexcept
    {
        m_state = state;
    }

    /// @brief Return the configured verification algorithm.
    [[nodiscard]] const common::AlgorithmId& GetAlgorithm() const noexcept
    {
        return m_algorithm;
    }

    // -----------------------------------------------------------------------
    // Typed verification operations — override in concrete provider handlers
    // -----------------------------------------------------------------------

    /// @brief Initialize a verification operation on an existing context.
    ///
    /// @param initial_data Optional data to include during initialization.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> InitVerify(
        std::optional<common::RequestParameter> initial_data);

    /// @brief Add data to the active verification stream.
    ///
    /// @param data Message data to add to the verification.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> UpdateVerify(
        const common::RequestParameter& data);

    /// @brief Finalize the verification and return the signature result.
    ///
    /// @param final_data Optional final data to add before verification.
    /// @param output Optional signature or output buffer.
    /// @return `true` if the signature is valid, `false` if it is invalid, or
    ///         a daemon error if the verification cannot be performed.
    [[nodiscard]] virtual Expected<bool, common::DaemonErrorCode> FinalizeVerify(
        std::optional<common::RequestParameter> final_data,
        std::optional<common::RequestParameter> output);

    /// @brief Perform single-shot verification without streaming.
    ///
    /// @param data Message data to verify.
    /// @param signature Signature to verify against the message data.
    /// @return `true` if the signature is valid, `false` if it is invalid, or
    ///         a daemon error if the verification cannot be performed.
    [[nodiscard]] virtual Expected<bool, common::DaemonErrorCode> SingleShotVerify(
        const common::RequestParameter& data,
        const common::RequestParameter& signature);

  protected:
    common::AlgorithmId m_algorithm;                                           ///< Algorithm handled by this instance.
    common::StreamOperationState m_state{common::StreamOperationState::IDLE};  ///< Current streaming state.

  private:
    std::unique_ptr<VerifyExecutor> m_executor;  ///< Owns the operation dispatcher.
};
}  // namespace score::crypto::daemon::provider::score_provider::operations::verify

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_SCORE_VERIFY_HANDLER_HPP
