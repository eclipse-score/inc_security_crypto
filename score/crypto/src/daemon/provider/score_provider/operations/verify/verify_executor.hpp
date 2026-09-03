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

/// @file verify_executor.hpp
/// @brief Operation dispatcher for provider-neutral verification handlers.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_VERIFY_EXECUTOR_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_VERIFY_EXECUTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::verify
{
/// @brief Forward declaration of the provider-neutral verification handler.
class ScoreVerifyHandler;

/// @brief Stateless dispatcher for provider-neutral verification operations.
///
/// Validates operation requests and streaming state transitions, then delegates
/// each operation to the corresponding ScoreVerifyHandler method. The executor
/// does not store operation state; the state is maintained by the handler.
class VerifyExecutor final
{
  public:
    /// @brief Execute one VERIFY operation.
    ///
    /// Dispatches the operation identified by the operation action to the
    /// corresponding ScoreVerifyHandler method.
    ///
    /// @param handler Verification handler receiving the operation.
    /// @param operation Operation identifier containing the verification action.
    /// @param request Operation parameters.
    /// @return Verification response, or a daemon error if the parameters,
    ///         operation, or stream state are invalid.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        ScoreVerifyHandler& handler,
        const common::OperationIdentifier& operation,
        common::RequestParameters& request);

  private:
    /// @brief Execute the initialization step of a streaming verification.
    ///
    /// @param handler Verification handler receiving the operation.
    /// @param request Optional initialization data.
    /// @return Success, or a daemon error reported by the handler.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteInit(ScoreVerifyHandler& handler,
                                                                                common::RequestParameters& request);

    /// @brief Add data to an active streaming verification.
    ///
    /// @param handler Verification handler receiving the operation.
    /// @param request Request containing the data to be verified.
    /// @return Success, or a daemon error if the request is invalid or the
    ///         handler rejects the operation.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteUpdate(ScoreVerifyHandler& handler,
                                                                                  common::RequestParameters& request);

    /// @brief Finalize a streaming verification.
    ///
    /// @param handler Verification handler receiving the operation.
    /// @param request Signature and optional final data or output parameters.
    /// @return Verification result, or a daemon error reported by the handler.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteFinalize(
        ScoreVerifyHandler& handler,
        common::RequestParameters& request);

    /// @brief Execute a single-shot verification operation.
    ///
    /// @param handler Verification handler receiving the operation.
    /// @param request Verification data and signature parameters.
    /// @return Verification result, or a daemon error if the request is invalid
    ///         or the handler rejects the operation.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSingleShot(
        ScoreVerifyHandler& handler,
        common::RequestParameters& request);

    /// @brief Reset the verification handler to its initial stream state.
    ///
    /// @param handler Verification handler receiving the reset operation.
    /// @param request Reset operation parameters, which are unused.
    /// @return Success, or a daemon error reported by the handler.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteReset(ScoreVerifyHandler& handler,
                                                                                 common::RequestParameters& request);

    /// @brief Validate a streaming operation and determine its next state.
    ///
    /// @param action Streaming operation to validate.
    /// @param currentState Current verification stream state.
    /// @param nextState Receives the state resulting from the operation.
    /// @return Success with the next state, or a daemon error for an invalid
    ///         operation or state transition.
    [[nodiscard]] static Expected<std::monostate, common::DaemonErrorCode> ValidateStreamTransition(
        common::OperationAction action,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState);
};
}  // namespace score::crypto::daemon::provider::score_provider::operations::verify

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_VERIFY_EXECUTOR_HPP
