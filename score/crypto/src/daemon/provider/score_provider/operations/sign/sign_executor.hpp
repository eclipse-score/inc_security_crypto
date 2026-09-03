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

/// @file sign_executor.hpp
/// @brief Operation dispatcher for provider-neutral signature handlers.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SIGN_EXECUTOR_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SIGN_EXECUTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::sign
{
/// @brief Forward declaration of the provider-neutral signature handler.
class ScoreSignHandler;

/// @brief Stateless dispatcher for provider-neutral signature operations.
///
/// Validates operation requests and streaming state transitions, then delegates
/// each operation to the corresponding ScoreSignHandler method. The executor
/// does not store operation state; the state is maintained by the handler.
class SignExecutor final
{
  public:
    /// @brief Execute one SIGN operation.
    ///
    /// Dispatches the operation identified by the operation action to the
    /// corresponding ScoreSignHandler method.
    ///
    /// @param handler Signature handler receiving the operation.
    /// @param operation Operation identifier containing the signature action.
    /// @param request Operation parameters.
    /// @return Operation response, or a daemon error if the parameters,
    ///         operation, or stream state are invalid.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        ScoreSignHandler& handler,
        const common::OperationIdentifier& operation,
        common::RequestParameters& request);

  private:
    /// @brief Execute the initialization step of a streaming signature.
    ///
    /// @param handler Signature handler receiving the operation.
    /// @param request Optional initialization data.
    /// @return Success, or a daemon error reported by the handler.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteInit(ScoreSignHandler& handler,
                                                                                common::RequestParameters& request);

    /// @brief Add data to an active streaming signature.
    ///
    /// @param handler Signature handler receiving the operation.
    /// @param request Request containing the data to be added.
    /// @return Success, or a daemon error if the request is invalid or the
    ///         handler rejects the operation.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteUpdate(ScoreSignHandler& handler,
                                                                                  common::RequestParameters& request);

    /// @brief Finalize a streaming signature.
    ///
    /// @param handler Signature handler receiving the operation.
    /// @param request Optional output buffer and final data.
    /// @return Signature response, or a daemon error reported by the handler.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteFinalize(
        ScoreSignHandler& handler,
        common::RequestParameters& request);

    /// @brief Execute a single-shot signature operation.
    ///
    /// @param handler Signature handler receiving the operation.
    /// @param request Input data and an optional output buffer.
    /// @return Signature response, or a daemon error if the request is invalid
    ///         or the handler rejects the operation.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSingleShot(
        ScoreSignHandler& handler,
        common::RequestParameters& request);

    /// @brief Reset the signature handler to its initial stream state.
    ///
    /// @param handler Signature handler receiving the reset operation.
    /// @param request Reset operation parameters, which are unused.
    /// @return Success, or a daemon error reported by the handler.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteReset(ScoreSignHandler& handler,
                                                                                 common::RequestParameters& request);

    /// @brief Query the signature size for the configured algorithm.
    ///
    /// @param handler Signature handler providing the algorithm-specific size.
    /// @param request Operation parameters, which are unused.
    /// @return Signature size response, or a daemon error reported by the handler.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> GetSignatureSize(
        const ScoreSignHandler& handler,
        common::RequestParameters& request);

    /// @brief Validate a streaming operation and determine its next state.
    ///
    /// @param action Streaming operation to validate.
    /// @param currentState Current signature stream state.
    /// @param nextState Receives the state resulting from the operation.
    /// @return Success with the next state, or a daemon error for an invalid
    ///         operation or state transition.
    [[nodiscard]] static Expected<std::monostate, common::DaemonErrorCode> ValidateStreamTransition(
        common::OperationAction action,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState);
};
}  // namespace score::crypto::daemon::provider::score_provider::operations::sign

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SIGN_EXECUTOR_HPP
