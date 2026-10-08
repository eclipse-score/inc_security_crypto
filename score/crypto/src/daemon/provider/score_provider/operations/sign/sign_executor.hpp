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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SIGN_EXECUTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SIGN_EXECUTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::sign
{

class ScoreSignHandler;

/// @brief Stateless executor implementing the strategy / visitor pattern for
///        signature generation under the score interface family.
///
/// Serves OP_ACTOR_SIGN_HANDLER only. A request carrying any other actor is
/// rejected, so a verification request cannot reach a context bound to the
/// private half of a key pair.
class SignExecutor
{
  public:
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        ScoreSignHandler& handler,
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request);

  private:
    /// @brief Runs one INIT / UPDATE / FINALIZE step after validating the transition.
    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode>
    ExecuteStreaming(ScoreSignHandler& handler, common::OperationAction action, common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteFinalize(
        ScoreSignHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSingleShot(
        ScoreSignHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<std::monostate, common::DaemonErrorCode> ValidateStreamTransition(
        common::OperationAction action,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState);
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::sign

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SIGN_EXECUTOR_HPP
