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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_VERIFY_EXECUTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_VERIFY_EXECUTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::verify
{

class ScoreVerifyHandler;

/// @brief Stateless executor implementing the strategy / visitor pattern for
///        signature verification under the score interface family.
///
/// Serves OP_ACTOR_VERIFY_HANDLER only. A request carrying any other actor is
/// rejected, so a signing request cannot reach a context bound to the public
/// half of a key pair.
class VerifyExecutor
{
  public:
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        ScoreVerifyHandler& handler,
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request);

  private:
    /// @brief Runs one INIT / UPDATE / FINALIZE step after validating the transition.
    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode>
    ExecuteStreaming(ScoreVerifyHandler& handler, common::OperationAction action, common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteFinalize(
        ScoreVerifyHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSingleShot(
        ScoreVerifyHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<std::monostate, common::DaemonErrorCode> ValidateStreamTransition(
        common::OperationAction action,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState);
};

}  // namespace score::crypto::daemon::provider::score_provider::operations::verify

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_VERIFY_EXECUTOR_HPP
